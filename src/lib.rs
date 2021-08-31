use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use ckb_vm::decoder::{build_decoder, Decoder};
use ckb_vm::instructions::instruction_length;
use ckb_vm::machine::{DefaultMachine, DefaultMachineBuilder};
use ckb_vm::memory::Memory;
use ckb_vm::{Bytes, CoreMachine, Error, Machine, Register, SupportMachine, Syscalls};

mod cost_model;
pub use cost_model::instruction_cycles;

type Addr2LineEndianReader = addr2line::gimli::EndianReader<addr2line::gimli::RunTimeEndian, Rc<[u8]>>;
type Addr2LineContext = addr2line::Context<Addr2LineEndianReader>;
type Addr2LineFrameIter<'a> = addr2line::FrameIter<'a, Addr2LineEndianReader>;

fn sprint_loc_file_line(loc: &Option<addr2line::Location>) -> String {
    if let Some(ref loc) = *loc {
        let file = loc.file.as_ref().unwrap();
        let mut s = String::from(*file);
        if let Some(line) = loc.line {
            s.push_str(format!(":{}", line).as_str());
        } else {
            s.push_str(":??");
        }
        s
    } else {
        String::from("??:??")
    }
}

fn sprint_loc_file(loc: &Option<addr2line::Location>) -> String {
    if let Some(ref loc) = *loc {
        let file = loc.file.as_ref().unwrap();
        String::from(*file)
    } else {
        String::from("??")
    }
}

fn sprint_fun(frame_iter: &mut Addr2LineFrameIter) -> String {
    let mut s = String::from("??");
    loop {
        if let Some(data) = frame_iter.next().unwrap() {
            let function = data.function.unwrap();
            s = String::from(addr2line::demangle_auto(
                Cow::from(function.raw_name().unwrap()),
                function.language,
            ));
            continue;
        }
        break;
    }
    s
}

fn goblin_fun(elf: &goblin::elf::Elf) -> Result<HashMap<u64, String>, Box<dyn std::error::Error>> {
    let mut map = HashMap::new();
    for sym in &elf.syms {
        if !sym.is_function() {
            continue;
        }
        if let Some(Ok(r)) = elf.strtab.get(sym.st_name) {
            map.insert(sym.st_value, r.to_string());
        }
    }
    Ok(map)
}

struct TrieNode {
    addr: u64,
    link: u64,
    pc: u64,
    parent: Option<Rc<RefCell<TrieNode>>>,
    childs: Vec<Rc<RefCell<TrieNode>>>,
    cycles: u64,
}

impl TrieNode {
    fn root() -> Self {
        Self {
            addr: 0,
            link: 0,
            pc: 0,
            parent: None,
            childs: vec![],
            cycles: 0,
        }
    }
}

pub struct Profile {
    addrctx: Addr2LineContext,
    trie_root: Rc<RefCell<TrieNode>>,
    trie_node: Rc<RefCell<TrieNode>>,
    cache_fun: HashMap<u64, String>,
}

impl Profile {
    pub fn new(program: &Bytes) -> Result<Self, Box<dyn std::error::Error>> {
        let object = object::File::parse(&program)?;
        let ctx = addr2line::Context::new(&object)?;
        let trie_root = Rc::new(RefCell::new(TrieNode::root()));
        let elf = goblin::elf::Elf::parse(&program)?;
        trie_root.borrow_mut().addr = elf.entry;
        Ok(Self {
            addrctx: ctx,
            trie_root: trie_root.clone(),
            trie_node: trie_root,
            cache_fun: goblin_fun(&elf)?,
        })
    }

    pub fn get_tag_simple(&self, addr: u64) -> String {
        let loc = self.addrctx.find_location(addr).unwrap();
        let loc_string = sprint_loc_file(&loc);
        let mut frame_iter = self.addrctx.find_frames(addr).unwrap();
        let fun_string = sprint_fun(&mut frame_iter);
        let tag_string = format!("{}:{}", loc_string, fun_string);
        tag_string
    }

    pub fn get_tag_detail(&self, addr: u64) -> String {
        let loc = self.addrctx.find_location(addr).unwrap();
        let loc_string = sprint_loc_file_line(&loc);
        let mut frame_iter = self.addrctx.find_frames(addr).unwrap();
        let fun_string = sprint_fun(&mut frame_iter);
        let tag_string = format!("{}:{}", loc_string, fun_string);
        tag_string
    }

    fn display_flamegraph_rec(&self, prefix: &str, node: Rc<RefCell<TrieNode>>, writer: &mut impl std::io::Write) {
        let prefix_name = format!("{}{}", prefix, self.get_tag_simple(node.borrow().addr));
        writer.write_all(format!("{} {}\n", prefix_name, node.borrow().cycles).as_bytes()).unwrap();
        for e in &node.borrow().childs {
            self.display_flamegraph_rec(format!("{}; ", prefix_name).as_str(), e.clone(), writer);
        }
        writer.flush().unwrap();
    }

    pub fn display_flamegraph(&self, writer: &mut impl std::io::Write) {
        self.display_flamegraph_rec("", self.trie_root.clone(), writer);
    }

    pub fn display_stacktrace(&self, writer: &mut impl std::io::Write) {
        let mut frame = self.trie_node.clone();
        let mut stack = vec![self.get_tag_detail(frame.borrow().pc)];
        loop {
            stack.push(self.get_tag_detail(frame.borrow().link));
            let parent = frame.borrow().parent.clone();
            if let Some(p) = parent {
                frame = p.clone();
            } else {
                break;
            }
        }
        stack.reverse();
        writer.write_all(b"Trace:\n").unwrap();
        for i in &stack {
            writer.write_all(format!("  {}\n", i).as_bytes()).unwrap();
        }
        writer.flush().unwrap();
    }

    fn step<'a, R: Register, M: Memory<REG = R>, Inner: SupportMachine<REG = R, MEM = M>>(
        &mut self,
        machine: &mut DefaultMachine<'a, Inner>,
        decoder: &mut Decoder,
    ) {
        let pc = machine.pc().to_u64();
        let inst = decoder.decode(machine.memory_mut(), pc).unwrap();
        let opcode = ckb_vm::instructions::extract_opcode(inst);
        let cycles = machine.instruction_cycle_func().as_ref().map(|f| f(inst)).unwrap_or(0);
        self.trie_node.borrow_mut().cycles += cycles;
        self.trie_node.borrow_mut().pc = pc;

        let call = |s: &mut Self, addr: u64, link: u64| {
            let chd = Rc::new(RefCell::new(TrieNode {
                addr: addr,
                link: link,
                pc: pc,
                parent: Some(s.trie_node.clone()),
                childs: vec![],
                cycles: 0,
            }));
            s.trie_node.borrow_mut().childs.push(chd.clone());
            s.trie_node = chd;
        };

        let quit_or_skip = |s: &mut Self, addr: u64| {
            let mut f = s.trie_node.clone();
            loop {
                if f.borrow().link == addr {
                    if let Some(p) = f.borrow().parent.clone() {
                        s.trie_node = p.clone();
                    } else {
                        s.trie_node = f.clone();
                    }
                    break;
                }
                let p = f.borrow().parent.clone();
                if let Some(p) = p {
                    f = p.clone();
                } else {
                    break;
                }
            }
        };

        if opcode == ckb_vm::instructions::insts::OP_JAL {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Utype(inst);
            let addr = pc.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            if self.cache_fun.contains_key(&addr) {
                call(self, addr, link);
                return;
            }
            quit_or_skip(self, addr);
            return;
        };
        if opcode == ckb_vm::instructions::insts::OP_JALR {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Itype(inst);
            let base = machine.registers()[inst.rs1()].to_u64();
            let addr = base.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            if self.cache_fun.contains_key(&addr) {
                call(self, addr, link);
                return;
            }
            quit_or_skip(self, addr);
            return;
        };
        if opcode == ckb_vm::instructions::insts::OP_FAR_JUMP_ABS {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Utype(inst);
            let addr = (inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            if self.cache_fun.contains_key(&addr) {
                call(self, addr, link);
                return;
            }
            quit_or_skip(self, addr);
            return;
        }
        if opcode == ckb_vm::instructions::insts::OP_FAR_JUMP_REL {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Utype(inst);
            let addr = pc.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            if self.cache_fun.contains_key(&addr) {
                call(self, addr, link);
                return;
            }
            quit_or_skip(self, addr);
            return;
        }
    }
}

pub struct PProfMachine<'a, Inner> {
    pub machine: DefaultMachine<'a, Inner>,
    pub profile: Profile,
}

impl<R: Register, M: Memory<REG = R>, Inner: SupportMachine<REG = R, MEM = M>> CoreMachine for PProfMachine<'_, Inner> {
    type REG = <Inner as CoreMachine>::REG;
    type MEM = <Inner as CoreMachine>::MEM;

    fn pc(&self) -> &Self::REG {
        &self.machine.pc()
    }

    fn update_pc(&mut self, pc: Self::REG) {
        self.machine.update_pc(pc)
    }

    fn commit_pc(&mut self) {
        self.machine.commit_pc()
    }

    fn memory(&self) -> &Self::MEM {
        self.machine.memory()
    }

    fn memory_mut(&mut self) -> &mut Self::MEM {
        self.machine.memory_mut()
    }

    fn registers(&self) -> &[Self::REG] {
        self.machine.registers()
    }

    fn set_register(&mut self, idx: usize, value: Self::REG) {
        self.machine.set_register(idx, value)
    }

    fn isa(&self) -> u8 {
        self.machine.isa()
    }

    fn version(&self) -> u32 {
        self.machine.version()
    }
}

impl<R: Register, M: Memory<REG = R>, Inner: SupportMachine<REG = R, MEM = M>> Machine for PProfMachine<'_, Inner> {
    fn ecall(&mut self) -> Result<(), Error> {
        self.machine.ecall()
    }

    fn ebreak(&mut self) -> Result<(), Error> {
        self.machine.ebreak()
    }
}

impl<'a, R: Register, M: Memory<REG = R>, Inner: SupportMachine<REG = R, MEM = M>> PProfMachine<'a, Inner> {
    pub fn new(machine: DefaultMachine<'a, Inner>, profile: Profile) -> Self {
        Self { machine, profile }
    }

    pub fn load_program(&mut self, program: &Bytes, args: &[Bytes]) -> Result<u64, Error> {
        self.machine.load_program(program, args)
    }

    pub fn run(&mut self) -> Result<i8, Error> {
        let mut decoder = build_decoder::<Inner::REG>(self.isa());
        self.machine.set_running(true);
        while self.machine.running() {
            self.profile.step(&mut self.machine, &mut decoder);
            self.machine.step(&mut decoder)?;
        }
        Ok(self.machine.exit_code())
    }
}

#[cfg(has_asm)]
use ckb_vm::machine::asm::AsmCoreMachine;
#[cfg(has_asm)]
type CoreMachineType = AsmCoreMachine;
#[cfg(has_asm)]
type CoreMachineTypeFour = Box<AsmCoreMachine>;

#[cfg(not(has_asm))]
use ckb_vm::machine::DefaultCoreMachine;
#[cfg(not(has_asm))]
use ckb_vm::memory::{sparse::SparseMemory, wxorx::WXorXMemory};
#[cfg(not(has_asm))]
type CoreMachineType = DefaultCoreMachine<u64, WXorXMemory<SparseMemory<u64>>>;
#[cfg(not(has_asm))]
type CoreMachineTypeFour = DefaultCoreMachine<u64, WXorXMemory<SparseMemory<u64>>>;

pub fn quick_start<'a>(
    syscalls: Vec<Box<(dyn Syscalls<CoreMachineTypeFour> + 'a)>>,
    fl_bin: &str,
    fl_arg: Vec<&str>,
    output_filename: &str,
) -> Result<(i8, u64), Error> {
    let code_data = std::fs::read(fl_bin)?;
    let code = Bytes::from(code_data);

    let isa = ckb_vm::ISA_IMC | ckb_vm::ISA_B | ckb_vm::ISA_MOP;
    let default_core_machine = CoreMachineType::new(isa, ckb_vm::machine::VERSION1, 1 << 32);
    let mut builder = DefaultMachineBuilder::new(default_core_machine)
        .instruction_cycle_func(Box::new(cost_model::instruction_cycles));
    builder = syscalls.into_iter().fold(builder, |builder, syscall| builder.syscall(syscall));
    let default_machine = builder.build();
    let profile = Profile::new(&code).unwrap();
    let mut machine = PProfMachine::new(default_machine, profile);
    let mut args = vec![fl_bin.to_string().into()];
    args.append(&mut fl_arg.iter().map(|x| Bytes::from(x.to_string())).collect());
    machine.load_program(&code, &args).unwrap();
    let result = machine.run();

    if let Err(err) = result {
        machine.profile.display_stacktrace(&mut std::io::stdout());
        return Err(err);
    }

    if output_filename == "-" {
        machine.profile.display_flamegraph(&mut std::io::stdout());
    } else {
        let mut output = std::fs::File::create(&output_filename).expect("can't create file");
        machine.profile.display_flamegraph(&mut output);
    }

    Ok((0, machine.machine.cycles()))
}
