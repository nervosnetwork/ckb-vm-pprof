use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use ckb_vm::decoder::{build_decoder, Decoder};
use ckb_vm::instructions::instruction_length;
use ckb_vm::machine::{DefaultMachine, DefaultMachineBuilder, VERSION1};
use ckb_vm::memory::Memory;
use ckb_vm::{Bytes, CoreMachine, Error, Machine, Register, SupportMachine, Syscalls};

mod cost_model;
pub use cost_model::instruction_cycles;

type Addr2LineEndianReader = addr2line::gimli::EndianReader<addr2line::gimli::RunTimeEndian, Rc<[u8]>>;
type Addr2LineContext = addr2line::Context<Addr2LineEndianReader>;
type Addr2LineFrameIter<'a> = addr2line::FrameIter<'a, Addr2LineEndianReader>;

#[allow(dead_code)]
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

fn goblin_fun(program: &Bytes) -> Result<HashMap<u64, String>, Box<dyn std::error::Error>> {
    let mut map = HashMap::new();
    let elf = goblin::elf::Elf::parse(&program)?;
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
    name: String,
    parent: Option<Rc<RefCell<TrieNode>>>,
    childs: Vec<Rc<RefCell<TrieNode>>>,
    cycles: u64,
}

impl TrieNode {
    fn root() -> Self {
        Self {
            name: String::from("??:??"),
            parent: None,
            childs: vec![],
            cycles: 0,
        }
    }

    fn display_flamegraph(&self, prefix: &str, writer: &mut impl std::io::Write) {
        let prefix_name = format!("{}{}", prefix, self.name);
        writer.write_all(format!("{} {}\n", prefix_name, self.cycles).as_bytes()).unwrap();
        for e in &self.childs {
            e.borrow().display_flamegraph(format!("{}; ", prefix_name).as_str(), writer);
        }
    }

    fn display_stacktrace(&self, writer: &mut impl std::io::Write) {
        let mut stack = vec![self.name.clone()];
        let mut frame = self.parent.clone();
        loop {
            if let Some(p) = frame {
                let a = p.borrow();
                stack.push(a.name.clone());
                frame = a.parent.clone();
                continue;
            }
            break;
        }
        stack.reverse();
        writer.write_all(b"Backtrace:\n").unwrap();
        for i in &stack {
            writer.write_all(format!("  {}\n", i).as_bytes()).unwrap();
        }
    }
}

pub struct Profile {
    addrctx: Addr2LineContext,
    trie_root: Rc<RefCell<TrieNode>>,
    trie_node: Rc<RefCell<TrieNode>>,

    ra_dict: HashMap<u64, Rc<RefCell<TrieNode>>>,
    cache_tag: HashMap<u64, String>,
    cache_fun: HashMap<u64, String>,
}

impl Profile {
    pub fn new(program: &Bytes) -> Result<Self, Box<dyn std::error::Error>> {
        let object = object::File::parse(&program)?;
        let ctx = addr2line::Context::new(&object)?;
        let trie_root = Rc::new(RefCell::new(TrieNode::root()));
        Ok(Self {
            addrctx: ctx,
            trie_root: trie_root.clone(),
            trie_node: trie_root,
            ra_dict: HashMap::new(),
            cache_tag: HashMap::new(),
            cache_fun: goblin_fun(&program)?,
        })
    }

    pub fn get_tag(&mut self, addr: u64) -> String {
        if let Some(data) = self.cache_tag.get(&addr) {
            return data.clone();
        }
        let loc = self.addrctx.find_location(addr).unwrap();
        let loc_string = sprint_loc_file(&loc);
        let mut frame_iter = self.addrctx.find_frames(addr).unwrap();
        let fun_string = sprint_fun(&mut frame_iter);
        let tag_string = format!("{}:{}", loc_string, fun_string);
        self.cache_tag.insert(addr, tag_string.clone());
        tag_string
    }
}

impl Profile {
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

        let once = |s: &mut Self, addr: u64, link: u64| {
            let tag_string = s.get_tag(addr);
            let chd = Rc::new(RefCell::new(TrieNode {
                name: tag_string,
                parent: Some(s.trie_node.clone()),
                childs: vec![],
                cycles: 0,
            }));
            s.trie_node.borrow_mut().childs.push(chd.clone());
            s.ra_dict.insert(link, s.trie_node.clone());
            s.trie_node = chd;
        };

        if opcode == ckb_vm::instructions::insts::OP_JAL {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Utype(inst);
            // The standard software calling convention uses x1 as the return address register and x5 as an alternate
            // link register.
            if inst.rd() == ckb_vm::registers::RA || inst.rd() == ckb_vm::registers::T0 {
                let addr = pc.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
                let link = pc + inst_length;
                once(self, addr, link);
            }
        };
        if opcode == ckb_vm::instructions::insts::OP_JALR {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Itype(inst);
            let base = machine.registers()[inst.rs1()].to_u64();
            let addr = base.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            let value = self.ra_dict.get(&addr);
            if value.is_some() {
                self.trie_node = value.unwrap().clone();
            } else {
                once(self, addr, link);
            }
        };
        if opcode == ckb_vm::instructions::insts::OP_FAR_JUMP_ABS {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Utype(inst);
            let addr = (inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            let value = self.ra_dict.get(&addr);
            if value.is_some() {
                self.trie_node = value.unwrap().clone();
            } else {
                once(self, addr, link);
            }
        }
        if opcode == ckb_vm::instructions::insts::OP_FAR_JUMP_REL {
            let inst_length = instruction_length(inst) as u64;
            let inst = ckb_vm::instructions::Utype(inst);
            let addr = pc.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            let value = self.ra_dict.get(&addr);
            if value.is_some() {
                self.trie_node = value.unwrap().clone();
            } else {
                once(self, addr, link);
            }
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
        let mut decoder = build_decoder::<Inner::REG>(self.isa(), VERSION1);
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
        machine.profile.trie_node.borrow().display_stacktrace(&mut std::io::stdout());
        return Err(err);
    }

    if output_filename == "-" {
        machine.profile.trie_root.borrow().display_flamegraph("", &mut std::io::stdout());
    } else {
        let mut output = std::fs::File::create(&output_filename).expect("can't create file");
        machine.profile.trie_root.borrow().display_flamegraph("", &mut output);
    }

    Ok((0, machine.machine.cycles()))
}
