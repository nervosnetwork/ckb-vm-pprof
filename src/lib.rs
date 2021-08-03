use ckb_vm::{instructions::instruction_length, Bytes, CoreMachine, Error, Memory, Register, SupportMachine};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;

pub mod cost_model;
pub mod machine;

#[allow(dead_code)]
fn sprint_loc_file_line(loc: &Option<addr2line::Location>) -> String {
    if let Some(ref loc) = *loc {
        let mut list = vec![];
        let file = loc.file.as_ref().unwrap();
        let path = Path::new(file);
        list.push(path.display().to_string());
        if let Some(line) = loc.line {
            list.push(format!("{}", line));
        } else {
            list.push(String::from("??"));
        }
        list.join(":")
    } else {
        String::from("??:??")
    }
}

fn sprint_loc_file(loc: &Option<addr2line::Location>) -> String {
    if let Some(ref loc) = *loc {
        let file = loc.file.as_ref().unwrap();
        let path = Path::new(file);
        path.display().to_string()
    } else {
        String::from("??")
    }
}

#[allow(dead_code)]
fn sprint_fun(
    mut frame_iter: addr2line::FrameIter<
        addr2line::gimli::EndianReader<addr2line::gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
    >,
) -> String {
    let mut stack: Vec<String> = vec![String::from("??")];
    loop {
        let frame = frame_iter.next().unwrap();
        if frame.is_none() {
            break;
        }
        let frame = frame.unwrap();
        let function = frame.function.unwrap();
        let function_name = String::from(addr2line::demangle_auto(
            Cow::from(function.raw_name().unwrap()),
            function.language,
        ));

        stack.push(function_name)
    }
    stack.last().unwrap().to_string()
}

// Use tree structure to store ckb vm's runtime data. At present, we care about cycles, but we may add other things in
// the future, for example, the number of times a certain instruction appears.
#[derive(Clone, Debug)]
struct PProfRecordTreeNode {
    name: String, // FILENAME + FUNCTION_NAME as expected.
    parent: Option<Rc<RefCell<PProfRecordTreeNode>>>,
    childs: Vec<Rc<RefCell<PProfRecordTreeNode>>>,
    cycles: u64,
}

impl PProfRecordTreeNode {
    // Create a new PProfRecordTreeNode with a user defined name(e.g. Function name).
    fn root() -> Self {
        Self {
            name: String::from("??:??"),
            parent: None,
            childs: vec![],
            cycles: 0,
        }
    }

    fn display_flamegraph(&self, prefix: &str, writer: &mut impl std::io::Write) {
        let prefix_name = prefix.to_owned() + self.name.as_str();
        writer
            .write_all(format!("{} {}\n", prefix_name, self.cycles).as_bytes())
            .unwrap();
        for e in &self.childs {
            e.borrow()
                .display_flamegraph(&(prefix_name.as_str().to_owned() + "; "), writer);
        }
    }
}

// Main handler.
pub struct PProfLogger {
    atsl_context:
        addr2line::Context<addr2line::gimli::EndianReader<addr2line::gimli::RunTimeEndian, std::rc::Rc<[u8]>>>,
    tree_root: Rc<RefCell<PProfRecordTreeNode>>,
    tree_node: Rc<RefCell<PProfRecordTreeNode>>,
    ra_dict: HashMap<u64, Rc<RefCell<PProfRecordTreeNode>>>,
    output_filename: String,
}

impl PProfLogger {
    pub fn new(filename: String, output_filename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(filename)?;
        let mmap = unsafe { memmap::Mmap::map(&file)? };
        let object = object::File::parse(&*mmap)?;
        let ctx = addr2line::Context::new(&object)?;
        let tree_root = Rc::new(RefCell::new(PProfRecordTreeNode::root()));
        Ok(Self {
            atsl_context: ctx,
            tree_root: tree_root.clone(),
            tree_node: tree_root,
            ra_dict: HashMap::new(),
            output_filename: String::from(output_filename),
        })
    }
}

impl<'a, R: Register, M: Memory<REG = R>, Inner: ckb_vm::machine::SupportMachine<REG = R, MEM = M>>
    machine::PProfLogger<ckb_vm::machine::DefaultMachine<'a, Inner>> for PProfLogger
{
    fn on_step(&mut self, machine: &mut ckb_vm::machine::DefaultMachine<'a, Inner>) {
        let pc = machine.pc().to_u64();
        let mut decoder = ckb_vm::decoder::build_decoder::<R>(machine.isa());
        let inst = decoder.decode(machine.memory_mut(), pc).unwrap();
        let inst_length = instruction_length(inst) as u64;
        let opcode = ckb_vm::instructions::extract_opcode(inst);
        let cycles = machine.instruction_cycle_func().as_ref().map(|f| f(inst)).unwrap_or(0);
        self.tree_node.borrow_mut().cycles += cycles;

        let once = |s: &mut Self, addr: u64, link: u64| {
            let loc = s.atsl_context.find_location(addr).unwrap();
            let loc_string = sprint_loc_file(&loc);
            let frame_iter = s.atsl_context.find_frames(addr).unwrap();
            let fun_string = sprint_fun(frame_iter);
            let tag_string = format!("{}:{}", loc_string, fun_string);
            let chd = Rc::new(RefCell::new(PProfRecordTreeNode {
                name: tag_string,
                parent: Some(s.tree_node.clone()),
                childs: vec![],
                cycles: 0,
            }));
            s.tree_node.borrow_mut().childs.push(chd.clone());
            s.ra_dict.insert(link, s.tree_node.clone());
            s.tree_node = chd;
        };

        if opcode == ckb_vm::instructions::insts::OP_JAL {
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
            let inst = ckb_vm::instructions::Itype(inst);
            let base = machine.registers()[inst.rs1()].to_u64();
            let addr = base.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            if self.ra_dict.contains_key(&addr) {
                self.tree_node = self.ra_dict.get(&addr).unwrap().clone();
            } else {
                once(self, addr, link);
            }
        };
        if opcode == ckb_vm::instructions::insts::OP_FAR_JUMP_ABS {
            let inst = ckb_vm::instructions::Utype(inst);
            let addr = (inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            if self.ra_dict.contains_key(&addr) {
                self.tree_node = self.ra_dict.get(&addr).unwrap().clone();
            } else {
                once(self, addr, link);
            }
        }
        if opcode == ckb_vm::instructions::insts::OP_FAR_JUMP_REL {
            let inst = ckb_vm::instructions::Utype(inst);
            let addr = pc.wrapping_add(inst.immediate_s() as u64) & 0xfffffffffffffffe;
            let link = pc + inst_length;
            if self.ra_dict.contains_key(&addr) {
                self.tree_node = self.ra_dict.get(&addr).unwrap().clone();
            } else {
                once(self, addr, link);
            }
        }
    }

    fn on_exit(&mut self, machine: &mut ckb_vm::machine::DefaultMachine<'a, Inner>) {
        assert_eq!(machine.exit_code(), 0);
        if self.output_filename == "-" {
            self.tree_root.borrow().display_flamegraph("", &mut std::io::stdout());
        } else {
            let mut output = std::fs::File::create(&self.output_filename).expect("can't create file");
            self.tree_root.borrow().display_flamegraph("", &mut output);
        }
    }
}

pub fn quick_start(fl_bin: &str, fl_arg: Vec<&str>, output_filename: &str) -> Result<(i8, u64), Error> {
    let code_data = std::fs::read(fl_bin)?;
    let code = Bytes::from(code_data);

    let default_core_machine = ckb_vm::DefaultCoreMachine::<u64, ckb_vm::SparseMemory<u64>>::new(
        ckb_vm::ISA_IMC | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
        ckb_vm::machine::VERSION1,
        1 << 32,
    );
    let default_machine_builder = ckb_vm::DefaultMachineBuilder::new(default_core_machine)
        .instruction_cycle_func(Box::new(cost_model::instruction_cycles));
    let default_machine = default_machine_builder.build();
    let pprof_logger = PProfLogger::new(String::from(fl_bin), output_filename).map_err(|e| {
        let mut stderr = std::io::stderr();
        writeln!(&mut stderr, "error while loading file {}: {:?}", fl_bin, e).expect("write stderr");
        Error::Unexpected
    })?;
    let pprof_func_provider = Box::new(pprof_logger);
    let mut machine = machine::PProfMachine::new(default_machine, pprof_func_provider);
    let mut args = vec![fl_bin.to_string().into()];
    args.append(&mut fl_arg.iter().map(|x| Bytes::from(x.to_string())).collect());
    machine.load_program(&code, &args).unwrap();
    machine.run()?;

    Ok((0, machine.machine.cycles()))
}
