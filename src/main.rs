use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use ckb_vm::{CoreMachine, Memory, Register, SupportMachine};

mod cost_model;
mod machine;

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

fn sprint_loc_file(loc: &Option<addr2line::Location>, enable_trace: bool) -> String {
    if enable_trace {
        if let Some(loc2) = loc {
            if let Some(file) = loc2.file {
                if let Some(line) = loc2.line {
                    println!("[trace] {} : {}", file, line);
                } else {
                    println!("[trace] {} : ???", file);
                }
            } else {
                println!("[trace] ???");
            }
        }
    }
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
struct PProfLogger {
    atsl_context: addr2line::Context<
        addr2line::gimli::EndianReader<addr2line::gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
    >,
    tree_root: Rc<RefCell<PProfRecordTreeNode>>,
    tree_node: Rc<RefCell<PProfRecordTreeNode>>,
    ra_dict: HashMap<u64, Rc<RefCell<PProfRecordTreeNode>>>,
    enable_trace: bool,
}

impl PProfLogger {
    fn new(filename: String, enable_trace: bool) -> Result<Self, Box<dyn std::error::Error>> {
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
            enable_trace,
        })
    }
}

impl<
        'a,
        R: Register,
        M: Memory<REG = R>,
        Inner: ckb_vm::machine::SupportMachine<REG = R, MEM = M>,
    > machine::PProfLogger<ckb_vm::machine::DefaultMachine<'a, Inner>> for PProfLogger
{
    fn on_step(&mut self, machine: &mut ckb_vm::machine::DefaultMachine<'a, Inner>) {
        let pc = machine.pc().to_u64();
        let decoder = ckb_vm::decoder::build_decoder::<R>(machine.isa(), machine.version());
        let inst = decoder.decode(machine.memory_mut(), pc).unwrap();
        let opcode = ckb_vm::instructions::extract_opcode(inst);
        let cycles = machine
            .instruction_cycle_func()
            .as_ref()
            .map(|f| f(inst))
            .unwrap_or(0);

        if opcode == ckb_vm::instructions::insts::OP_JAL {
            let inst = ckb_vm::instructions::Utype(inst);
            if inst.rd() == ckb_vm::registers::RA {
                let d = pc.overflowing_add(inst.immediate_s() as u64).0 & 0xfffffffffffffffe;
                let loc = self.atsl_context.find_location(d).unwrap();
                let loc_string = sprint_loc_file(&loc, self.enable_trace);
                let frame_iter = self.atsl_context.find_frames(d).unwrap();
                let fun_string = sprint_fun(frame_iter);
                let tag_string = format!("{}:{}", loc_string, fun_string);
                let chd = Rc::new(RefCell::new(PProfRecordTreeNode {
                    name: tag_string,
                    parent: Some(self.tree_node.clone()),
                    childs: vec![],
                    cycles: 0,
                }));
                self.tree_node.borrow_mut().childs.push(chd.clone());
                self.ra_dict.insert(pc + 4, self.tree_node.clone());
                self.tree_node = chd;
            }
        };
        if opcode == ckb_vm::instructions::insts::OP_VERSION1_JALR {
            let inst = ckb_vm::instructions::Itype(inst);
            if inst.rd() == ckb_vm::registers::RA {
                let d = machine.registers()[inst.rs1()]
                    .to_u64()
                    .overflowing_add(inst.immediate_s() as u64)
                    .0
                    & 0xfffffffffffffffe;
                let loc = self.atsl_context.find_location(d).unwrap();
                let loc_string = sprint_loc_file(&loc, self.enable_trace);
                let frame_iter = self.atsl_context.find_frames(d).unwrap();
                let fun_string = sprint_fun(frame_iter);
                let tag_string = format!("{}:{}", loc_string, fun_string);
                let chd = Rc::new(RefCell::new(PProfRecordTreeNode {
                    name: tag_string,
                    parent: Some(self.tree_node.clone()),
                    childs: vec![],
                    cycles: 0,
                }));
                self.tree_node.borrow_mut().childs.push(chd.clone());
                self.ra_dict.insert(pc + 4, self.tree_node.clone());
                self.tree_node = chd;
            }
        };
        if opcode == ckb_vm::instructions::insts::OP_VERSION1_RVC_JALR {
            let inst = ckb_vm::instructions::Stype(inst);
            let d = machine.registers()[inst.rs1()].to_u64() & 0xfffffffffffffffe;
            let loc = self.atsl_context.find_location(d).unwrap();
            let loc_string = sprint_loc_file(&loc, self.enable_trace);
            let frame_iter = self.atsl_context.find_frames(d).unwrap();
            let fun_string = sprint_fun(frame_iter);
            let tag_string = format!("{}:{}", loc_string, fun_string);
            let chd = Rc::new(RefCell::new(PProfRecordTreeNode {
                name: tag_string,
                parent: Some(self.tree_node.clone()),
                childs: vec![],
                cycles: 0,
            }));
            self.tree_node.borrow_mut().childs.push(chd.clone());
            self.ra_dict.insert(pc + 2, self.tree_node.clone());
            self.tree_node = chd;
        };
        if opcode == ckb_vm::instructions::insts::OP_RVC_JR {
            let inst = ckb_vm::instructions::Stype(inst);
            if inst.rs1() == ckb_vm::registers::RA {
                let d = machine.registers()[ckb_vm::registers::RA].to_u64();
                self.tree_node = self.ra_dict.get(&d).unwrap().clone();
            }
        }
        self.tree_node.borrow_mut().cycles += cycles;
    }

    fn on_exit(&mut self, machine: &mut ckb_vm::machine::DefaultMachine<'a, Inner>) {
        if !self.enable_trace {
            assert_eq!(machine.exit_code(), 0);
            self.tree_root
                .borrow()
                .display_flamegraph("", &mut std::io::stdout());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flag_parser = clap::App::new("ckb-vm-pprof")
        .version("0.1")
        .about("A pprof tool for CKB VM")
        .arg(
            clap::Arg::with_name("bin")
                .long("bin")
                .value_name("filename")
                .help("Specify the name of the executable")
                .required(true),
        )
        .arg(
            clap::Arg::with_name("arg")
                .long("arg")
                .value_name("arguments")
                .help("Pass arguments to binary")
                .multiple(true),
        )
        .arg(
            clap::Arg::with_name("trace")
                .long("trace")
                .value_name("trace mode")
                .takes_value(false)
                .help("Enable trace mode")
                .required(false),
        )
        .get_matches();
    let fl_bin = flag_parser.value_of("bin").unwrap();
    let fl_arg: Vec<_> = flag_parser.values_of("arg").unwrap_or_default().collect();
    let enable_trace = flag_parser.is_present("trace");

    let code_data = std::fs::read(fl_bin)?;
    let code = bytes::Bytes::from(code_data);

    let default_core_machine = ckb_vm::DefaultCoreMachine::<u64, ckb_vm::SparseMemory<u64>>::new(
        ckb_vm::ISA_IMC | ckb_vm::ISA_B,
        ckb_vm::machine::VERSION1,
        1 << 32,
    );
    let default_machine_builder = ckb_vm::DefaultMachineBuilder::new(default_core_machine)
        .instruction_cycle_func(Box::new(cost_model::instruction_cycles));
    let default_machine = default_machine_builder.build();
    let pprof_func_provider = Box::new(PProfLogger::new(String::from(fl_bin), enable_trace)?);
    let mut machine = machine::PProfMachine::new(default_machine, pprof_func_provider);
    let mut args = vec![fl_bin.to_string().into()];
    args.append(
        &mut fl_arg
            .iter()
            .map(|x| bytes::Bytes::from(x.to_string()))
            .collect(),
    );
    machine.load_program(&code, &args).unwrap();
    machine.run()?;

    if enable_trace {
        let code = machine.machine.exit_code();
        println!("[trace] total cycles = {}", machine.machine.cycles());
        if code != 0 {
            println!("[trace] exit code is = {} !!!, not zero", code);
        }
    }
    Ok(())
}
