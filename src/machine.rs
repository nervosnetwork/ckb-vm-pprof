use bytes::Bytes;
use ckb_vm::{
    decoder::build_decoder, instructions::Register, memory::Memory, CoreMachine, DefaultMachine,
    Error, Machine, SupportMachine,
};

pub trait PProfLogger<Mac> {
    fn on_step(&mut self, machine: &mut Mac);
    fn on_exit(&mut self, machine: &mut Mac);
}

pub struct PProfMachine<'a, Inner> {
    pub machine: DefaultMachine<'a, Inner>,
    pprof_logger: Box<dyn PProfLogger<DefaultMachine<'a, Inner>>>,
}

impl<R: Register, M: Memory<R>, Inner: SupportMachine<REG = R, MEM = M>> CoreMachine
    for PProfMachine<'_, Inner>
{
    type REG = <Inner as CoreMachine>::REG;
    type MEM = <Inner as CoreMachine>::MEM;

    fn pc(&self) -> &Self::REG {
        &self.machine.pc()
    }

    fn set_pc(&mut self, next_pc: Self::REG) {
        self.machine.set_pc(next_pc)
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

impl<R: Register, M: Memory<R>, Inner: SupportMachine<REG = R, MEM = M>> Machine
    for PProfMachine<'_, Inner>
{
    fn ecall(&mut self) -> Result<(), Error> {
        self.machine.ecall()
    }

    fn ebreak(&mut self) -> Result<(), Error> {
        self.machine.ebreak()
    }
}

impl<'a, R: Register, M: Memory<R>, Inner: SupportMachine<REG = R, MEM = M>>
    PProfMachine<'a, Inner>
{
    pub fn new(
        machine: DefaultMachine<'a, Inner>,
        pprof_logger: Box<dyn PProfLogger<DefaultMachine<'a, Inner>>>,
    ) -> Self {
        Self {
            machine,
            pprof_logger,
        }
    }

    pub fn load_program(&mut self, program: &Bytes, args: &[Bytes]) -> Result<u64, Error> {
        self.machine.load_program(program, args)
    }

    pub fn run(&mut self) -> Result<i8, Error> {
        let decoder = build_decoder::<Inner::REG>(self.isa(), self.version());
        self.machine.set_running(true);
        while self.machine.running() {
            self.pprof_logger.on_step(&mut self.machine);
            self.machine.step(&decoder)?;
        }
        self.pprof_logger.on_exit(&mut self.machine);
        Ok(self.machine.exit_code())
    }
}
