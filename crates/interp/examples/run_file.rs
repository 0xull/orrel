use interp::Vm;
use isa::decode;

fn main() {
    let path = std::env::args().nth(1).expect("file path not found");
    let bytes = std::fs::read(&path).expect("read file path failed");
    let prog = decode(&bytes).expect("instruction decoder failed to run");
    let mut vm = Vm::new();
    match vm.run(&prog) {
        Ok(r0) => println!("exit r0 = 0x{r0:016x} ({r0})"),
        Err(err) => eprintln!("failed: {err:?}"),
    }
}
