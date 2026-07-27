use interp::{FRAME_PTR, FRAME_TOP, Vm, VmError};

fn main() {
    let mut vm = Vm::new();

    println!("program-entry register file");
    for i in 0..=FRAME_PTR {
        let tag = if i == FRAME_PTR { "  <- read-only frame pointer" } else { "" };
        println!("  r{i:<2} = 0x{:016x}{tag}", vm.reg(i).unwrap());
    }

    println!("frame pointer top-of-stack = 0x{FRAME_TOP:016x}");

    match vm.set_reg(FRAME_PTR, 0xdead) {
        Err(VmError::WriteToFramePointer) => {
            println!("write to r10 correctly rejected: WriteToFramePointer");
        }
        other => println!("UNEXPECTED: {other:?}"),
    }
}