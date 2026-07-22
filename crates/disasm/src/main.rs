use std::process::ExitCode;

use isa::{Insn, decode};

fn render(vec_idex: usize, ins: &Insn) -> String {
    let head = format!(
        "[idx {vec_idex}] slot {:>3}  {} slot(s)  op=0x{:02x} {:<6?} dst=r{:<2} src=r{:<2}",
        ins.slot, ins.slots, ins.opcode, ins.class(), ins.dst, ins.src
    );
    match ins.imm64 {
        Some(v) => format!("{head} imm64=0x{:016x}", v as u64),
        None => format!("{head} off={:<6} imm=0x{:08x}", ins.offset, ins.imm as u32)
    }
}

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: disasm <raw-text-section.bin>");
            return ExitCode::from(2);
        }
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };

    match decode(&bytes) {
       Ok(prog) =>  {
           for (idx, ins) in prog.iter().enumerate() {
               println!("{}", render(idx, ins));
           }
           eprintln!("decoded {} instructions from {} bytes", prog.len(), bytes.len());
           ExitCode::SUCCESS
       },
       Err(e) => {
           eprintln!("decode error: {e:?}");
           ExitCode::FAILURE
       }
    }
}