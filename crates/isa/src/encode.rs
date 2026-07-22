//! Encoding of decoded instructions back into their byte form.
//!
//! This is the inverse of `decode`, defined on the space of well-formed
//! `Insn` values. It exists so the round-trip property has an inverse to
//! check against, and so generators can build valid byte streams.

use crate::{Insn, opcode::BPF_LD_IMM_DW};

/// Encode one decoded instruction back into its 8 or 16 bytes.
/// 
/// Every instruction produces 8 bytes, except a wide load instruction
/// with 16 bytes and identified by `imm64.is_some()`.
pub fn encode_insn(ins: &Insn) -> Vec<u8> {
    let mut out = Vec::with_capacity(if ins.imm64.is_some() { 16 } else { 8 });

    let regs = (ins.src << 4) | (ins.dst & 0x0f);
    match ins.imm64 {
        Some(value) => {
            // first slot; opcode is wide-load, its imm holds the low 32 bits of imm64
            let low = (value as u64) as u32;
            out.push(BPF_LD_IMM_DW);
            out.push(regs);
            out.extend_from_slice(&ins.offset.to_le_bytes());
            out.extend_from_slice(&low.to_le_bytes());

            // second slot; opcode, regs, offset all zeroed out, imm holds the high 32
            // bits of imm64
            let high = ((value >> 32) as u64) as u32;
            out.push(0);
            out.push(0);
            out.extend_from_slice(&0i16.to_le_bytes());
            out.extend_from_slice(&high.to_le_bytes()); 
        },
        None => {
            out.push(ins.opcode);
            out.push(regs);
            out.extend_from_slice(&ins.offset.to_le_bytes());
            out.extend_from_slice(&ins.imm.to_le_bytes());
        },
    }
    
    out
}

/// Encode a whole program by concatenating the encoding of each instruction.
pub fn encode_program(prog: &Vec<Insn>) -> Vec<u8> {
    let mut out = Vec::new();
    for ins in prog {
        out.extend_from_slice(&encode_insn(ins));
    }
    out
}
