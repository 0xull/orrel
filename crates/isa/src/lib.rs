use crate::opcode::{Class, BPF_LD_IMM_DW};

pub mod opcode;
pub mod encode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub slot: usize,
    pub opcode: u8,
    pub src: u8,
    pub dst: u8,
    pub offset: i16,
    pub imm: i32,
    pub imm64: Option<i64>,
    pub slots: usize,
}

impl Insn {
    pub fn class(&self) -> Class {
        Class::from_opcode(self.opcode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderError {
    NotSlotAligned(usize),
    TruncatedWideLoad(usize),
}

pub fn decode(code: &[u8]) -> Result<Vec<Insn>, DecoderError> {
    if code.len() % 8 != 0 {
        return Err(DecoderError::NotSlotAligned(code.len()));
    }

    let mut out = Vec::new();
    let mut i = 0usize;

    while i < code.len() {
        let slot = i / 8;
        let b = &code[i..i + 8];

        let opcode = b[0];
        let regs = b[1];
        let dst = regs & 0x0f;
        let src = regs >> 4;
        let offset = i16::from_le_bytes([b[2], b[3]]);
        let imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);

        if opcode == BPF_LD_IMM_DW {
            if i + 16 > code.len() {
                return Err(DecoderError::TruncatedWideLoad(slot));
            }
            let hi = &code[i + 8..i + 16];
            let high = i32::from_le_bytes([hi[4], hi[5], hi[6], hi[7]]);
            let low_bits = imm as u32 as u64;
            let high_bits = high as u32 as u64;
            let value = (low_bits | (high_bits << 32)) as i64;

            out.push(Insn {
                slot,
                src,
                dst,
                offset,
                opcode,
                imm,
                imm64: Some(value),
                slots: 2,
            });
            i += 16;
        } else {
            out.push(Insn {
                slot,
                opcode,
                src,
                dst,
                offset,
                imm,
                imm64: None,
                slots: 1,
            });
            i += 8;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hand_authored_stream_with_wide_load() {
        // mov r0, r1 ; lddw r0, 0xdeadbeefcafef00d ; exit
        let code: [u8; 32] = [
            0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x18, 0x00, 0x00, 0x00, 0x0d, 0xf0,0xfe, 0xca, 
            0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 
            0x95, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
        ];

        let imm64_lbs = &code[12..16];
        let imm64_hbs = &code[20..24];
        let imm64 = u64::from_le_bytes([imm64_lbs[0], imm64_lbs[1], imm64_lbs[2], imm64_lbs[3], imm64_hbs[0], imm64_hbs[1], imm64_hbs[2], imm64_hbs[3]]);
        println!("{imm64:064b}\n{imm64:x}");

        let prog = decode(&code).expect("must decode");

        assert_eq!(prog.len(), 3, "three instructions, not four slots");

        assert_eq!(prog[0].class(), Class::Alu64);
        assert_eq!(prog[0].dst, 0x00);
        assert_eq!(prog[0].src, 0x01);

        assert_eq!(prog[1].slot, 1);
        assert_eq!(prog[1].slots, 2);
        assert_eq!(prog[1].imm64, Some(0xdeadbeefcafef00du64 as i64));

        assert_eq!(prog[2].slot, 3, "exit instruction sits at slot 3");
        assert_eq!(prog[2].opcode, 0x95);
    }

    #[test]
    fn rejects_truncated_wide_load() {
        let code: [u8; 8] = [0x18, 0x00, 0x00, 0x00, 0x0d, 0x0f, 0xfe, 0xca];
        assert_eq!(decode(&code), Err(DecoderError::TruncatedWideLoad(0)));
    }

    #[test]
    fn rejects_unaligned_buffer() {
        let code: [u8; 7] = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode(&code), Err(DecoderError::NotSlotAligned(7)));
    }
}
