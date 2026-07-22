//! Numeric constants taken directly from the BPF ISA (RFC 9669)

pub const BPF_CLASS_MASK: u8 = 0x07;

pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

pub const BPF_SRC_MASK: u8 = 0x08;
pub const BPF_OP_MASK: u8 = 0xf0;

pub const BPF_SIZE_MASK: u8 = 0x18;
pub const BPF_MODE_MASK: u8 = 0xe0;

pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_DW: u8 = 0x18;

pub const BPF_IMM: u8 = 0x00;

pub const BPF_LD_IMM_DW: u8 = BPF_LD | BPF_IMM | BPF_DW;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class{Ld, Ldx, St, Stx, Alu, Jmp, Jmp32, Alu64}

impl Class{
    pub fn from_opcode(opcode: u8) -> Class {
        match opcode & BPF_CLASS_MASK {
            BPF_LD => Class::Ld,
            BPF_LDX => Class::Ldx,
            BPF_ST=> Class::St,
            BPF_STX => Class::Stx,
            BPF_ALU => Class::Alu,
            BPF_JMP => Class::Jmp,
            BPF_JMP32 => Class::Jmp32,
            BPF_ALU64 => Class::Alu64,
            _ => unreachable!("the class field is only 3 bits wide")
        }
    }
}
