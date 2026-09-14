//! The eBPF virtual machine state; the interpreter, the register file and the stack frame.

use isa::{opcode::*, Insn};

pub const NUM_REGS: usize = 11;
pub const FRAME_PTR: usize = 10;
pub const STACK_SIZE: u64 = 512;

// The virtual base address of the stack region.
pub const STACK_BASE: u64 = 0x2_0000_0000;
// r10 points one byte past the top of the stack.
pub const FRAME_TOP: u64 = STACK_BASE + STACK_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    BadByteSwapWidth(i32),
    BadSignExtendWidth(i16),
    BadRegister(usize),
    WriteToFramePointer,
    NoExit,
    Unimplemented(u8),
}

pub struct Vm {
    regs: [u64; NUM_REGS],
    #[allow(dead_code)]
    stack: Box<[u8; STACK_SIZE as usize]>,
}

impl Default for Vm {
    fn default() -> Self {
        Vm::new()
    }
}

impl Vm {
    /// Construct a VM in its program-entry state.
    pub fn new() -> Vm {
        let mut regs = [0u64; NUM_REGS];
        regs[FRAME_PTR] = FRAME_TOP;
        Vm {
            regs,
            stack: Box::new([0u8; STACK_SIZE as usize]),
        }
    }

    pub fn reg(&self, i: usize) -> Result<u64, VmError> {
        if i >= NUM_REGS {
            return Err(VmError::BadRegister(i));
        }
        Ok(self.regs[i])
    }

    pub fn set_reg(&mut self, i: usize, val: u64) -> Result<(), VmError> {
        if i >= NUM_REGS {
            return Err(VmError::BadRegister(i));
        }
        if i == FRAME_PTR {
            return Err(VmError::WriteToFramePointer);
        }
        self.regs[i] = val;
        Ok(())
    }

    /// Execute a decoded program until EXIT, returning r0.
    pub fn run(&mut self, prog: &[Insn]) -> Result<u64, VmError> {
        let mut pc: usize = 0;
        loop {
            let insn = prog.get(pc).ok_or(VmError::NoExit)?;
            match insn.class() {
                Class::Alu | Class::Alu64 => {
                    self.exec_alu(insn)?;
                    pc += 1;
                }
                Class::Jmp if (insn.opcode & BPF_OP_MASK) == BPF_EXIT => {
                    return self.reg(0);
                }
                _ => return Err(VmError::Unimplemented(insn.opcode)),
            }
        }
    }

    fn exec_alu(&mut self, insn: &Insn) -> Result<(), VmError> {
        let is64 = insn.class() == Class::Alu64;
        let op = insn.opcode & BPF_OP_MASK;
        let is_x = (insn.opcode & BPF_SRC_MASK) != 0;
        let dst_i = insn.dst as usize;
        let dst = self.reg(dst_i)?;

        let src = if is_x {
            self.reg(insn.src as usize)?
        } else if is64 {
            (insn.imm as i64) as u64 // ALU64 K: sign-extend imm 32 -> 64
        } else {
            (insn.imm as u32) as u64 // ALU K: imm as unsigned 32
        };

        // Byte swap
        if op == BPF_END {
            let w = insn.imm;
            let res = if !is64 {
                process_endian(dst, w, is_x)?
            } else {
                byteswap(dst, w)?
            };
            return self.set_reg(dst_i, res);
        }

        // NEG is unary.
        if op == BPF_NEG {
            let res = if is64 {
                dst.wrapping_neg()
            } else {
                (dst as u32).wrapping_neg() as u64
            };
            return self.set_reg(dst_i, res);
        }

        // MOVSX: MOV with non-zero offset sign-extend the source's low `offset` bits.
        if op == BPF_MOV && insn.offset != 0 {
            let sx = sign_extend(src, insn.offset)?;
            let res = if is64 { sx as u64 } else { (sx as u32) as u64 };
            return self.set_reg(dst_i, res);
        }

        if is64 {
            let res: u64 = match op {
                BPF_ADD => dst.wrapping_add(src),
                BPF_SUB => dst.wrapping_sub(src),
                BPF_MUL => dst.wrapping_mul(src),
                BPF_OR => dst | src,
                BPF_AND => dst & src,
                BPF_XOR => dst ^ src,
                BPF_MOV => src,
                BPF_LSH => dst.wrapping_shl((src & 63) as u32),
                BPF_RSH => dst.wrapping_shr((src & 63) as u32),
                BPF_ARSH => (dst as i64).wrapping_shr((src & 63) as u32) as u64,
                BPF_DIV => {
                    if insn.offset == 1 {
                        // SDIV
                        let s = src as i64;
                        if s == 0 {
                            0
                        } else {
                            (dst as i64).wrapping_div(s) as u64
                        }
                    } else {
                        if src == 0 {
                            0
                        } else {
                            dst / src
                        }
                    }
                }
                BPF_MOD => {
                    if insn.offset == 1 {
                        // SMOD
                        let s = src as i64;
                        if s == 0 {
                            return Ok(());
                        } else {
                            (dst as i64).wrapping_rem(s) as u64
                        }
                    } else {
                        if src == 0 {
                            return Ok(());
                        } else {
                            dst % src
                        }
                    }
                }
                _ => return Err(VmError::Unimplemented(insn.opcode)),
            };
            self.set_reg(dst_i, res)
        } else {
            let d = dst as u32;
            let s = src as u32;
            let res32: u32 = match op {
                BPF_ADD => d.wrapping_add(s),
                BPF_SUB => d.wrapping_sub(s),
                BPF_MUL => d.wrapping_mul(s),
                BPF_OR => d | s,
                BPF_AND => d & s,
                BPF_XOR => d ^ s,
                BPF_MOV => s,
                BPF_LSH => d.wrapping_shl(s & 31),
                BPF_RSH => d.wrapping_shr(s & 31),
                BPF_ARSH => ((d as i32).wrapping_shr(s & 31)) as u32,
                BPF_DIV => {
                    if insn.offset == 1 {
                        let ss = s as i32;
                        if ss == 0 {
                            0
                        } else {
                            (d as i32).wrapping_div(ss) as u32
                        }
                    } else {
                        if s == 0 {
                            0
                        } else {
                            d / s
                        }
                    }
                }
                BPF_MOD => {
                    if insn.offset == 1 {
                        // SMOD
                        let ss = s as i32;
                        if ss == 0 {
                            d
                        } else {
                            (d as i32).wrapping_rem(ss) as u32
                        }
                    } else {
                        if s == 0 {
                            d
                        } else {
                            d % s
                        }
                    }
                }
                _ => return Err(VmError::Unimplemented(insn.opcode)),
            };
            // zero-extend 32-bit results into the 64-bit register.
            self.set_reg(dst_i, res32 as u64)
        }
    }
}

#[cfg(target_endian = "little")]
fn process_endian(v: u64, width: i32, end_flag: bool) -> Result<u64, VmError> {
    if !end_flag {
        trunc_byte(v, width)
    } else {
        byteswap(v, width)
    }
}

#[cfg(target_endian = "big")]
fn process_endian(v: u64, width: i32, end_flag: bool) -> Result<u64, VmError> {
    if !end_flag {
        byteswap(v, width)
    } else {
        trunc_byte(v, width)
    }
}

fn trunc_byte(v: u64, width: i32) -> Result<u64, VmError> {
    match width {
        16 => Ok(v & 0xffff),
        32 => Ok(v & 0xffff_ffff),
        64 => Ok(v),
        other => Err(VmError::BadByteSwapWidth(other)),
    }
}

fn byteswap(v: u64, width: i32) -> Result<u64, VmError> {
    match width {
        16 => Ok((v as u16).swap_bytes() as u64),
        32 => Ok((v as u32).swap_bytes() as u64),
        64 => Ok(v.swap_bytes()),
        other => Err(VmError::BadByteSwapWidth(other)),
    }
}

fn sign_extend(v: u64, bits: i16) -> Result<i64, VmError> {
    match bits {
        8 => Ok((v as u8 as i8) as i64),
        16 => Ok((v as u16 as i16) as i64),
        32 => Ok((v as u32 as i32) as i64),
        other => Err(VmError::BadSignExtendWidth(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_state_zeroes_all_but_frame_pointer() {
        let vm = Vm::new();
        for i in 0..FRAME_PTR {
            assert_eq!(vm.reg(i).unwrap(), 0, "r{i} must start at zero");
        }
        assert_eq!(vm.reg(FRAME_PTR).unwrap(), FRAME_TOP);
    }

    #[test]
    fn general_registers_are_writable() {
        let mut vm = Vm::new();
        for i in 0..FRAME_PTR {
            assert!(vm.set_reg(i, 0xabcd_ef01_2345_6789).is_ok());
            assert_eq!(vm.reg(i).unwrap(), 0xabcd_ef01_2345_6789);
        }
    }

    #[test]
    fn frame_pointer_is_read_only() {
        let mut vm = Vm::new();
        assert_eq!(vm.set_reg(FRAME_PTR, 0), Err(VmError::WriteToFramePointer));
        assert_eq!(vm.reg(FRAME_PTR).unwrap(), FRAME_TOP, "r10 changed");
    }

    #[test]
    fn unsupported_registers_are_rejected() {
        let mut vm = Vm::new();
        assert_eq!(vm.reg(11), Err(VmError::BadRegister(11)));
        assert_eq!(vm.set_reg(11, 0), Err(VmError::BadRegister(11)));
    }

    fn ins(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Insn {
        Insn {
            slot: 0,
            opcode,
            src,
            dst,
            offset,
            imm,
            imm64: None,
            slots: 1,
        }
    }

    fn one(
        opcode: u8,
        dst_val: u64,
        src_reg: Option<(u8, u64)>,
        offset: i16,
        imm: i32,
        dst: u8,
        src: u8,
    ) -> u64 {
        let mut vm = Vm::new();
        vm.set_reg(dst as usize, dst_val).unwrap();
        if let Some((r, v)) = src_reg {
            vm.set_reg(r as usize, v).unwrap();
        }
        vm.exec_alu(&ins(opcode, dst, src, offset, imm)).unwrap();
        vm.reg(dst as usize).unwrap()
    }

    #[test]
    fn alu64_imm_is_sign_extended() {
        assert_eq!(one(BPF_ALU64 | BPF_ADD, 1, None, 0, -1, 3, 0), 0);
        assert_eq!(
            one(BPF_ALU64 | BPF_MOV, 0, None, 0, -1, 3, 0),
            0xffff_ffff_ffff_ffff
        );
    }

    #[test]
    fn alu32_imm_is_unsigned_and_zero_extends() {
        assert_eq!(
            one(BPF_ALU | BPF_MOV, 0, None, 0, -1, 3, 0),
            0x0000_0000_ffff_ffff
        );
        assert_eq!(
            one(BPF_ALU | BPF_ADD, 0xAAAA_AAAA_0000_0001, None, 0, 1, 3, 0),
            2
        );
    }

    #[test]
    fn div_by_zero_is_zero() {
        assert_eq!(one(BPF_ALU64 | BPF_DIV, 123, None, 0, 0, 3, 0), 0);
        assert_eq!(one(BPF_ALU | BPF_DIV, 123, None, 0, 0, 3, 0), 0);
    }

    #[test]
    fn mod_zero_alu64_unchanged_alu32_upper_zeroed() {
        assert_eq!(
            one(BPF_ALU64 | BPF_MOD, 0xDEAD_BEEF_0000_0007, None, 0, 0, 3, 0),
            0xDEAD_BEEF_0000_0007
        );
        assert_eq!(
            one(BPF_ALU | BPF_MOD, 0xDEAD_BEEF_0000_0007, None, 0, 0, 3, 0),
            0x0000_0000_0000_0007
        );
    }

    #[test]
    fn shift_counts_are_masked() {
        assert_eq!(one(BPF_ALU64 | BPF_LSH, 1, None, 0, 64, 3, 0), 1);
        assert_eq!(one(BPF_ALU64 | BPF_LSH, 1, None, 0, 65, 3, 0), 2);
        assert_eq!(one(BPF_ALU | BPF_LSH, 1, None, 0, 32, 3, 0), 1);
    }

    #[test]
    fn arsh_is_signed() {
        assert_eq!(
            one(
                BPF_ALU64 | BPF_ARSH,
                0x8000_0000_0000_0000,
                None,
                0,
                4,
                3,
                0
            ),
            0xF800_0000_0000_0000
        );
        assert_eq!(
            one(BPF_ALU | BPF_ARSH, 0x8000_0000, None, 0, 4, 3, 0),
            0x0000_0000_F800_0000
        );
    }

    #[test]
    fn movsx_sign_extend() {
        assert_eq!(
            one(
                BPF_ALU64 | BPF_MOV | BPF_SRC_MASK,
                0,
                Some((2, 0x0000_00ff)),
                8,
                0,
                3,
                2
            ),
            0xffff_ffff_ffff_ffff
        );
        assert_eq!(
            one(
                BPF_ALU | BPF_MOV | BPF_SRC_MASK,
                0,
                Some((2, 0x0000_000ff)),
                8,
                0,
                3,
                2
            ),
            0x0000_0000_ffff_ffff
        );
    }

    #[test]
    fn signed_div_mod() {
        assert_eq!(
            one(BPF_ALU64 | BPF_DIV, (-6i64) as u64, None, 1, 4, 3, 0),
            (-1i64) as u64
        );
        assert_eq!(
            one(BPF_ALU64 | BPF_MOD, (-7i64) as u64, None, 1, 3, 3, 0),
            (-1i64) as u64
        );
    }

    #[test]
    fn end_to_end_arithmetic_program() {
        let code: &[u8] = &[
            0xb7, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // r1  =  5
            0xb7, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // r2  =  7
            0x0f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 += r2 --> 12
            0x27, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // r1 *=  3 --> 36
            0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0  = r1
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let prog = isa::decode(code).unwrap();
        let mut vm = Vm::new();
        assert_eq!(vm.run(&prog).unwrap(), 36);
    }

    #[test]
    fn program_without_exit_is_rejected() {
        let code: &[u8] = &[0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let prog = isa::decode(code).unwrap();
        let mut vm = Vm::new();
        assert_eq!(vm.run(&prog), Err(VmError::NoExit));
    }
}
