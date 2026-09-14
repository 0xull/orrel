//! Differential and property tests for orrel's ALU engine
//!
//! The ordinary binary operations are checked against Rust's own native
//! wrapping arithmetic. The deliberately-divergent cases are checked
//! against the eBPF specification rule.

use interp::Vm;
use isa::{encode::encode_program, opcode::*, Insn};
use proptest::prelude::*;

fn eval_alu(
    opcode: u8,
    dst: u8,
    src: u8,
    offset: i16,
    imm: i32,
    dst_val: u64,
    src_val: u64,
) -> u64 {
    let op = Insn {
        slot: 0,
        opcode,
        dst,
        src,
        offset,
        imm,
        imm64: None,
        slots: 1,
    };
    let exit = Insn {
        slot: 1,
        opcode: BPF_JMP | BPF_EXIT,
        dst: 0,
        src: 0,
        offset: 0,
        imm: 0,
        imm64: None,
        slots: 1,
    };
    let bytes = encode_program(&[op, exit].into());
    let prog = isa::decode(&bytes).expect("decode failed");

    let mut vm = Vm::new();
    vm.set_reg(dst as usize, dst_val).unwrap();
    if src != dst {
        vm.set_reg(src as usize, src_val).unwrap();
    }
    let _ = vm.run(&prog);
    vm.reg(dst as usize).unwrap()
}

fn native64(op: u8, dst: u64, src: u64) -> Option<u64> {
    Some(match op {
        BPF_ADD => dst.wrapping_add(src),
        BPF_SUB => dst.wrapping_sub(src),
        BPF_MUL => dst.wrapping_mul(src),
        BPF_OR => dst | src,
        BPF_AND => dst & src,
        BPF_XOR => dst ^ src,
        BPF_MOV => src,
        BPF_LSH => dst.wrapping_shl((src & 63) as u32),
        BPF_RSH => dst.wrapping_shr((src & 63) as u32),
        BPF_ARSH => ((dst as i64).wrapping_shr((src & 63) as u32)) as u64,
        _ => return None, // div and mod handled separately
    })
}

fn native32(op: u8, dst: u64, src: u64) -> Option<u64> {
    let d = dst as u32;
    let s = src as u32;
    let r = match op {
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
        _ => return None,
    };

    Some(r as u64) // widening into u64 clears upper half bits, hence the invariant.
}

const ORDINARY: &[u8] = &[
    BPF_ADD, BPF_SUB, BPF_MUL, BPF_OR, BPF_AND, BPF_XOR, BPF_MOV, BPF_LSH, BPF_RSH, BPF_ARSH,
];

proptest! {
    #[test]
    fn alu64_matches_native(op_idx in 0usize..ORDINARY.len(), dst_val in any::<u64>(), src_val in any::<u64>()) {
        let op = ORDINARY[op_idx];
        let got = eval_alu(BPF_ALU64 | op | BPF_SRC_MASK, 3, 2, 0, 0, dst_val, src_val);
        let want = native64(op, dst_val, src_val).unwrap();
        prop_assert_eq!(got, want, "ALU64 op 0x{:02x}", op);
    }

    #[test]
    fn alu32_matches_native_and_zero_extends(op_idx in 0usize..ORDINARY.len(), dst_val in any::<u64>(), src_val in any::<u64>()) {
        let op = ORDINARY[op_idx];
        let got = eval_alu(BPF_ALU | op | BPF_SRC_MASK, 3, 2, 0, 0, dst_val, src_val);
        let want = native32(op, dst_val, src_val).unwrap();
        prop_assert_eq!(got, want, "ALU op 0x{:02x}", op);
        prop_assert_eq!(got >> 32, 0, "ALU op 0x{:02x} left a dirty upper half", op);
    }

    #[test]
    fn every_alu32_op_clears_dirty_upper_half(
        op_idx in 0usize..ORDINARY.len(),
        low in any::<u32>(),
        upper in 1u32..=u32::MAX,
        src_val in any::<u64>(),
    ) {
        let op = ORDINARY[op_idx];
        let dirty = ((upper as u64) << 32) | (low as u64);
        let got = eval_alu(BPF_ALU | op | BPF_SRC_MASK, 3, 2, 0, 0, dirty, src_val);
        prop_assert_eq!(got >> 32, 0, "ALU op 0x{:02x} failed to clear dirty half", op);
    }

    #[test]
    fn div_mod_by_zero_follows_spec(dst_val in any::<u64>()) {
        // DIV by zero
        prop_assert_eq!(eval_alu(BPF_ALU64 | BPF_DIV, 3, 0, 0, 0, dst_val, 0), 0);
        prop_assert_eq!(eval_alu(BPF_ALU | BPF_DIV, 3, 0, 0, 0, dst_val, 0), 0);

        // MOD by zero
        prop_assert_eq!(eval_alu(BPF_ALU64 | BPF_MOD, 3, 0, 0, 0, dst_val, 0), dst_val);
        prop_assert_eq!(eval_alu(BPF_ALU | BPF_MOD, 3, 0, 0, 0, dst_val, 0), dst_val & 0xffff_ffff);
    }

    #[test]
    fn div_mod_nonzero_matches_native(dst_val in any::<u64>(), src_val in 1u64..=u64::MAX) {
        prop_assert_eq!(
            eval_alu(BPF_ALU64 | BPF_DIV | BPF_SRC_MASK, 3, 2, 0, 0, dst_val, src_val),
            dst_val / src_val
        );
        prop_assert_eq!(
            eval_alu(BPF_ALU64 | BPF_MOD | BPF_SRC_MASK, 3, 2, 0, 0, dst_val, src_val),
            dst_val % src_val
        );
        let d = dst_val as u32;
        let s = (src_val as u32).max(1);
        prop_assert_eq!(
            eval_alu(BPF_ALU | BPF_DIV | BPF_SRC_MASK, 3, 2, 0, 0, dst_val, s as u64),
            (d/s) as u64
        );
    }

    #[test]
    fn shift_counts_mask(dst_val in any::<u64>(), raw_count in 0u64..256) {
        let got = eval_alu(BPF_ALU64 | BPF_LSH | BPF_SRC_MASK, 3, 2, 0, 0, dst_val, raw_count);
        let want = dst_val.wrapping_shl((raw_count & 63) as u32);
        prop_assert_eq!(got, want);
    }
}

#[test]
fn sdiv_overflow_wraps_not_panics() {
    let mn = 0x8000_0000_0000_0000u64;
    let got = eval_alu(BPF_ALU64 | BPF_DIV | BPF_SRC_MASK, 3, 2, 1, 0, mn, (-1i64) as u64);
    assert_eq!(got, mn, "SDIV MIN / -1 must wrap to MIN");
}
