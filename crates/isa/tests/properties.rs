//! Structure-aware property tests for the decoder.
//!
//! These assert the four decoder invariants over generated populations
//! rather than over hand-picked examples.

use isa::encode::{encode_insn, encode_program};
use isa::{decode, DecoderError, Insn};
use proptest::prelude::*;

// A small, plausible set of single-slot opcodes drawn from the classes the
// decoder recognizes. The generator need enough spread of opcodes whose low
// 3 bits exercise several classes and whose value is not wide-load opcode.
const BASIC_OPCODES: &[u8] = &[
    0x07, // ALU64 ADD imm
    0xbf, // ALU64 MOV reg
    0x0f, // ALU64 ADD reg
    0xb7, // ALU64 MOV imm
    0x79, // LDX DW
    0x7b, // STX DW
    0x61, // LDX W
    0x63, // STX W
    0x05, // JMP JA
    0x1d, // JMP JEQ reg
    0x95, // JMP EXIT
];

/// A strategy that produces a one well-formed single-slot instruction as an
/// 8-byte vector. Register numbers stay in 0..=10 to remain plausible, although
/// the decoder doesn't itself range-check them.
fn basic_slot() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::sample::select(BASIC_OPCODES),
        0u8..=9,
        0u8..=10,
        any::<i16>(),
        any::<i32>(),
    )
        .prop_map(|(opcode, dst, src, offset, imm)| {
            let ins = Insn {
                slot: 0,
                opcode,
                dst,
                src,
                offset,
                imm,
                imm64: None,
                slots: 1,
            };
            encode_insn(&ins)
        })
}

/// A strategy that produces one well-formed wide load as a 16-byte vector,
/// with source register zero so it is a plain 64-bit constant load.
fn wide_slot() -> impl Strategy<Value = Vec<u8>> {
    (0u8..=9, any::<u64>()).prop_map(|(dst, value)| {
        let ins = Insn {
            slot: 0,
            opcode: 0x18,
            dst,
            src: 0,
            offset: 0,
            imm: (value & 0xffff_ffff) as i32,
            imm64: Some(value as i64),
            slots: 2,
        };
        encode_insn(&ins)
    })
}

fn valid_stream() -> impl Strategy<Value = Vec<u8>> {
    let one = prop_oneof![
        3 => basic_slot(),
        1 => wide_slot(),
    ];
    prop::collection::vec(one, 0..=24).prop_map(|slots| {
        let mut buf = Vec::new();
        for s in slots {
            buf.extend_from_slice(&s);
        }
        buf
    })
}

proptest! {
    // on any valid stream, decode succeeds, the slot counts
    // sum to the true slot count, and slot numbers advance in
    // lockstep with slots consumed.
    #[test]
    fn slot_accounting_and_monotonicity(buf in valid_stream()) {
        let prog = decode(&buf).expect("a structurally valid stream must decode");

        let total_slots: usize = prog.iter().map(|i| i.slots).sum();
        prop_assert_eq!(total_slots, buf.len()/8, "slot accounting diverged");

        let mut expected_slot = 0usize;
        for ins in prog {
            prop_assert_eq!(ins.slot, expected_slot, "slot monotonicity broke");
            expected_slot += ins.slots;
        }
    }

    // decode then encode then decode recovers the same program.
    #[test]
    fn round_trip_is_stable(buf in valid_stream()) {
        let prog = decode(&buf).expect("valid stream must decode");
        let reencoded = encode_program(&prog);
        prop_assert_eq!(&reencoded, &buf, "re-encoding did not reproduce the same bytes");

        let prog2 = decode(&reencoded).expect("re-encoded stream must decode");
        prop_assert_eq!(prog, prog2, "decode is not idempotent across a round trip");
    }

    // on arbitrary bytes, decode never panics.
    #[test]
    fn never_panics_on_arbitrary_input(buf in prop::collection::vec(any::<u8>(), 0..64)) {
        match decode(&buf) {
            Ok(_) => {},
            Err(DecoderError::NotSlotAligned(_)) => {},
            Err(DecoderError::TruncatedWideLoad(_)) => {},
        }
    }

    // a robustness check that an 8-byte-aligned buffer whose final slot
    // is a wide-load opcode with no following slot must be handled (rejected).
    fn truncated_wide_load_is_rejected(prefix in prop::collection::vec(basic_slot(), 0..8)) {
        let mut buf = Vec::new();
        for s in prefix {
            buf.extend_from_slice(&s);
        }
        let truncated_slot = buf.len()/8;
        buf.extend_from_slice(&[0x18, 0, 0, 0, 0, 0, 0, 0]); //wide-load opcode with no second slot

        prop_assert_eq!(decode(&buf), Err(DecoderError::TruncatedWideLoad(truncated_slot)));
    }
}
