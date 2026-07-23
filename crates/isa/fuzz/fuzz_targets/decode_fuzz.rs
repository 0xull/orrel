#![no_main]

use libfuzzer_sys::fuzz_target;
use isa::{decode, DecoderError};

fuzz_target!(|data: &[u8]| {
    match decode(data) {
        Ok(prog) => {
            let total: usize = prog.iter().map(|i| i.slots).sum();
            assert_eq!(total, data.len()/8, "fuzz: slot accounting diverged");
        }
        Err(DecoderError::NotSlotAligned(_)) => {}
        Err(DecoderError::TruncatedWideLoad(_)) => {}
    }
});