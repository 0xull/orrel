//! Property test for the below register-file trichotomy.
//! 
//! For every register index in 0..=15 and every 64-bit value, the accessors
//! place operations into exactly one of three outcomes:
//! - round-trip for a general register,
//! - read-only rejection for the frame pointer, or
//! - bad-register rejection for an index that names no real register.

use proptest::prelude::*;
use interp::{FRAME_PTR, FRAME_TOP, NUM_REGS, Vm, VmError};

proptest! {
    #[test]
    fn accessor_trichotomy(index in 0usize..=15, value in any::<u64>()) {
       let mut vm = Vm::new();
       let fp_before = vm.reg(FRAME_PTR).expect("r10 is always readable");

       if index < FRAME_PTR {
           // For general register, write succeeds and read returns exactly it.
           prop_assert!(vm.set_reg(index, value).is_ok());
           prop_assert_eq!(vm.reg(index).unwrap(), value);
       } else if index == FRAME_PTR {
           // Frame pointer, write is rejected and the value is unchanged.
           prop_assert_eq!(vm.set_reg(index, value), Err(VmError::WriteToFramePointer));
           prop_assert_eq!(vm.reg(index).unwrap(), fp_before);
       } else {
           // 11..=15, no real register, rejected on both operations
           prop_assert_eq!(vm.set_reg(index, value), Err(VmError::BadRegister(index)));
           prop_assert_eq!(vm.reg(index), Err(VmError::BadRegister(index)));
       }
    }

    #[test]
    fn writes_do_not_bleed_across_registers(target in 0usize..FRAME_PTR, value in any::<u64>()) {
        let mut vm = Vm::new();
        vm.set_reg(target, value).unwrap();

        for other in 0..NUM_REGS {
            if other == target {
                continue;
            }

            let expected = if other == FRAME_PTR { FRAME_TOP } else { 0 };
            prop_assert_eq!(
                vm.reg(other).unwrap(),
                expected,
                "writing r{} affected r{}",
                target, 
                other,
            );
        }
    }
}