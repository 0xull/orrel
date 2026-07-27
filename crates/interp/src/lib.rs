//! The eBPF virtual machine state; the register file and the stack frame.

pub const NUM_REGS: usize = 11;
pub const FRAME_PTR: usize = 10;
pub const STACK_SIZE: u64 = 512;

// The virtual base address of the stack region.
pub const STACK_BASE: u64 = 0x2_0000_0000;
// r10 points one byte past the top of the stack.
pub const FRAME_TOP: u64 = STACK_BASE + STACK_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    BadRegister(usize),
    WriteToFramePointer,
}

pub struct Vm {
    regs: [u64; NUM_REGS],
    #[allow(dead_code)]
    stack: Box<[u8; STACK_SIZE as usize]>,
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
}

impl Default for Vm {
    fn default() -> Self {
        Vm::new()
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
}
