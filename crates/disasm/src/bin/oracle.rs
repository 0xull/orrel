//! Differential oracle. For each object file given on the command line,
//! extract its .text, decode it and confirm the decoded slot numbers
//! and raw bytes agree with llvm-objdump's view.
//!
//! Ground truth is the raw byte column of llvm-objdump. The slot number
//! column is llvm's independent opinion on slot numbering.
//! 
//! Run with:
//!   ./oracle prog1.o prog2.o prog3.o ...

use std::process::{Command, ExitCode};

use isa::decode;

/// One instruction as llvm-objdump reports it. the slot it labels
/// the instruction with, and the raw bytes it prints for that instruction.
struct ObjdumpInsn {
    slot: usize,
    bytes: Vec<u8>
}

/// Parse `llvm-objdump -d` output into the instruction lines. Each instruction line
/// has the shape: whitespace, decimal slot, ':', tab, space-separated hex byte pairs,
/// tab, disassembly text. Rest is skipped.
fn parse_objdump(text: &str) -> Vec<ObjdumpInsn> {
    let mut out = Vec::new();

    for line in text.lines() {
        let Some((label, rest)) = line.split_once('\t') else {
            continue;
        };
        let label = label.trim();
        let Some(slot_str) = label.strip_suffix(':') else {
            continue;
        };
        let Ok(slot) = slot_str.trim().parse::<usize>() else {
            continue;
        };

        let hex_col = match rest.split_once('\t') {
            Some((hex, _disasm)) => hex,
            None => rest, // some lines might lack trailing disasm
        };

        let mut bytes = Vec::new();
        let mut ok = true;
        for tok in hex_col.split_whitespace() {
            match u8::from_str_radix(tok, 16) {
                Ok(b) => bytes.push(b),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }

        if ok && !bytes.is_empty() {
            out.push(ObjdumpInsn { slot, bytes })
        }
    }
    out
}

fn check_one(path: &str) -> Result<(), String> {
    // extract .text section into a temp file
    let bin_path = format!("{path}.text.bin");
    let copy = Command::new("llvm-objcopy")
        .args(["--dump-section", &format!(".text={bin_path}"), path])
        .status()
        .map_err(|e| format!("cannot run llvm-objcopy: {e}"))?;
    if !copy.success() {
        return Err(format!("llvm-objcopy failed on {path}"));
    }

    // disassemble with reference tool
    let dump = Command::new("llvm-objdump")
        .args(["-d", path])
        .output()
        .map_err(|e| format!("cannot run llvm-objdump: {e}"))?;
    if !dump.status.success() {
        return Err(format!("llvm-objdump failed on {path}"));
    }
    let dump_text = String::from_utf8_lossy(&dump.stdout);
    let reference = parse_objdump(&dump_text);

    // disassemble with orrel `decode`
    let bytes = std::fs::read(&bin_path).map_err(|e| format!("cannot read {bin_path}: {e}"))?;
    let decode_out = decode(&bytes).map_err(|e| format!("orrel-decoder rejected {path}: {e:?}"))?;

    // both must agree on same number of instructions
    if decode_out.len() != reference.len() {
        return Err(format!(
            "{path}: instruction count differs, orrel-decoder={} llvm-objdump={}",
            decode_out.len(),
            reference.len()
        ));
    }

    // for each instruction, both slot number/label and raw bytes (byte column)
    // must match.
    let mut byte_cursor = 0usize;
    for (idx, (decode_ins, ref_ins)) in decode_out.iter().zip(reference.iter()).enumerate() {
        if decode_ins.slot != ref_ins.slot {
            return Err(format!(
                "{path}: instruction {idx}: slot differs, orrel-decoder={} llvm-objdump={}",
                decode_ins.slot, ref_ins.slot
            ));
        }

        let width = decode_ins.slots * 8;
        let decode_bytes = &bytes[byte_cursor..byte_cursor+width];
        if decode_bytes != ref_ins.bytes.as_slice() {
            return Err(format!(
                "{path}: instruction {idx} at slot {}: raw bytes differ\n  orrel-decoder=    {:02x?}\n  llvm-objdump=    {:02x?}",
                decode_ins.slot, decode_bytes, ref_ins.bytes
            ));
        }
        byte_cursor += width;
    }

    println!("ok: {path}: {} instructions agree with llvm-objdump", decode_out.len());
    Ok(())
}

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: oracle <obj1.o> [obj2.o ...]");
        return ExitCode::from(2);
    }

    let mut failures = 0;
    for path in &paths {
        if let Err(e) = check_one(path) {
            eprintln!("MISMATCH {e}");
            failures +=1;
        }
    }

    if failures == 0 {
        println!("all {} object(s) agree with llvm-objdump", paths.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("{failures} object(s) disagreed");
        ExitCode::FAILURE
    }
}
