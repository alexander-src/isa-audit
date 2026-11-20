# AI-Assisted Engineering & Verification Notes

`isa-audit` was built using a **spec-first, oracle-verified AI engineering workflow**: AI coding tools accelerated boilerplate and decoding table implementation, while deterministic compilers (`g++`), `objdump`, and strict Rust compiler/lint invariants acted as the ground-truth verification gate.

## 1. Constraints Set Upfront (Before Code Generation)
Before writing implementation code, [`docs/SPEC.md`](SPEC.md) locked down four invariants that agents could not relax:
- `#![forbid(unsafe_code)]` across the entire crate.
- Zero external crates (`Cargo.toml` `[dependencies]` empty).
- Every ELF parse operation uses explicit checked arithmetic and slice bounds.
- Verification requires **real compiled C++ binaries from `g++`** across distinct `-m*` ISA flags, not just hand-crafted unit test arrays.

## 2. Real Bugs Caught by Deterministic Verification

### Bug #1: `ET_REL` Object File Symbol Attribution (`st_value == 0`)
- **What went wrong:** The initial ELF64 symbol parser skipped any symbol with `st_value == 0` to ignore undefined external imports. That worked on synthetic linked `ET_EXEC` binaries (where `.text` starts at `0x401000`), so all unit tests passed.
- **How it was caught:** The `tests/gcc_ground_truth.rs` oracle compiled real relocatable object files (`g++ -c ... -o kernel.o`), where the first function (`fma3_kernel`) legitimately lives at `st_value == 0` inside `.text`. Symbol attribution returned `None`.
- **Root-cause fix:** Updated `src/elf.rs` to filter undefined imports via `st_shndx != SHN_UNDEF` rather than `st_value != 0`, and scoped symbol lookups by `section_index` so multiple executable sections starting at offset `0` in `ET_REL` files never collide.

### Bug #2: `tzcnt` (`F3 0F BC`) False Positive on Baseline `x86-64-v1` Binaries
- **What went wrong:** Following textbook ISA tables, the decoder initially classified `F3 0F BC` (`tzcnt`) as `BMI1`.
- **How it was caught:** Running `isa-audit` on its **own** release binary (`./target/release/isa-audit`) reported `min-profile: x86-64-v3` with 26 `BMI1` hits. Cross-checking address `0x36574` with `objdump -d` revealed LLVM/rustc's classic baseline sequence:
  ```asm
  test   %eax, %eax
  je     36582
  tzcnt  %eax, %eax   ; F3 0F BC C0, executes as `rep bsf` on pre-BMI1 CPUs
  ```
- **Why it matters:** On pre-BMI1 CPUs, `F3 0F BC` executes as `REP BSF` without raising `#UD`/`SIGILL`, and produces identical output whenever the input is proven non-zero. Flagging it as hard-faulting `BMI1` produces false positives on virtually every Rust/LLVM baseline binary.
- **Root-cause fix:** Reclassified `F3 0F BC` as `Baseline` (`tzcnt/rep-bsf`) so `isa-audit` strictly reports instructions capable of raising `SIGILL`, while continuing to flag VEX-encoded BMI1 instructions (`andn`, `blsr`, `blsmsk`, `blsi`, `bextr`). Added a regression test in `tests/decoder_unit.rs` and an end-to-end self-scan assertion in `tests/cli_integration.rs`.

## 3. Automated Quality Gates
Every change is verified against:
1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test` (decoder unit tests + truncated/corrupted ELF fuzzing + 6-configuration `g++` ground-truth suite + CLI exit-code integration tests)
4. Cross-checks against GNU `objdump` on real system binaries (`/usr/bin/ls`, `/usr/bin/objdump`, and self-hosted release binary).
