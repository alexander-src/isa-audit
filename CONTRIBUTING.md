# Contributing to isa-audit

Contributions, bug reports, and new x86-64 ISA coverage are welcome.

## Design rules

- Keep zero external crate dependencies (`Cargo.toml` `[dependencies]` stays empty).
- Preserve `#![forbid(unsafe_code)]` across the crate and binary.
- Never panic on truncated, malformed, or hostile ELF inputs.

## Local verification

Run these checks before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

On Linux x86-64 with `g++` on `PATH`, `cargo test` also compiles real C++ kernels in `tests/gcc_ground_truth.rs` to verify decoder classifications against GCC output.

## Adding a new x86-64 ISA extension

1. Add the variant to `IsaFeature` in `src/isa.rs` (including `id()`, `label()`, `FromStr`, and `TargetProfile` mappings where appropriate).
2. Add decoding rules in `src/decoder.rs` (legacy 2/3-byte opcodes, VEX2/VEX3, or EVEX).
3. Add a byte-level decoding test in `tests/decoder_unit.rs`.
4. Add a live compiler ground-truth kernel in `tests/gcc_ground_truth.rs` so classification is checked against real emitted machine code.
