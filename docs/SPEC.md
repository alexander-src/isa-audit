# `isa-audit` Engineering Specification

## 1. Problem Statement

When building portable Linux binaries, binary relinkers, or instruction-lowering passes (e.g., lowering FMA3 or AVX2 down to baseline AVX or x86-64-v2 for older CPUs), a single accidental compiler-emitted or unlowered instruction causes `SIGILL` (Illegal Instruction) at runtime—often inside a rarely executed cold path that standard unit tests miss.

`isa-audit` is a standalone, zero-dependency static binary auditor and CI gate that scans x86-64 ELF64 executables and shared objects, decodes executable sections, classifies CPU ISA extensions, attributes offending instructions to symbols and virtual addresses, and fails CI if forbidden extensions appear.

## 2. Non-Negotiable Constraints

1. **Zero external crates** (`Cargo.toml` `[dependencies]` is empty) to eliminate supply-chain bloat and guarantee deterministic offline builds.
2. **Memory safety by construction:** `#![forbid(unsafe_code)]` across the entire crate. All binary parsing uses explicit bounds-checked slice reads and checked arithmetic.
3. **Graceful handling of adversarial/corrupted inputs:** Truncated headers, overlapping sections, huge offsets, and non-ELF inputs must return typed errors rather than panicking or allocating unbounded memory.
4. **Deterministic verification oracle:** Decoder accuracy must be verified both with byte-level unit tests and with real compiled C++ kernels produced by `g++` under distinct `-m*` ISA flags.

## 3. Functional Requirements

### 3.1 Supported Input Format
- 64-bit little-endian ELF (`ELFCLASS64`, `ELFDATA2LSB`, `EM_X86_64`).
- Executable sections (`SHF_EXECINSTR` and `SHT_PROGBITS`), with optional symbol attribution from `.symtab`/`.strtab` and `.dynsym`/`.dynstr`.

### 3.2 Tracked x86-64 ISA Features
- Baseline & SSE lineage: `baseline`, `sse3`, `ssse3`, `sse4.1`, `sse4.2`, `popcnt`, `pclmulqdq`, `aes`
- Bit manipulation & misc: `movbe`, `lzcnt`, `bmi1`, `bmi2`, `adx`, `sha`, `f16c`
- Vector extensions: `avx`, `avx2`, `fma3`, `avx512f`, `avx512vl`, `avx512bw`, `avx512dq`

### 3.3 Microarchitecture Target Profiles
- `x86-64-v1`: baseline (SSE/SSE2)
- `x86-64-v2`: v1 + `sse3`, `ssse3`, `sse4.1`, `sse4.2`, `popcnt`
- `avx-no-fma`: v2 + `avx`, `aes`, `pclmulqdq` (useful for verifying `--to-avx` / FMA3-lowering passes on Sandy Bridge / Ivy Bridge targets)
- `x86-64-v3`: v2 + `avx`, `avx2`, `fma3`, `bmi1`, `bmi2`, `f16c`, `lzcnt`, `movbe`
- `x86-64-v4`: v3 + `avx512f`, `avx512vl`, `avx512bw`, `avx512dq`

### 3.4 CLI Interface
- `isa-audit scan <binary> [--format text|json|sarif] [--top N] [--section NAME]`
- `isa-audit check <binary> [--target PROFILE] [--forbid feat1,feat2] [--format text|json|sarif] [--max-findings N]`
  - Exit code `0`: binary complies with policy.
  - Exit code `1`: one or more forbidden instructions found.
  - Exit code `2`: invalid arguments, I/O error, or malformed ELF.
- `isa-audit bench <binary> [--iterations N]`
  - Measures pure decode & analysis throughput in MB/s and instructions/sec.

## 4. Non-Goals (v0.1)
- Full symbolic disassembly (mnemonics are classified into ISA family + exact class labels rather than duplicating full `xed`/`capstone` operand printers).
- Control-flow graph reconstruction (linear + function-symbol-resynchronized sweep is used, which handles standard compiler output reliably while staying O(n) single-pass).
