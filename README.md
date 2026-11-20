# `isa-audit`

[![CI](https://github.com/alexander-src/isa-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/alexander-src/isa-audit/actions/workflows/ci.yml)
![Zero Dependencies](https://img.shields.io/badge/dependencies-0-22c55e)
![Unsafe Code](https://img.shields.io/badge/unsafe-forbidden-38bdf8)
![License](https://img.shields.io/badge/license-MIT-94a3b8)

A fast, **zero-dependency**, `#![forbid(unsafe_code)]` Rust CLI & library that audits x86-64 ELF64 binaries for CPU ISA extensions and acts as a **CI verification gate** against accidental `SIGILL` instructions.

Built for verifying portable release builds, binary relinkers, and instruction-lowering passes (such as lowering `FMA3` / `AVX2` down to `AVX` or `x86-64-v2`).

---

## Why `isa-audit`?

A single unlowered `vfmadd` or compiler-emitted `AVX2` instruction inside a rarely hit error path crashes older x86-64 CPUs with `SIGILL` in production. `isa-audit` statically scans every executable ELF section (`SHF_EXECINSTR`), resynchronizes on `STT_FUNC` symbol boundaries, classifies x86-64 instructions across legacy, REX, VEX2, VEX3, and EVEX encodings, and pinpoints offending sites with **section, virtual address, symbol+offset, and raw bytes**.

### Highlights
- **Zero external crates:** compiles offline in ~1 second; stripped release binary is **427 KB**.
- **100% safe Rust (`#![forbid(unsafe_code)]`):** bounds-checked ELF64 parsing tested against byte-by-byte truncation and integer-overflow corruption.
- **High throughput:** **259-282 MiB/s (~68-70 million instructions/sec)** single-threaded decode speed on real x86-64 binaries.
- **CI-native output:** deterministic terminal tables, strict RFC 8259 **JSON**, and **SARIF 2.1.0** for GitHub Code Scanning, with semantic exit codes (`0` pass, `1` policy violation, `2` error).
- **Compiler ground-truth verified:** integration suite compiles real C++ kernels via `g++` (`-mno-avx`, `-mavx -mno-fma`, `-mfma`, `-mavx2`, `-mbmi -mbmi2`, `-maes -mpopcnt`) and asserts exact ISA classification and symbol attribution.

---

## Quick Start

```bash
cargo build --release

# Inspect ISA profile and instruction breakdown of any x86-64 ELF64 binary
./target/release/isa-audit scan /path/to/binary

# Enforce a microarchitecture policy in CI (e.g. verify FMA3 lowering to AVX)
./target/release/isa-audit check ./build/relinked_game --target avx-no-fma

# Forbid specific extensions and emit GitHub Code Scanning SARIF
./target/release/isa-audit check ./build/app --forbid fma3,avx2,avx512 --format sarif > isa.sarif

# Benchmark decode throughput on any binary
./target/release/isa-audit bench /usr/bin/objdump --iterations 100
```

### Example Output (`check --target avx-no-fma`)

```text
isa-audit report: demo.o
  min-profile   : x86-64-v3
  sections      : 1 (21 bytes decoded, 6 instructions, 0 recovery steps)
  policy-status : FAIL (forbid: movbe, lzcnt, bmi1, bmi2, adx, sha, f16c, avx2, fma3, avx512f, avx512vl, avx512bw, avx512dq, violations: 1)

ISA Feature Breakdown:
  FEATURE                   COUNT    STATUS
  ------------------------------------------
  AVX                           4        ok
  x86-64 (SSE/SSE2)             1        ok
  FMA3                          1   FORBIDDEN

Forbidden Instruction Sites (showing 1 of 1):
  0x000000000008  FMA3       vfmadd         vector_fma+0x8                       [c4 e2 75 98 06]
```

---

## Microarchitecture Profiles

| Profile | Allowed Extensions | Primary Use Case |
| :--- | :--- | :--- |
| `x86-64-v1` | Baseline SSE / SSE2 | Maximum portability (2003+ x86-64 CPUs) |
| `x86-64-v2` | v1 + SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT | Standard distro baseline (Nehalem+) |
| `avx-no-fma` | v2 + AVX, AES-NI, PCLMULQDQ | Verifying `--to-avx` / FMA3-lowering targets (Sandy/Ivy Bridge) |
| `x86-64-v3` | v2 + AVX, AVX2, FMA3, BMI1/2, F16C, LZCNT, MOVBE | Modern x86-64 baseline (Haswell / Zen 1+) |
| `x86-64-v4` | v3 + AVX-512F, VL, BW, DQ | High-throughput AVX-512 builds |

---

## Measured Benchmarks

Measured on Linux x86-64 (single-threaded release build, 100 iterations):

| Binary | Executable Bytes | Instructions / Pass | Recovery Steps | Throughput |
| :--- | ---: | ---: | ---: | ---: |
| `isa-audit` (self-scan) | 341,751 B | 86,343 | 0 | **259.1 MiB/s** (68.6M insns/s) |
| `/usr/bin/objdump` | 274,050 B | 65,085 | 0 | **281.6 MiB/s** (70.1M insns/s) |
| `/usr/bin/ls` | 134,923 B | 30,891 | 0 | Verified against `objdump` (AVX / AVX-512) |

---

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md): Formal specification and invariants
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): ELF64 parser, function-resynchronized scanner, and x86-64 decoder design
- [`docs/AI_WORKFLOW.md`](docs/AI_WORKFLOW.md): Engineering workflow and real bugs caught by compiler & `objdump` verification

---

## License

MIT. See [`LICENSE`](LICENSE).
