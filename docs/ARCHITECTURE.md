# `isa-audit` Architecture

## Pipeline Overview

```
ELF64 Binary Bytes
        │
        ▼
┌───────────────────┐
│   src/elf.rs      │  Bounds-checked ELF64 header, section table,
│   ELF64 Parser    │  SHF_EXECINSTR extraction, .symtab/.dynsym symbol map
└────────┬──────────┘
         │  Vec<ExecSection> + Vec<SymbolSpan>
         ▼
┌───────────────────┐
│  src/analyzer.rs  │  Resynchronizes at known STT_FUNC boundaries inside
│  Section Scanner  │  executable sections; falls back to linear sweep on
└────────┬──────────┘  stripped binaries; attributes every finding to symbol
         │
         ▼
┌───────────────────┐
│  src/decoder.rs   │  64-bit x86-64 instruction length & feature decoder:
│  x86-64 Decoder   │  Legacy prefixes -> REX / VEX2 / VEX3 / EVEX ->
└────────┬──────────┘  Opcode map (1B / 0F / 0F38 / 0F3A) -> ModRM/SIB/Imm
         │
         ▼
┌───────────────────┐
│   src/report.rs   │  Deterministic outputs:
│   Report Engine   │  - ANSI-aware human summary + top offending sites
└───────────────────┘  - Strict RFC 8259 JSON
                       - SARIF 2.1.0 for GitHub Code Scanning
```

## Key Engineering Decisions

### 1. Function-Boundary Resynchronization
Linear disassembly over an entire `.text` section can desynchronize if inline jump tables or non-NOP padding sit between functions. When `.symtab` or `.dynsym` is present, `analyzer.rs` partitions executable ranges along sorted `STT_FUNC` spans `[addr, addr + size)` and restarts the decoder at every function entry point. Stripped binaries seamlessly fall back to a full linear sweep with 1-byte recovery on invalid encodings.

### 2. Zero-Allocation Hot Loop
The inner x86-64 decoder (`decoder::decode_one`) operates purely on `&[u8]` slices with stack-only `Copy` structs (`DecodedInsn`), avoiding per-instruction heap allocations. Findings are only materialized for instructions that violate the active policy (or match non-baseline detail requests).

### 3. Strict 64-Bit Encoding Rules
- In 64-bit mode, `0xC4` (VEX3), `0xC5` (VEX2), and `0x62` (EVEX) are never valid legacy `LES`/`LDS`/`BOUND` opcodes, but random padding bytes in data islands can still match those byte values. The decoder validates map bits (`mmmmm in 1..=3` for VEX, `P1.bit2 == 1` and valid `mmm` for EVEX) and rejects malformed sequences instead of misreporting false AVX/AVX-512 hits.
- `vzeroupper`/`vzeroall` (`VEX.0F 0x77`) take no ModRM byte; handling this explicitly prevents consuming the first byte of the following instruction.
- `REX.W` promotes `0xB8..=0xBF` immediate operands from `imm32` to `imm64`, while `0x66` narrows default 32-bit immediates to `imm16` when `REX.W == 0`.
- `0xF6`/`0xF7` Group 3 opcodes only carry an immediate operand when `ModRM.reg` is `0` or `1` (`TEST`), not for `NOT`/`NEG`/`MUL`/`DIV`.

### 4. Inferred Microarchitecture Level
After scanning all executable sections, `isa.rs` computes the minimum x86-64 microarchitecture level (`x86-64-v1`, `x86-64-v2`, `avx-no-fma`, `x86-64-v3`, `x86-64-v4`, or `custom`) required to run the binary without `SIGILL`.
