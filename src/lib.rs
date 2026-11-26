#![forbid(unsafe_code)]

//! `isa-audit`: Zero-dependency x86-64 ELF64 binary ISA feature auditor and CI verification gate.

pub mod analyzer;
pub mod archive;
pub mod decoder;
pub mod elf;
pub mod isa;
pub mod report;
