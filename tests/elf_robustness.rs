use std::collections::BTreeSet;

use isa_audit::analyzer::{audit_binary, AuditOptions};
use isa_audit::elf::{ElfBinary, ElfError};
use isa_audit::isa::IsaFeature;

/// Builds a minimal valid x86-64 ELF64 binary with a `.text` section and optional `.symtab`.
fn build_synthetic_elf(text_bytes: &[u8], func_symbols: &[(&str, u64, u64)]) -> Vec<u8> {
    let mut buf = Vec::new();
    let text_vaddr: u64 = 0x401000;

    // Reserve 64-byte ELF header (patched at end)
    buf.resize(64, 0);

    // Section 1: .text
    let text_off = buf.len() as u64;
    buf.extend_from_slice(text_bytes);

    // Section 2: .shstrtab
    let shstrtab_off = buf.len() as u64;
    let mut shstrtab = Vec::new();
    shstrtab.push(0);
    let name_text = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");
    let name_shstrtab = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");
    let name_strtab = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".strtab\0");
    let name_symtab = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".symtab\0");
    buf.extend_from_slice(&shstrtab);

    // Section 3: .strtab
    let strtab_off = buf.len() as u64;
    let mut strtab = vec![0u8];
    let mut sym_name_offsets = Vec::new();
    for &(name, _, _) in func_symbols {
        sym_name_offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
    }
    buf.extend_from_slice(&strtab);

    // Align to 8 bytes for .symtab
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    // Section 4: .symtab (null entry + function entries)
    let symtab_off = buf.len() as u64;
    buf.extend_from_slice(&[0u8; 24]); // STN_UNDEF
    for (idx, &(_, rel_off, size)) in func_symbols.iter().enumerate() {
        let mut ent = [0u8; 24];
        ent[0..4].copy_from_slice(&sym_name_offsets[idx].to_le_bytes());
        ent[4] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
        ent[6..8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx = .text
        ent[8..16].copy_from_slice(&(text_vaddr + rel_off).to_le_bytes());
        ent[16..24].copy_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&ent);
    }
    let symtab_size = (buf.len() as u64) - symtab_off;

    // Align to 8 bytes for Section Header Table
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    let shoff = buf.len() as u64;

    let push_shdr = |out: &mut Vec<u8>,
                     sh_name: u32,
                     sh_type: u32,
                     sh_flags: u64,
                     sh_addr: u64,
                     sh_offset: u64,
                     sh_size: u64,
                     sh_link: u32,
                     sh_entsize: u64| {
        let mut sh = [0u8; 64];
        sh[0..4].copy_from_slice(&sh_name.to_le_bytes());
        sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
        sh[8..16].copy_from_slice(&sh_flags.to_le_bytes());
        sh[16..24].copy_from_slice(&sh_addr.to_le_bytes());
        sh[24..32].copy_from_slice(&sh_offset.to_le_bytes());
        sh[32..40].copy_from_slice(&sh_size.to_le_bytes());
        sh[40..44].copy_from_slice(&sh_link.to_le_bytes());
        sh[56..64].copy_from_slice(&sh_entsize.to_le_bytes());
        out.extend_from_slice(&sh);
    };

    // 0: SHT_NULL
    push_shdr(&mut buf, 0, 0, 0, 0, 0, 0, 0, 0);
    // 1: .text (SHT_PROGBITS=1, SHF_ALLOC|SHF_EXECINSTR=6)
    push_shdr(
        &mut buf,
        name_text,
        1,
        0x6,
        text_vaddr,
        text_off,
        text_bytes.len() as u64,
        0,
        0,
    );
    // 2: .shstrtab (SHT_STRTAB=3)
    push_shdr(
        &mut buf,
        name_shstrtab,
        3,
        0,
        0,
        shstrtab_off,
        shstrtab.len() as u64,
        0,
        0,
    );
    // 3: .strtab (SHT_STRTAB=3)
    push_shdr(
        &mut buf,
        name_strtab,
        3,
        0,
        0,
        strtab_off,
        strtab.len() as u64,
        0,
        0,
    );
    // 4: .symtab (SHT_SYMTAB=2, link=3)
    push_shdr(
        &mut buf,
        name_symtab,
        2,
        0,
        0,
        symtab_off,
        symtab_size,
        3,
        24,
    );

    // Patch ELF64 header
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&text_vaddr.to_le_bytes());
    buf[40..48].copy_from_slice(&shoff.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&5u16.to_le_bytes()); // e_shnum
    buf[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx

    buf
}

#[test]
fn attributes_forbidden_fma_instruction_to_exact_symbol_and_offset() {
    // Function 1 @ +0x0 (size 5): vaddps ymm0, ymm1, ymm2; ret
    // Function 2 @ +0x5 (size 6): vfmadd213ps ymm0, ymm1, ymm2; ret
    let text = [
        0xc5, 0xf4, 0x58, 0xc2, 0xc3, // clean_avx_fn (5 bytes)
        0xc4, 0xe2, 0x75, 0xa8, 0xc2, 0xc3, // unlowered_fma_fn (6 bytes)
    ];
    let elf_bytes =
        build_synthetic_elf(&text, &[("clean_avx_fn", 0, 5), ("unlowered_fma_fn", 5, 6)]);
    let elf = ElfBinary::parse(&elf_bytes).expect("synthetic ELF must parse cleanly");

    let mut forbidden = BTreeSet::new();
    forbidden.insert(IsaFeature::Fma3);
    let report = audit_binary(
        "synthetic.elf",
        &elf,
        &AuditOptions {
            forbidden,
            ..AuditOptions::default()
        },
    );

    assert!(!report.passed());
    assert_eq!(report.total_violations, 1);
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert_eq!(f.feature, IsaFeature::Fma3);
    assert_eq!(f.symbol.as_deref(), Some("unlowered_fma_fn"));
    assert_eq!(f.symbol_offset, 0);
    assert_eq!(f.vaddr, 0x401005);
}

#[test]
fn rejects_corrupted_truncated_and_non_x86_64_inputs_gracefully() {
    assert!(matches!(
        ElfBinary::parse(&[0u8; 16]),
        Err(ElfError::TooSmall { .. })
    ));

    let mut bad_magic = [0u8; 64];
    bad_magic[0..4].copy_from_slice(b"NOPE");
    assert_eq!(
        ElfBinary::parse(&bad_magic).unwrap_err(),
        ElfError::BadMagic
    );

    // Valid synthetic ELF mutated with extreme section header offsets/sizes
    let valid = build_synthetic_elf(&[0x90, 0xc3], &[]);

    // 32-bit ELF rejected
    let mut elf32 = valid.clone();
    elf32[4] = 1;
    assert_eq!(
        ElfBinary::parse(&elf32).unwrap_err(),
        ElfError::UnsupportedClass(1)
    );

    // Big-endian rejected
    let mut big_endian = valid.clone();
    big_endian[5] = 2;
    assert_eq!(
        ElfBinary::parse(&big_endian).unwrap_err(),
        ElfError::UnsupportedEndianness(2)
    );

    // AArch64 (EM_AARCH64 = 183) rejected
    let mut arm64 = valid.clone();
    arm64[18..20].copy_from_slice(&183u16.to_le_bytes());
    assert_eq!(
        ElfBinary::parse(&arm64).unwrap_err(),
        ElfError::UnsupportedMachine(183)
    );

    // Integer overflow in e_shoff rejected cleanly
    let mut overflow_shoff = valid.clone();
    overflow_shoff[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(ElfBinary::parse(&overflow_shoff).is_err());

    // Truncating at every single byte boundary never panics
    for cut in 0..valid.len() {
        let _ = ElfBinary::parse(&valid[..cut]);
    }
}
