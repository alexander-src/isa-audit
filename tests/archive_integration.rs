use std::collections::BTreeSet;

use isa_audit::analyzer::{audit_input, AuditOptions};
use isa_audit::archive::{is_archive, Archive, ArchiveError, ARCHIVE_MAGIC, THIN_ARCHIVE_MAGIC};
use isa_audit::isa::IsaFeature;

fn build_minimal_elf(text: &[u8]) -> Vec<u8> {
    let text_vaddr: u64 = 0x401000;
    let mut buf = vec![0u8; 64];

    let text_off = buf.len() as u64;
    buf.extend_from_slice(text);

    let shstrtab_off = buf.len() as u64;
    let shstrtab = b"\0.text\0.shstrtab\0";
    buf.extend_from_slice(shstrtab);

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
                     sh_size: u64| {
        let mut sh = [0u8; 64];
        sh[0..4].copy_from_slice(&sh_name.to_le_bytes());
        sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
        sh[8..16].copy_from_slice(&sh_flags.to_le_bytes());
        sh[16..24].copy_from_slice(&sh_addr.to_le_bytes());
        sh[24..32].copy_from_slice(&sh_offset.to_le_bytes());
        sh[32..40].copy_from_slice(&sh_size.to_le_bytes());
        out.extend_from_slice(&sh);
    };

    push_shdr(&mut buf, 0, 0, 0, 0, 0, 0);
    push_shdr(&mut buf, 1, 1, 0x6, text_vaddr, text_off, text.len() as u64);
    push_shdr(&mut buf, 7, 3, 0, 0, shstrtab_off, shstrtab.len() as u64);

    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[16..18].copy_from_slice(&1u16.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[40..48].copy_from_slice(&shoff.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    buf[60..62].copy_from_slice(&3u16.to_le_bytes());
    buf[62..64].copy_from_slice(&2u16.to_le_bytes());
    buf
}

fn push_ar_member(out: &mut Vec<u8>, raw_name: &str, payload: &[u8]) {
    let mut header = [b' '; 60];
    let name_bytes = raw_name.as_bytes();
    assert!(name_bytes.len() <= 16);
    header[..name_bytes.len()].copy_from_slice(name_bytes);
    header[16..17].copy_from_slice(b"0");
    header[28..29].copy_from_slice(b"0");
    header[34..35].copy_from_slice(b"0");
    header[40..46].copy_from_slice(b"100644");
    let size_s = payload.len().to_string();
    header[48..48 + size_s.len()].copy_from_slice(size_s.as_bytes());
    header[58..60].copy_from_slice(b"\x60\n");
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        out.push(b'\n');
    }
}

#[test]
fn parses_gnu_archive_with_symtabs_long_names_and_odd_padding() {
    let baseline = build_minimal_elf(&[0x90, 0xc3]);
    let fma_elf = build_minimal_elf(&[0xc4, 0xe2, 0x71, 0xa8, 0xc2, 0xc3]);

    let mut ar = Vec::from(*ARCHIVE_MAGIC);
    push_ar_member(&mut ar, "/", &[0, 0, 0, 0]);
    push_ar_member(&mut ar, "/SYM64/", &[0; 8]);
    push_ar_member(
        &mut ar,
        "//",
        b"very_long_fma_kernel_member.o/\nanother_long_name.o/\n",
    );
    push_ar_member(&mut ar, "note.txt/", b"odd");
    push_ar_member(&mut ar, "base.o/", &baseline);
    push_ar_member(&mut ar, "/0", &fma_elf);

    assert!(is_archive(&ar));
    let parsed = Archive::parse(&ar).expect("parse GNU archive");
    assert_eq!(parsed.members.len(), 3);
    assert_eq!(parsed.members[0].name, "note.txt");
    assert_eq!(parsed.members[1].name, "base.o");
    assert_eq!(parsed.members[2].name, "very_long_fma_kernel_member.o");

    let mut forbidden = BTreeSet::new();
    forbidden.insert(IsaFeature::Fma3);
    let opts = AuditOptions {
        forbidden,
        ..AuditOptions::default()
    };
    let report = audit_input("libvendor.a", &ar, &opts).expect("audit GNU archive");
    assert_eq!(
        report.members_scanned,
        vec![
            "base.o".to_string(),
            "very_long_fma_kernel_member.o".to_string()
        ]
    );
    assert!(!report.passed());
    assert_eq!(report.total_violations, 1);
    assert_eq!(
        report.findings[0].member.as_deref(),
        Some("very_long_fma_kernel_member.o")
    );
    assert_eq!(report.findings[0].feature, IsaFeature::Fma3);
}

#[test]
fn parses_bsd_archive_with_symdef_and_extended_names() {
    let avx_elf = build_minimal_elf(&[0xc5, 0xf4, 0x58, 0xc2, 0xc3]);

    let mut ar = Vec::from(*ARCHIVE_MAGIC);
    push_ar_member(&mut ar, "__.SYMDEF", &[0; 8]);

    let mut symdef_sorted = b"__.SYMDEF SORTED\0\0\0\0".to_vec();
    symdef_sorted.extend_from_slice(&[0; 8]);
    push_ar_member(&mut ar, "#1/20", &symdef_sorted);

    let mut bsd_long = b"bsd_extended_avx_member.o\0\0\0".to_vec();
    let name_len = bsd_long.len();
    bsd_long.extend_from_slice(&avx_elf);
    push_ar_member(&mut ar, &format!("#1/{name_len}"), &bsd_long);

    let parsed = Archive::parse(&ar).expect("parse BSD archive");
    assert_eq!(parsed.members.len(), 1);
    assert_eq!(parsed.members[0].name, "bsd_extended_avx_member.o");

    let report = audit_input("libbsd.a", &ar, &AuditOptions::default()).expect("audit BSD archive");
    assert_eq!(report.min_profile, "avx-no-fma");
    assert_eq!(
        report.members_scanned,
        vec!["bsd_extended_avx_member.o".to_string()]
    );
}

#[test]
fn rejects_malformed_and_thin_archives_cleanly() {
    assert_eq!(Archive::parse(b"short"), Err(ArchiveError::TooSmall));
    assert_eq!(
        Archive::parse(b"NOTARCH\n"),
        Err(ArchiveError::InvalidMagic)
    );
    assert_eq!(
        Archive::parse(THIN_ARCHIVE_MAGIC),
        Err(ArchiveError::ThinArchiveUnsupported)
    );

    let empty = Archive::parse(ARCHIVE_MAGIC).expect("empty archive parses");
    assert!(empty.members.is_empty());

    let mut bad_end = Vec::from(*ARCHIVE_MAGIC);
    let mut hdr = [b' '; 60];
    hdr[0..5].copy_from_slice(b"a.o/ ");
    hdr[48..49].copy_from_slice(b"0");
    hdr[58..60].copy_from_slice(b"XX");
    bad_end.extend_from_slice(&hdr);
    assert!(matches!(
        Archive::parse(&bad_end),
        Err(ArchiveError::InvalidHeaderEnd { offset: 8 })
    ));

    let mut signed_size = Vec::from(*ARCHIVE_MAGIC);
    let mut hdr2 = [b' '; 60];
    hdr2[0..4].copy_from_slice(b"a.o/");
    hdr2[48..51].copy_from_slice(b"+10");
    hdr2[58..60].copy_from_slice(b"\x60\n");
    signed_size.extend_from_slice(&hdr2);
    assert!(matches!(
        Archive::parse(&signed_size),
        Err(ArchiveError::InvalidMemberSize { offset: 8 })
    ));

    let mut missing_strtab = Vec::from(*ARCHIVE_MAGIC);
    push_ar_member(&mut missing_strtab, "/0", b"data");
    assert!(matches!(
        Archive::parse(&missing_strtab),
        Err(ArchiveError::InvalidExtendedName { offset: 8 })
    ));

    let mut bsd_oob = Vec::from(*ARCHIVE_MAGIC);
    push_ar_member(&mut bsd_oob, "#1/32", b"tiny");
    assert!(matches!(
        Archive::parse(&bsd_oob),
        Err(ArchiveError::BsdNameLengthExceedsSize {
            offset: 8,
            name_len: 32,
            member_size: 4,
        })
    ));

    let mut corrupt_elf_member = Vec::from(*ARCHIVE_MAGIC);
    push_ar_member(&mut corrupt_elf_member, "broken.o/", b"\x7fELFtruncated");
    let err = audit_input("bad.a", &corrupt_elf_member, &AuditOptions::default())
        .expect_err("corrupt ELF member must fail");
    assert!(err.contains("broken.o"));
}

#[test]
fn byte_by_byte_truncation_never_panics() {
    let elf1 = build_minimal_elf(&[0x90, 0xc3]);
    let elf2 = build_minimal_elf(&[0xc5, 0xf4, 0x58, 0xc2, 0xc3]);

    let mut ar = Vec::from(*ARCHIVE_MAGIC);
    push_ar_member(&mut ar, "//", b"long_archive_member_object_file.o/\n");
    push_ar_member(&mut ar, "short.o/", &elf1);
    push_ar_member(&mut ar, "/0", &elf2);

    for cut in 0..ar.len() {
        let res = Archive::parse(&ar[..cut]);
        if cut < ARCHIVE_MAGIC.len() {
            assert!(res.is_err());
        }
    }
    assert!(Archive::parse(&ar).is_ok());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn cli_scans_checks_and_diffs_real_gcc_ar_static_libraries() {
    use std::fs;
    use std::process::Command;

    let has_gpp = Command::new("g++").arg("--version").output().is_ok();
    let has_ar = Command::new("ar").arg("--version").output().is_ok();
    if !has_gpp || !has_ar {
        return;
    }

    let bin = env!("CARGO_BIN_EXE_isa-audit");
    let dir = std::env::temp_dir().join(format!("isa_audit_ar_live_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");

    let base_cpp = dir.join("base_unit.cpp");
    let fma_cpp = dir.join("very_long_fma_kernel_module.cpp");
    let base_o = dir.join("base_unit.o");
    let fma_o = dir.join("very_long_fma_kernel_module.o");
    let lib_base = dir.join("libbase.a");
    let lib_fma = dir.join("libwithfma.a");

    fs::write(
        &base_cpp,
        "extern \"C\" int add_vals(int a, int b) { return a + b; }\n",
    )
    .expect("write base_cpp");
    fs::write(
        &fma_cpp,
        "#include <immintrin.h>\nextern \"C\" __m256 fma_kernel(__m256 a, __m256 b, __m256 c) { return _mm256_fmadd_ps(a, b, c); }\n",
    )
    .expect("write fma_cpp");

    let s1 = Command::new("g++")
        .args([
            "-O2",
            "-c",
            base_cpp.to_str().unwrap(),
            "-o",
            base_o.to_str().unwrap(),
        ])
        .status()
        .expect("compile base_o");
    assert!(s1.success());

    let s2 = Command::new("g++")
        .args([
            "-O2",
            "-mfma",
            "-c",
            fma_cpp.to_str().unwrap(),
            "-o",
            fma_o.to_str().unwrap(),
        ])
        .status()
        .expect("compile fma_o");
    assert!(s2.success());

    let a1 = Command::new("ar")
        .args(["rcs", lib_base.to_str().unwrap(), base_o.to_str().unwrap()])
        .status()
        .expect("ar libbase.a");
    assert!(a1.success());

    let a2 = Command::new("ar")
        .args([
            "rcs",
            lib_fma.to_str().unwrap(),
            base_o.to_str().unwrap(),
            fma_o.to_str().unwrap(),
        ])
        .status()
        .expect("ar libwithfma.a");
    assert!(a2.success());

    let check_fail = Command::new(bin)
        .args([
            "check",
            lib_fma.to_str().unwrap(),
            "--target",
            "avx-no-fma",
            "--format",
            "text",
        ])
        .output()
        .expect("run check text");
    assert_eq!(check_fail.status.code(), Some(1));
    let txt = String::from_utf8_lossy(&check_fail.stdout);
    assert!(txt.contains("members       : 2"));
    assert!(txt.contains("very_long_fma_kernel_module.o:fma_kernel+0x"));

    let check_json = Command::new(bin)
        .args([
            "check",
            lib_fma.to_str().unwrap(),
            "--target",
            "avx-no-fma",
            "--format",
            "json",
        ])
        .output()
        .expect("run check json");
    assert_eq!(check_json.status.code(), Some(1));
    let jtxt = String::from_utf8_lossy(&check_json.stdout);
    assert!(jtxt.contains("\"member\": \"very_long_fma_kernel_module.o\""));
    assert!(
        jtxt.contains("\"members_scanned\": [\"base_unit.o\", \"very_long_fma_kernel_module.o\"]")
    );

    let check_sarif = Command::new(bin)
        .args([
            "check",
            lib_fma.to_str().unwrap(),
            "--target",
            "avx-no-fma",
            "--format",
            "sarif",
        ])
        .output()
        .expect("run check sarif");
    assert_eq!(check_sarif.status.code(), Some(1));
    let stxt = String::from_utf8_lossy(&check_sarif.stdout);
    assert!(stxt.contains("very_long_fma_kernel_module.o:.text"));

    let check_pass = Command::new(bin)
        .args(["check", lib_fma.to_str().unwrap(), "--target", "x86-64-v3"])
        .output()
        .expect("run check pass");
    assert_eq!(check_pass.status.code(), Some(0));

    let diff_reg = Command::new(bin)
        .args([
            "diff",
            lib_base.to_str().unwrap(),
            lib_fma.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on-regression",
        ])
        .output()
        .expect("run diff on archives");
    assert_eq!(diff_reg.status.code(), Some(1));
    let dtxt = String::from_utf8_lossy(&diff_reg.stdout);
    assert!(dtxt.contains("\"regressed\": true"));
    assert!(dtxt.contains("\"fma3\""));

    let _ = fs::remove_dir_all(&dir);
}
