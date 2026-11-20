use std::fs;
use std::process::Command;

/// Minimal valid x86-64 ELF64 binary with the supplied `.text` instruction bytes.
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
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..32].copy_from_slice(&text_vaddr.to_le_bytes());
    buf[40..48].copy_from_slice(&shoff.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[58..60].copy_from_slice(&64u16.to_le_bytes());
    buf[60..62].copy_from_slice(&3u16.to_le_bytes());
    buf[62..64].copy_from_slice(&2u16.to_le_bytes());
    buf
}

#[test]
fn cli_exits_0_on_pass_1_on_policy_violation_and_2_on_error() {
    let bin = env!("CARGO_BIN_EXE_isa-audit");
    let fixture = std::env::temp_dir().join(format!("isa_audit_cli_{}.elf", std::process::id()));
    fs::write(&fixture, build_minimal_elf(&[0xc5, 0xf4, 0x58, 0xc2, 0xc3]))
        .expect("write ELF fixture");

    // 1. AVX fixture passes avx-no-fma (exit code 0)
    let pass = Command::new(bin)
        .args([
            "check",
            fixture.to_str().unwrap(),
            "--target",
            "avx-no-fma",
            "--format",
            "json",
        ])
        .output()
        .expect("run isa-audit pass check");
    assert_eq!(
        pass.status.code(),
        Some(0),
        "expected pass; stdout:\n{}",
        String::from_utf8_lossy(&pass.stdout)
    );
    let stdout = String::from_utf8_lossy(&pass.stdout);
    assert!(stdout.contains("\"passed\": true"));
    assert!(stdout.contains("\"min_profile\": \"avx-no-fma\""));

    // 2. AVX fixture fails x86-64-v2 policy (exit code 1) and emits SARIF 2.1.0
    let fail = Command::new(bin)
        .args([
            "check",
            fixture.to_str().unwrap(),
            "--target",
            "x86-64-v2",
            "--format",
            "sarif",
        ])
        .output()
        .expect("run isa-audit fail check");
    assert_eq!(fail.status.code(), Some(1));
    let sarif = String::from_utf8_lossy(&fail.stdout);
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("isa-audit/forbidden-avx"));

    // 3. Nonexistent path exits with code 2
    let err = Command::new(bin)
        .args(["scan", "/nonexistent/path/to/elf"])
        .output()
        .expect("run isa-audit error case");
    assert_eq!(err.status.code(), Some(2));

    let _ = fs::remove_file(&fixture);
}

#[test]
fn cli_diff_detects_isa_lowering_and_regressions() {
    let bin = env!("CARGO_BIN_EXE_isa-audit");
    let pid = std::process::id();
    let avx_only = std::env::temp_dir().join(format!("isa_audit_diff_avx_{pid}.elf"));
    let avx_fma = std::env::temp_dir().join(format!("isa_audit_diff_fma_{pid}.elf"));

    // vaddps xmm0, xmm1, xmm2; ret
    fs::write(
        &avx_only,
        build_minimal_elf(&[0xc5, 0xf4, 0x58, 0xc2, 0xc3]),
    )
    .expect("write avx fixture");
    // vfmadd213ps xmm0, xmm1, xmm2; vaddps xmm0, xmm1, xmm2; ret
    fs::write(
        &avx_fma,
        build_minimal_elf(&[0xc4, 0xe2, 0x71, 0xa8, 0xc2, 0xc5, 0xf4, 0x58, 0xc2, 0xc3]),
    )
    .expect("write fma fixture");

    // 1. Removing FMA3 (lowering pass): passes --fail-on-regression
    let lowered = Command::new(bin)
        .args([
            "diff",
            avx_fma.to_str().unwrap(),
            avx_only.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on-regression",
        ])
        .output()
        .expect("run isa-audit diff lowering");
    assert_eq!(lowered.status.code(), Some(0));
    let out = String::from_utf8_lossy(&lowered.stdout);
    assert!(out.contains("\"regressed\": false"));
    assert!(out.contains("\"removed_features\": [\"fma3\"]"));
    assert!(out.contains("\"before_min_profile\": \"x86-64-v3\""));
    assert!(out.contains("\"after_min_profile\": \"avx-no-fma\""));

    // 2. Adding FMA3 (regression): fails --fail-on-regression with exit code 1
    let regressed = Command::new(bin)
        .args([
            "diff",
            avx_only.to_str().unwrap(),
            avx_fma.to_str().unwrap(),
            "--format",
            "json",
            "--fail-on-regression",
        ])
        .output()
        .expect("run isa-audit diff regression");
    assert_eq!(regressed.status.code(), Some(1));
    let reg_out = String::from_utf8_lossy(&regressed.stdout);
    assert!(reg_out.contains("\"regressed\": true"));
    assert!(reg_out.contains("\"added_features\": [\"fma3\"]"));

    // 3. Text diff format and unsupported sarif format
    let text = Command::new(bin)
        .args([
            "diff",
            avx_only.to_str().unwrap(),
            avx_fma.to_str().unwrap(),
        ])
        .output()
        .expect("run isa-audit diff text");
    assert_eq!(text.status.code(), Some(0));
    let text_out = String::from_utf8_lossy(&text.stdout);
    assert!(text_out.contains("avx-no-fma -> x86-64-v3"));
    assert!(text_out.contains("ADDED"));

    let bad_fmt = Command::new(bin)
        .args([
            "diff",
            avx_only.to_str().unwrap(),
            avx_fma.to_str().unwrap(),
            "--format",
            "sarif",
        ])
        .output()
        .expect("run isa-audit diff bad format");
    assert_eq!(bad_fmt.status.code(), Some(2));

    let _ = fs::remove_file(&avx_only);
    let _ = fs::remove_file(&avx_fma);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn cli_self_scan_verifies_linux_x86_64_binary_is_baseline() {
    let bin = env!("CARGO_BIN_EXE_isa-audit");
    let out = Command::new(bin)
        .args(["check", bin, "--target", "x86-64-v1", "--format", "json"])
        .output()
        .expect("run self scan");
    assert_eq!(
        out.status.code(),
        Some(0),
        "self binary must comply with x86-64-v1; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
