use std::process::Command;

#[test]
fn cli_exits_0_on_pass_1_on_policy_violation_and_2_on_error() {
    let bin = env!("CARGO_BIN_EXE_isa-audit");

    // 1. Self-scan must pass x86-64-v1 (exit code 0)
    let out = Command::new(bin)
        .args(["check", bin, "--target", "x86-64-v1", "--format", "json"])
        .output()
        .expect("run isa-audit check");
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected self binary to comply with x86-64-v1; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"passed\": true"));
    assert!(stdout.contains("\"min_profile\": \"x86-64-v1\""));

    // 2. Forbidding `baseline` on any non-empty ELF must fail with exit code 1
    let fail = Command::new(bin)
        .args(["check", bin, "--forbid", "baseline", "--format", "sarif"])
        .output()
        .expect("run isa-audit failing check");
    assert_eq!(fail.status.code(), Some(1));
    let sarif = String::from_utf8_lossy(&fail.stdout);
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("isa-audit/forbidden-baseline"));

    // 3. Nonexistent path must exit with code 2
    let err = Command::new(bin)
        .args(["scan", "/nonexistent/path/to/elf"])
        .output()
        .expect("run isa-audit error case");
    assert_eq!(err.status.code(), Some(2));
}
