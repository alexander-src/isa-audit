use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use isa_audit::analyzer::{audit_binary, AuditOptions};
use isa_audit::elf::ElfBinary;
use isa_audit::isa::{IsaFeature, TargetProfile};
use isa_audit::report::{render_json, render_sarif};

fn has_gxx() -> bool {
    Command::new("g++")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn compile_kernel(tag: &str, cpp_src: &str, flags: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("isa_audit_gt_{}_{}", std::process::id(), tag));
    let _ = fs::create_dir_all(&dir);
    let src_path = dir.join("kernel.cpp");
    let obj_path = dir.join("kernel.o");
    fs::write(&src_path, cpp_src).expect("write test C++ source");

    let output = Command::new("g++")
        .arg("-c")
        .arg("-O2")
        .args(flags)
        .arg(&src_path)
        .arg("-o")
        .arg(&obj_path)
        .output()
        .expect("invoke g++");

    assert!(
        output.status.success(),
        "g++ failed for {tag}:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    obj_path
}

#[test]
fn gcc_ground_truth_verifies_avx_fma3_avx2_bmi_aes_and_popcnt() {
    if !has_gxx() {
        eprintln!("skipping gcc_ground_truth: g++ not available on PATH");
        return;
    }

    // 1. Baseline x86-64 (no AVX, no FMA)
    let baseline_src = r#"
extern "C" void baseline_add(const float* __restrict a, const float* __restrict b, float* __restrict c, int n) {
    for (int i = 0; i < n; ++i) c[i] = a[i] * b[i] + 1.0f;
}
"#;
    let obj = compile_kernel(
        "baseline",
        baseline_src,
        &["-mno-sse3", "-mno-avx", "-mno-fma", "-mno-bmi", "-mno-bmi2"],
    );
    let data = fs::read(&obj).unwrap();
    let elf = ElfBinary::parse(&data).unwrap();
    let rep = audit_binary(
        "baseline.o",
        &elf,
        &AuditOptions {
            forbidden: TargetProfile::X86_64V1.forbidden_features(),
            ..AuditOptions::default()
        },
    );
    assert!(
        rep.passed(),
        "baseline binary should pass x86-64-v1, got findings: {:?}",
        rep.findings
    );

    // 2. AVX without FMA (--to-avx / Sandy Bridge verification target!)
    let avx_src = r#"
#include <immintrin.h>
extern "C" void avx_mul_add(const float* a, const float* b, const float* c, float* out) {
    __m256 va = _mm256_loadu_ps(a);
    __m256 vb = _mm256_loadu_ps(b);
    __m256 vc = _mm256_loadu_ps(c);
    __m256 prod = _mm256_mul_ps(va, vb);
    _mm256_storeu_ps(out, _mm256_add_ps(prod, vc));
}
"#;
    let obj = compile_kernel("avx_nofma", avx_src, &["-mavx", "-mno-avx2", "-mno-fma"]);
    let data = fs::read(&obj).unwrap();
    let elf = ElfBinary::parse(&data).unwrap();
    let rep = audit_binary(
        "avx_nofma.o",
        &elf,
        &AuditOptions {
            forbidden: TargetProfile::AvxNoFma.forbidden_features(),
            ..AuditOptions::default()
        },
    );
    assert!(
        rep.feature_counts
            .get(&IsaFeature::Avx)
            .copied()
            .unwrap_or(0)
            > 0,
        "expected AVX instructions in avx_nofma.o"
    );
    assert_eq!(
        rep.feature_counts
            .get(&IsaFeature::Fma3)
            .copied()
            .unwrap_or(0),
        0,
        "avx_nofma.o must contain zero FMA3 instructions"
    );
    assert!(
        rep.passed(),
        "avx_nofma.o must pass avx-no-fma policy, got findings: {:?}",
        rep.findings
    );

    // 3. FMA3 kernel MUST fail avx-no-fma policy and attribute to `fma3_kernel`
    let fma_src = r#"
#include <immintrin.h>
extern "C" void fma3_kernel(const float* a, const float* b, const float* c, float* out) {
    __m256 va = _mm256_loadu_ps(a);
    __m256 vb = _mm256_loadu_ps(b);
    __m256 vc = _mm256_loadu_ps(c);
    _mm256_storeu_ps(out, _mm256_fmadd_ps(va, vb, vc));
}
"#;
    let obj = compile_kernel("fma3", fma_src, &["-mavx", "-mfma", "-mno-avx2"]);
    let data = fs::read(&obj).unwrap();
    let elf = ElfBinary::parse(&data).unwrap();
    let rep = audit_binary(
        "fma3.o",
        &elf,
        &AuditOptions {
            forbidden: TargetProfile::AvxNoFma.forbidden_features(),
            ..AuditOptions::default()
        },
    );
    assert!(!rep.passed(), "fma3.o must FAIL avx-no-fma policy");
    assert!(
        rep.findings
            .iter()
            .any(|f| f.feature == IsaFeature::Fma3 && f.symbol.as_deref() == Some("fma3_kernel")),
        "expected FMA3 finding attributed to fma3_kernel, got: {:?}",
        rep.findings
    );

    // Verify JSON & SARIF rendering include finding metadata cleanly
    let json = render_json(&rep);
    assert!(json.contains("\"fma3\"") && json.contains("\"fma3_kernel\""));
    let sarif = render_sarif(&rep);
    assert!(sarif.contains("\"version\": \"2.1.0\"") && sarif.contains("isa-audit/forbidden-fma3"));

    // 4. AVX2 integer kernel
    let avx2_src = r#"
#include <immintrin.h>
extern "C" void avx2_int_kernel(const int* a, const int* b, int* out) {
    __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a));
    __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), _mm256_add_epi32(va, vb));
}
"#;
    let obj = compile_kernel("avx2", avx2_src, &["-mavx2", "-mno-fma"]);
    let data = fs::read(&obj).unwrap();
    let elf = ElfBinary::parse(&data).unwrap();
    let mut forbid = BTreeSet::new();
    forbid.insert(IsaFeature::Avx2);
    let rep = audit_binary(
        "avx2.o",
        &elf,
        &AuditOptions {
            forbidden: forbid,
            ..AuditOptions::default()
        },
    );
    assert!(!rep.passed(), "avx2.o must trigger forbidden AVX2");
    assert!(rep
        .findings
        .iter()
        .any(|f| f.feature == IsaFeature::Avx2 && f.symbol.as_deref() == Some("avx2_int_kernel")));

    // 5. BMI1 + BMI2
    let bmi_src = r#"
#include <x86intrin.h>
#include <cstdint>
extern "C" uint64_t bmi_kernel(uint64_t x, uint64_t y) {
    uint64_t a = _andn_u64(x, y);
    uint64_t b = _pext_u64(a, y);
    return b;
}
"#;
    let obj = compile_kernel("bmi", bmi_src, &["-mbmi", "-mbmi2", "-mno-avx"]);
    let data = fs::read(&obj).unwrap();
    let elf = ElfBinary::parse(&data).unwrap();
    let rep = audit_binary("bmi.o", &elf, &AuditOptions::default());
    assert!(
        rep.feature_counts
            .get(&IsaFeature::Bmi1)
            .copied()
            .unwrap_or(0)
            > 0
    );
    assert!(
        rep.feature_counts
            .get(&IsaFeature::Bmi2)
            .copied()
            .unwrap_or(0)
            > 0
    );

    // 6. AES-NI + POPCNT
    let crypto_src = r#"
#include <wmmintrin.h>
#include <nmmintrin.h>
#include <cstdint>
extern "C" uint64_t aes_popcnt_kernel(const __m128i* a, const __m128i* k, __m128i* out, uint64_t v) {
    *out = _mm_aesenc_si128(*a, *k);
    return static_cast<uint64_t>(_mm_popcnt_u64(v));
}
"#;
    let obj = compile_kernel("aes_popcnt", crypto_src, &["-maes", "-mpopcnt", "-mno-avx"]);
    let data = fs::read(&obj).unwrap();
    let elf = ElfBinary::parse(&data).unwrap();
    let rep = audit_binary("aes_popcnt.o", &elf, &AuditOptions::default());
    assert!(
        rep.feature_counts
            .get(&IsaFeature::Aes)
            .copied()
            .unwrap_or(0)
            > 0
    );
    assert!(
        rep.feature_counts
            .get(&IsaFeature::Popcnt)
            .copied()
            .unwrap_or(0)
            > 0
    );
}
