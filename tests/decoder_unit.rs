use isa_audit::decoder::decode_one;
use isa_audit::isa::IsaFeature;

#[test]
fn decodes_baseline_x86_64_instructions_with_exact_lengths() {
    // push rbp (55)
    let d = decode_one(&[0x55]);
    assert!(!d.invalid);
    assert_eq!(d.len, 1);
    assert_eq!(d.feature, IsaFeature::Baseline);

    // mov rbp, rsp (48 89 e5)
    let d = decode_one(&[0x48, 0x89, 0xe5]);
    assert!(!d.invalid);
    assert_eq!(d.len, 3);
    assert_eq!(d.feature, IsaFeature::Baseline);

    // movabs rax, 0x1122334455667788 (48 b8 + 8-byte imm64 = 10 bytes)
    let d = decode_one(&[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    assert!(!d.invalid);
    assert_eq!(d.len, 10);
    assert_eq!(d.feature, IsaFeature::Baseline);

    // mov eax, 0x12345678 (b8 + 4-byte imm32 = 5 bytes)
    let d = decode_one(&[0xb8, 0x78, 0x56, 0x34, 0x12]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);

    // mov ax, 0x1234 (66 b8 + 2-byte imm16 = 4 bytes)
    let d = decode_one(&[0x66, 0xb8, 0x34, 0x12]);
    assert!(!d.invalid);
    assert_eq!(d.len, 4);

    // endbr64 (f3 0f 1e fa = 4 bytes)
    let d = decode_one(&[0xf3, 0x0f, 0x1e, 0xfa]);
    assert!(!d.invalid);
    assert_eq!(d.len, 4);
    assert_eq!(d.feature, IsaFeature::Baseline);

    // test eax, 0xdeadbeef (f7 c0 ef be ad de = 6 bytes, Group 3 reg=0 has imm32)
    let d = decode_one(&[0xf7, 0xc0, 0xef, 0xbe, 0xad, 0xde]);
    assert!(!d.invalid);
    assert_eq!(d.len, 6);

    // not eax (f7 d0 = 2 bytes, Group 3 reg=2 has NO imm)
    let d = decode_one(&[0xf7, 0xd0, 0x90, 0x90]);
    assert!(!d.invalid);
    assert_eq!(d.len, 2);

    // lea rax, [rip + 0x12345678] (48 8d 05 78 56 34 12 = 7 bytes)
    let d = decode_one(&[0x48, 0x8d, 0x05, 0x78, 0x56, 0x34, 0x12]);
    assert!(!d.invalid);
    assert_eq!(d.len, 7);

    // mov eax, [rsp + rcx*4 + 0x10] (8b 44 8c 10 = 4 bytes: op + modrm + sib + disp8)
    let d = decode_one(&[0x8b, 0x44, 0x8c, 0x10]);
    assert!(!d.invalid);
    assert_eq!(d.len, 4);
}

#[test]
fn decodes_avx_fma3_avx2_bmi_and_vzeroupper() {
    // vzeroupper (c5 f8 77 = 3 bytes, NO ModRM!) followed by ret (c3)
    let stream = [0xc5, 0xf8, 0x77, 0xc3];
    let d1 = decode_one(&stream);
    assert!(!d1.invalid);
    assert_eq!(d1.len, 3);
    assert_eq!(d1.feature, IsaFeature::Avx);
    assert_eq!(d1.mnemonic, "vzeroupper");
    let d2 = decode_one(&stream[d1.len as usize..]);
    assert!(!d2.invalid);
    assert_eq!(d2.len, 1);
    assert_eq!(d2.feature, IsaFeature::Baseline);

    // vaddps ymm0, ymm1, ymm2 (c5 f4 58 c2 = 4 bytes) -> AVX
    let d = decode_one(&[0xc5, 0xf4, 0x58, 0xc2]);
    assert!(!d.invalid);
    assert_eq!(d.len, 4);
    assert_eq!(d.feature, IsaFeature::Avx);

    // vfmadd213ps ymm0, ymm1, ymm2 (c4 e2 75 a8 c2 = 5 bytes) -> FMA3
    let d = decode_one(&[0xc4, 0xe2, 0x75, 0xa8, 0xc2]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);
    assert_eq!(d.feature, IsaFeature::Fma3);
    assert_eq!(d.mnemonic, "vfmadd");

    // vfnmadd231sd xmm0, xmm1, [rip+0x10] (c4 e2 f1 bd 05 10 00 00 00 = 9 bytes) -> FMA3
    let d = decode_one(&[0xc4, 0xe2, 0xf1, 0xbd, 0x05, 0x10, 0x00, 0x00, 0x00]);
    assert!(!d.invalid);
    assert_eq!(d.len, 9);
    assert_eq!(d.feature, IsaFeature::Fma3);
    assert_eq!(d.mnemonic, "vfnmadd");

    // vpaddd ymm0, ymm1, ymm2 (c5 f5 fe c2 = 4 bytes, L=1 pp=1 0F FE) -> AVX2
    let d = decode_one(&[0xc5, 0xf5, 0xfe, 0xc2]);
    assert!(!d.invalid);
    assert_eq!(d.len, 4);
    assert_eq!(d.feature, IsaFeature::Avx2);

    // vpermq ymm0, ymm1, 0x1b (c4 e3 fd 00 c1 1b = 6 bytes, 0F3A imm8) -> AVX2
    let d = decode_one(&[0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b]);
    assert!(!d.invalid);
    assert_eq!(d.len, 6);
    assert_eq!(d.feature, IsaFeature::Avx2);
    assert_eq!(d.mnemonic, "vpermq");

    // andn eax, ecx, edx (c4 e2 70 f2 c2 = 5 bytes) -> BMI1
    let d = decode_one(&[0xc4, 0xe2, 0x70, 0xf2, 0xc2]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);
    assert_eq!(d.feature, IsaFeature::Bmi1);

    // pext rax, rcx, rdx (c4 e2 f2 f5 c2 = 5 bytes) -> BMI2
    let d = decode_one(&[0xc4, 0xe2, 0xf2, 0xf5, 0xc2]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);
    assert_eq!(d.feature, IsaFeature::Bmi2);

    // rorx rax, rcx, 7 (c4 e3 fb f0 c1 07 = 6 bytes) -> BMI2
    let d = decode_one(&[0xc4, 0xe3, 0xfb, 0xf0, 0xc1, 0x07]);
    assert!(!d.invalid);
    assert_eq!(d.len, 6);
    assert_eq!(d.feature, IsaFeature::Bmi2);
}

#[test]
fn decodes_sse_lineage_and_avx512() {
    // popcnt eax, ecx (f3 0f b8 c1 = 4 bytes)
    let d = decode_one(&[0xf3, 0x0f, 0xb8, 0xc1]);
    assert!(!d.invalid);
    assert_eq!(d.len, 4);
    assert_eq!(d.feature, IsaFeature::Popcnt);

    // tzcnt eax, eax (f3 0f bc c0 = 4 bytes) executes as `rep bsf` on pre-BMI1 CPUs (no SIGILL)
    let d = decode_one(&[0xf3, 0x0f, 0xbc, 0xc0]);
    assert!(!d.invalid);
    assert_eq!(d.len, 4);
    assert_eq!(d.feature, IsaFeature::Baseline);
    assert_eq!(d.mnemonic, "tzcnt/rep-bsf");

    // pshufb xmm0, xmm1 (66 0f 38 00 c1 = 5 bytes) -> SSSE3
    let d = decode_one(&[0x66, 0x0f, 0x38, 0x00, 0xc1]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);
    assert_eq!(d.feature, IsaFeature::Ssse3);

    // pmulld xmm0, xmm1 (66 0f 38 40 c1 = 5 bytes) -> SSE4.1
    let d = decode_one(&[0x66, 0x0f, 0x38, 0x40, 0xc1]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);
    assert_eq!(d.feature, IsaFeature::Sse41);

    // crc32 eax, ecx (f2 0f 38 f1 c1 = 5 bytes) -> SSE4.2
    let d = decode_one(&[0xf2, 0x0f, 0x38, 0xf1, 0xc1]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);
    assert_eq!(d.feature, IsaFeature::Sse42);

    // aesenc xmm0, xmm1 (66 0f 38 dc c1 = 5 bytes) -> AES-NI
    let d = decode_one(&[0x66, 0x0f, 0x38, 0xdc, 0xc1]);
    assert!(!d.invalid);
    assert_eq!(d.len, 5);
    assert_eq!(d.feature, IsaFeature::Aes);

    // vaddps zmm0, zmm1, zmm2 (62 f1 74 48 58 c2 = 6 bytes, EVEX L'L=10) -> AVX-512F
    let d = decode_one(&[0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2]);
    assert!(!d.invalid);
    assert_eq!(d.len, 6);
    assert_eq!(d.feature, IsaFeature::Avx512F);

    // vaddps xmm0, xmm1, xmm2 via EVEX (62 f1 74 08 58 c2 = 6 bytes, EVEX L'L=00) -> AVX-512VL
    let d = decode_one(&[0x62, 0xf1, 0x74, 0x08, 0x58, 0xc2]);
    assert!(!d.invalid);
    assert_eq!(d.len, 6);
    assert_eq!(d.feature, IsaFeature::Avx512Vl);
}

#[test]
fn rejects_malformed_vex_evex_and_truncated_sequences_without_panicking() {
    // Empty input
    assert_eq!(decode_one(&[]).len, 0);

    // Invalid VEX3 map = 0 (c4 e0 75 a8 c2) -> must NOT falsely report FMA3/AVX
    let d = decode_one(&[0xc4, 0xe0, 0x75, 0xa8, 0xc2]);
    assert!(d.invalid);
    assert_eq!(d.len, 1);

    // Invalid EVEX with p1 bit2 == 0 (62 f1 70 48 58 c2) -> must reject
    let d = decode_one(&[0x62, 0xf1, 0x70, 0x48, 0x58, 0xc2]);
    assert!(d.invalid);
    assert_eq!(d.len, 1);

    // Prefix 0x66 followed by 0xC4 is illegal in x86-64 (cannot combine legacy 66 with VEX)
    let d = decode_one(&[0x66, 0xc4, 0xe2, 0x75, 0xa8, 0xc2]);
    assert!(d.invalid);
    assert_eq!(d.len, 1);

    // Truncated multi-byte instructions never panic or exceed slice bounds
    for len in 1..=5 {
        let sample = &[0xc4, 0xe2, 0x75, 0xa8, 0x05][..len];
        let d = decode_one(sample);
        assert!(d.len as usize <= sample.len());
    }
}
