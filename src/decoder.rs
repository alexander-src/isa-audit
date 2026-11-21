use crate::isa::IsaFeature;

const MAX_INSN_LEN: usize = 15;

/// Result of decoding a single x86-64 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedInsn {
    /// Total encoded instruction length in bytes (`1..=15`).
    pub len: u8,
    /// Required ISA extension (or `IsaFeature::Baseline`).
    pub feature: IsaFeature,
    /// Human-readable instruction family/mnemonic classification.
    pub mnemonic: &'static str,
    /// True if decoding fell back to a 1-byte recovery step due to invalid/truncated encoding.
    pub invalid: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct LegacyPrefixes {
    has_66: bool,
    has_67: bool,
    has_f0: bool,
    has_f2: bool,
    has_f3: bool,
    last_rep: u8,
}

impl LegacyPrefixes {
    #[inline]
    fn has_simd_conflicting_prefix(self) -> bool {
        self.has_66 || self.has_f0 || self.has_f2 || self.has_f3
    }
}

#[inline]
fn invalid_step() -> DecodedInsn {
    DecodedInsn {
        len: 1,
        feature: IsaFeature::Baseline,
        mnemonic: "<invalid>",
        invalid: true,
    }
}

/// Computes the byte length consumed by ModRM + optional SIB + displacement in 64-bit mode.
/// Returns `None` if `bytes` does not have enough remaining bytes.
#[inline]
fn modrm_len(bytes: &[u8], pos: usize) -> Option<usize> {
    let modrm = *bytes.get(pos)?;
    let mod_bits = modrm >> 6;
    let rm = modrm & 0x07;

    let mut extra = 1usize; // ModRM byte itself
    match mod_bits {
        0 => {
            if rm == 4 {
                let sib = *bytes.get(pos + 1)?;
                extra += 1;
                if (sib & 0x07) == 5 {
                    extra += 4;
                }
            } else if rm == 5 {
                extra += 4; // RIP-relative disp32
            }
        }
        1 => {
            if rm == 4 {
                extra += 2; // SIB + disp8
            } else {
                extra += 1; // disp8
            }
        }
        2 => {
            if rm == 4 {
                extra += 5; // SIB + disp32
            } else {
                extra += 4; // disp32
            }
        }
        3 => {}
        _ => unreachable!(),
    }

    if pos + extra <= bytes.len() {
        Some(extra)
    } else {
        None
    }
}

#[inline]
fn finalize(
    len: usize,
    feature: IsaFeature,
    mnemonic: &'static str,
    total_avail: usize,
) -> DecodedInsn {
    if len == 0 || len > MAX_INSN_LEN || len > total_avail {
        invalid_step()
    } else {
        DecodedInsn {
            len: len as u8,
            feature,
            mnemonic,
            invalid: false,
        }
    }
}

/// Decodes a single 64-bit x86-64 instruction at the start of `bytes`.
///
/// Guarantees `decoded.len >= 1` and `decoded.len as usize <= bytes.len()` whenever
/// `!bytes.is_empty()`.
pub fn decode_one(bytes: &[u8]) -> DecodedInsn {
    if bytes.is_empty() {
        return DecodedInsn {
            len: 0,
            feature: IsaFeature::Baseline,
            mnemonic: "<eof>",
            invalid: true,
        };
    }

    let mut pos = 0usize;
    let mut pref = LegacyPrefixes::default();

    // 1. Consume legacy prefixes (up to MAX_INSN_LEN - 1 bytes).
    while pos < bytes.len() && pos < MAX_INSN_LEN - 1 {
        match bytes[pos] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => pos += 1,
            0x66 => {
                pref.has_66 = true;
                pos += 1;
            }
            0x67 => {
                pref.has_67 = true;
                pos += 1;
            }
            0xF0 => {
                pref.has_f0 = true;
                pos += 1;
            }
            0xF2 => {
                pref.has_f2 = true;
                pref.last_rep = 0xF2;
                pos += 1;
            }
            0xF3 => {
                pref.has_f3 = true;
                pref.last_rep = 0xF3;
                pos += 1;
            }
            _ => break,
        }
    }

    if pos >= bytes.len() {
        return invalid_step();
    }

    // 2. Check VEX2 (0xC5), VEX3 (0xC4), EVEX (0x62) in 64-bit mode.
    // VEX/EVEX cannot combine with legacy 66/F0/F2/F3 prefixes or REX.
    if !pref.has_simd_conflicting_prefix() {
        match bytes[pos] {
            0xC5 => return decode_vex2(bytes, pos),
            0xC4 => return decode_vex3(bytes, pos),
            0x62 => return decode_evex(bytes, pos),
            _ => {}
        }
    }

    // 3. Optional single REX prefix (0x40..=0x4F).
    let mut rex = 0u8;
    if (0x40..=0x4F).contains(&bytes[pos]) {
        rex = bytes[pos];
        pos += 1;
        if pos >= bytes.len() {
            return invalid_step();
        }
    }
    let rex_w = (rex & 0x08) != 0;

    // 4. Primary opcode dispatch.
    let op = bytes[pos];
    pos += 1;

    if op == 0x0F {
        return decode_0f(bytes, pos, pref, rex_w);
    }

    decode_1byte(bytes, pos, op, pref, rex_w)
}

fn decode_vex2(bytes: &[u8], pos: usize) -> DecodedInsn {
    // 0xC5 <b1> <opcode> [ModRM ...] [imm]
    if pos + 2 >= bytes.len() {
        return invalid_step();
    }
    let b1 = bytes[pos + 1];
    let opcode = bytes[pos + 2];
    let l_256 = ((b1 >> 2) & 1) != 0;
    let pp = b1 & 0x03;
    decode_vex_body(bytes, pos + 3, 1, false, l_256, pp, opcode)
}

fn decode_vex3(bytes: &[u8], pos: usize) -> DecodedInsn {
    // 0xC4 <b1> <b2> <opcode> [ModRM ...] [imm]
    if pos + 3 >= bytes.len() {
        return invalid_step();
    }
    let b1 = bytes[pos + 1];
    let b2 = bytes[pos + 2];
    let map = b1 & 0x1F;
    if !(1..=3).contains(&map) {
        return invalid_step();
    }
    let opcode = bytes[pos + 3];
    let w = (b2 & 0x80) != 0;
    let l_256 = ((b2 >> 2) & 1) != 0;
    let pp = b2 & 0x03;
    decode_vex_body(bytes, pos + 4, map, w, l_256, pp, opcode)
}

fn decode_vex_body(
    bytes: &[u8],
    pos: usize,
    map: u8,
    w: bool,
    l_256: bool,
    pp: u8,
    opcode: u8,
) -> DecodedInsn {
    // vzeroupper / vzeroall take NO ModRM and NO immediate.
    if map == 1 && opcode == 0x77 {
        let name = if l_256 { "vzeroall" } else { "vzeroupper" };
        return finalize(pos, IsaFeature::Avx, name, bytes.len());
    }

    let Some(m_len) = modrm_len(bytes, pos) else {
        return invalid_step();
    };
    let modrm = bytes[pos];
    let mod_bits = modrm >> 6;
    let reg_field = (modrm >> 3) & 0x07;

    let imm_len = match map {
        1 => match opcode {
            0x70 | 0x71 | 0x72 | 0x73 | 0xC2 | 0xC4 | 0xC5 | 0xC6 => 1,
            _ => 0,
        },
        2 => 0,
        3 => 1,
        _ => return invalid_step(),
    };

    let total_len = pos + m_len + imm_len;
    let (feature, mnemonic) = classify_vex(map, w, l_256, pp, opcode, mod_bits, reg_field);
    finalize(total_len, feature, mnemonic, bytes.len())
}

fn classify_vex(
    map: u8,
    _w: bool,
    l_256: bool,
    pp: u8,
    opcode: u8,
    mod_bits: u8,
    reg_field: u8,
) -> (IsaFeature, &'static str) {
    match map {
        // Map 1: VEX.0F
        1 => {
            if l_256 && pp == 1 {
                let is_avx2_int = matches!(
                    opcode,
                    0x60..=0x6E
                        | 0x70..=0x76
                        | 0xD1..=0xD5
                        | 0xD7..=0xDF
                        | 0xE0..=0xE5
                        | 0xE8..=0xEF
                        | 0xF1..=0xF6
                        | 0xF8..=0xFE
                );
                if is_avx2_int {
                    return (IsaFeature::Avx2, "avx2-int-256");
                }
            }
            let mnemonic = match opcode {
                0x10 | 0x11 => "vmovups/d",
                0x28 | 0x29 => "vmovaps/d",
                0x58 => "vaddp/s",
                0x59 => "vmulp/s",
                0x5C => "vsubp/s",
                0x5E => "vdivp/s",
                0x6F | 0x7F => "vmovdqa/u",
                _ => "avx-0f",
            };
            (IsaFeature::Avx, mnemonic)
        }
        // Map 2: VEX.0F38
        2 => {
            // FMA3: VEX.66.0F38 96..9F, A6..AF, B6..BF
            if pp == 1 && matches!(opcode, 0x96..=0x9F | 0xA6..=0xAF | 0xB6..=0xBF) {
                let name = match opcode {
                    0x96 | 0xA6 | 0xB6 => "vfmaddsub",
                    0x97 | 0xA7 | 0xB7 => "vfmsubadd",
                    0x98 | 0x99 | 0xA8 | 0xA9 | 0xB8 | 0xB9 => "vfmadd",
                    0x9A | 0x9B | 0xAA | 0xAB | 0xBA | 0xBB => "vfmsub",
                    0x9C | 0x9D | 0xAC | 0xAD | 0xBC | 0xBD => "vfnmadd",
                    _ => "vfnmsub",
                };
                return (IsaFeature::Fma3, name);
            }

            // F16C: VEX.66.0F38 13 (vcvtph2ps)
            if pp == 1 && opcode == 0x13 {
                return (IsaFeature::F16c, "vcvtph2ps");
            }

            // BMI1: VEX.NP.0F38 F2 (andn), F3 (blsr/blsmsk/blsi), F7 (bextr)
            if pp == 0 {
                match opcode {
                    0xF2 => return (IsaFeature::Bmi1, "andn"),
                    0xF3 => {
                        let name = match reg_field {
                            1 => "blsr",
                            2 => "blsmsk",
                            3 => "blsi",
                            _ => "bmi1-f3",
                        };
                        return (IsaFeature::Bmi1, name);
                    }
                    0xF7 => return (IsaFeature::Bmi1, "bextr"),
                    0xF5 => return (IsaFeature::Bmi2, "bzhi"),
                    _ => {}
                }
            }

            // BMI2: pdep/pext/mulx/shlx/sarx/shrx
            match (pp, opcode) {
                (3, 0xF5) => return (IsaFeature::Bmi2, "pdep"),
                (2, 0xF5) => return (IsaFeature::Bmi2, "pext"),
                (3, 0xF6) => return (IsaFeature::Bmi2, "mulx"),
                (1, 0xF7) => return (IsaFeature::Bmi2, "shlx"),
                (2, 0xF7) => return (IsaFeature::Bmi2, "sarx"),
                (3, 0xF7) => return (IsaFeature::Bmi2, "shrx"),
                _ => {}
            }

            // AES-NI (128-bit VEX) vs VAES (256-bit VEX)
            if pp == 1 {
                if opcode == 0xDB {
                    return (IsaFeature::Aes, "vaesimc");
                }
                if matches!(opcode, 0xDC..=0xDF) {
                    return if l_256 {
                        (IsaFeature::Vaes, "vaes-256")
                    } else {
                        (IsaFeature::Aes, "vaes-128")
                    };
                }
            }

            // AVX2-specific VEX.66.0F38 instructions (both 128-bit and 256-bit)
            if pp == 1 {
                match opcode {
                    0x16 => return (IsaFeature::Avx2, "vpermps"),
                    0x36 => return (IsaFeature::Avx2, "vpermd"),
                    0x18 | 0x19 if mod_bits == 3 => return (IsaFeature::Avx2, "vbroadcasts-reg"),
                    0x45..=0x47 => return (IsaFeature::Avx2, "vpshiftv"),
                    0x58 | 0x59 | 0x78 | 0x79 => return (IsaFeature::Avx2, "vpbroadcast"),
                    0x5A => return (IsaFeature::Avx2, "vbroadcasti128"),
                    0x8C | 0x8E => return (IsaFeature::Avx2, "vpmaskmov"),
                    0x90..=0x93 => return (IsaFeature::Avx2, "vgather"),
                    0x00..=0x0B | 0x1C..=0x25 | 0x28..=0x2B | 0x30..=0x35 | 0x37..=0x41
                        if l_256 =>
                    {
                        return (IsaFeature::Avx2, "avx2-0f38-256");
                    }
                    _ => {}
                }
            }

            (IsaFeature::Avx, "avx-0f38")
        }
        // Map 3: VEX.0F3A
        3 => {
            if pp == 3 && opcode == 0xF0 {
                return (IsaFeature::Bmi2, "rorx");
            }
            if pp == 1 && opcode == 0x1D {
                return (IsaFeature::F16c, "vcvtps2ph");
            }
            if pp == 1 && opcode == 0xDF {
                return (IsaFeature::Aes, "vaeskeygenassist");
            }
            if pp == 1 && opcode == 0x44 {
                return if l_256 {
                    (IsaFeature::Vpclmulqdq, "vpclmulqdq-256")
                } else {
                    (IsaFeature::Pclmulqdq, "vpclmulqdq-128")
                };
            }
            if pp == 1 {
                match opcode {
                    0x00 => return (IsaFeature::Avx2, "vpermq"),
                    0x01 => return (IsaFeature::Avx2, "vpermpd"),
                    0x02 => return (IsaFeature::Avx2, "vpblendd"),
                    0x38 => return (IsaFeature::Avx2, "vinserti128"),
                    0x39 => return (IsaFeature::Avx2, "vextracti128"),
                    0x46 => return (IsaFeature::Avx2, "vperm2i128"),
                    0x0E | 0x0F | 0x42 if l_256 => return (IsaFeature::Avx2, "avx2-0f3a-256"),
                    _ => {}
                }
            }
            (IsaFeature::Avx, "avx-0f3a")
        }
        _ => (IsaFeature::Avx, "avx"),
    }
}

fn decode_evex(bytes: &[u8], pos: usize) -> DecodedInsn {
    // 0x62 <p0> <p1> <p2> <opcode> <ModRM ...> [imm]
    if pos + 4 >= bytes.len() {
        return invalid_step();
    }
    let p0 = bytes[pos + 1];
    let p1 = bytes[pos + 2];
    let p2 = bytes[pos + 3];
    let opcode = bytes[pos + 4];

    // EVEX validity invariants: p1 bit 2 MUST be 1; map in 1..=3 or 5..=6; p0 bit 3 must be 0.
    let map = p0 & 0x07;
    if (p1 & 0x04) == 0 || (p0 & 0x08) != 0 || !matches!(map, 1..=3 | 5 | 6) {
        return invalid_step();
    }

    let modrm_pos = pos + 5;
    let Some(m_len) = modrm_len(bytes, modrm_pos) else {
        return invalid_step();
    };

    let imm_len = match map {
        1 => match opcode {
            0x70 | 0x71 | 0x72 | 0x73 | 0xC2 | 0xC4 | 0xC5 | 0xC6 => 1,
            _ => 0,
        },
        3 => 1,
        _ => 0,
    };

    let pp = p1 & 0x03;
    let ll = (p2 >> 5) & 0x03;
    let (feature, mnemonic) = if map == 2 && pp == 1 && matches!(opcode, 0xDC..=0xDF) {
        (IsaFeature::Vaes, "vaes-evex")
    } else if map == 3 && pp == 1 && opcode == 0x44 {
        (IsaFeature::Vpclmulqdq, "vpclmulqdq-evex")
    } else if ll == 0 || ll == 1 {
        (IsaFeature::Avx512Vl, "avx512vl")
    } else if map == 2 && matches!(opcode, 0x00 | 0x04 | 0x1C..=0x1E | 0x7A..=0x7D) {
        (IsaFeature::Avx512Bw, "avx512bw")
    } else if map == 3 && matches!(opcode, 0x08..=0x0B | 0x3E | 0x3F | 0x54..=0x57) {
        (IsaFeature::Avx512Dq, "avx512dq")
    } else {
        (IsaFeature::Avx512F, "avx512f")
    };

    finalize(modrm_pos + m_len + imm_len, feature, mnemonic, bytes.len())
}

fn decode_0f(bytes: &[u8], pos: usize, pref: LegacyPrefixes, rex_w: bool) -> DecodedInsn {
    if pos >= bytes.len() {
        return invalid_step();
    }
    let op2 = bytes[pos];
    let after_op2 = pos + 1;

    // 3-byte opcode maps: 0F 38 and 0F 3A
    if op2 == 0x38 {
        return decode_0f38(bytes, after_op2, pref);
    }
    if op2 == 0x3A {
        return decode_0f3a(bytes, after_op2, pref);
    }

    // 0F 80..=8F: Jcc rel32 (no ModRM)
    if (0x80..=0x8F).contains(&op2) {
        return finalize(after_op2 + 4, IsaFeature::Baseline, "jcc", bytes.len());
    }

    // No-ModRM 0F opcodes
    if matches!(
        op2,
        0x05 | 0x06
            | 0x07
            | 0x08
            | 0x09
            | 0x0B
            | 0x0E
            | 0x30..=0x35
            | 0x37
            | 0x77
            | 0xA0
            | 0xA1
            | 0xA2
            | 0xA8
            | 0xA9
            | 0xAA
            | 0xC8..=0xCF
    ) {
        return finalize(after_op2, IsaFeature::Baseline, "x86-0f", bytes.len());
    }

    // Almost all remaining 0F opcodes take a ModRM byte.
    let Some(m_len) = modrm_len(bytes, after_op2) else {
        return invalid_step();
    };

    let imm_len = match op2 {
        0x70 | 0x71 | 0x72 | 0x73 | 0xA4 | 0xAC | 0xBA | 0xC2 | 0xC4 | 0xC5 | 0xC6 => 1,
        _ => 0,
    };

    let _ = rex_w;
    let (feature, mnemonic) = match op2 {
        0xB8 if pref.last_rep == 0xF3 => (IsaFeature::Popcnt, "popcnt"),
        // F3 0F BC (`tzcnt`) is encoded as `rep bsf` and never raises #UD/SIGILL on
        // pre-BMI1 CPUs; LLVM/rustc routinely emits it behind a non-zero check in
        // baseline x86-64-v1 binaries. Only VEX-encoded BMI1 ops fault without BMI1.
        0xBC if pref.last_rep == 0xF3 => (IsaFeature::Baseline, "tzcnt/rep-bsf"),
        0xBD if pref.last_rep == 0xF3 => (IsaFeature::Lzcnt, "lzcnt"),
        0x12 if pref.last_rep == 0xF3 || pref.last_rep == 0xF2 => (IsaFeature::Sse3, "movs/ddup"),
        0x16 if pref.last_rep == 0xF3 => (IsaFeature::Sse3, "movshdup"),
        0x7C | 0x7D | 0xD0 if pref.has_66 || pref.last_rep == 0xF2 => {
            (IsaFeature::Sse3, "hadd/hsub/addsub")
        }
        0xF0 if pref.last_rep == 0xF2 => (IsaFeature::Sse3, "lddqu"),
        _ => (IsaFeature::Baseline, "x86-0f"),
    };

    finalize(after_op2 + m_len + imm_len, feature, mnemonic, bytes.len())
}

fn decode_0f38(bytes: &[u8], pos: usize, pref: LegacyPrefixes) -> DecodedInsn {
    if pos >= bytes.len() {
        return invalid_step();
    }
    let op3 = bytes[pos];
    let after_op3 = pos + 1;
    let Some(m_len) = modrm_len(bytes, after_op3) else {
        return invalid_step();
    };

    let (feature, mnemonic) = match op3 {
        0x00..=0x0B | 0x1C..=0x1E => (IsaFeature::Ssse3, "ssse3"),
        0x10 | 0x14 | 0x15 | 0x17 | 0x20..=0x25 | 0x28..=0x2B | 0x30..=0x35 | 0x38..=0x41 => {
            (IsaFeature::Sse41, "sse4.1")
        }
        0x37 => (IsaFeature::Sse42, "pcmpgtq"),
        0xF0 | 0xF1 if pref.last_rep == 0xF2 => (IsaFeature::Sse42, "crc32"),
        0xF0 | 0xF1 => (IsaFeature::Movbe, "movbe"),
        0xF6 if pref.has_66 || pref.last_rep == 0xF3 => (IsaFeature::Adx, "adcx/adox"),
        0xDB..=0xDF if pref.has_66 => (IsaFeature::Aes, "aes"),
        0xC8 if !pref.has_66 && pref.last_rep == 0 => (IsaFeature::Sha, "sha1nexte"),
        0xC9 if !pref.has_66 && pref.last_rep == 0 => (IsaFeature::Sha, "sha1msg1"),
        0xCA if !pref.has_66 && pref.last_rep == 0 => (IsaFeature::Sha, "sha1msg2"),
        0xCB if !pref.has_66 && pref.last_rep == 0 => (IsaFeature::Sha, "sha256rnds2"),
        0xCC if !pref.has_66 && pref.last_rep == 0 => (IsaFeature::Sha, "sha256msg1"),
        0xCD if !pref.has_66 && pref.last_rep == 0 => (IsaFeature::Sha, "sha256msg2"),
        _ => (IsaFeature::Baseline, "x86-0f38"),
    };

    finalize(after_op3 + m_len, feature, mnemonic, bytes.len())
}

fn decode_0f3a(bytes: &[u8], pos: usize, pref: LegacyPrefixes) -> DecodedInsn {
    if pos >= bytes.len() {
        return invalid_step();
    }
    let op3 = bytes[pos];
    let after_op3 = pos + 1;
    let Some(m_len) = modrm_len(bytes, after_op3) else {
        return invalid_step();
    };

    let (feature, mnemonic) = match op3 {
        0x0F => (IsaFeature::Ssse3, "palignr"),
        0x08..=0x0E | 0x14..=0x17 | 0x20..=0x22 | 0x40..=0x42 => (IsaFeature::Sse41, "sse4.1"),
        0x44 if pref.has_66 => (IsaFeature::Pclmulqdq, "pclmulqdq"),
        0x60..=0x63 if pref.has_66 => (IsaFeature::Sse42, "pcmpstr"),
        0xCC if !pref.has_66 && pref.last_rep == 0 => (IsaFeature::Sha, "sha1rnds4"),
        0xDF if pref.has_66 => (IsaFeature::Aes, "aeskeygenassist"),
        _ => (IsaFeature::Baseline, "x86-0f3a"),
    };

    finalize(after_op3 + m_len + 1, feature, mnemonic, bytes.len())
}

fn decode_1byte(
    bytes: &[u8],
    pos: usize,
    op: u8,
    pref: LegacyPrefixes,
    rex_w: bool,
) -> DecodedInsn {
    let imm_z: usize = if pref.has_66 && !rex_w { 2 } else { 4 };

    // Primary 1-byte opcodes without ModRM
    match op {
        // Invalid in 64-bit mode
        0x06 | 0x07 | 0x0E | 0x16 | 0x17 | 0x1E | 0x1F | 0x27 | 0x2F | 0x37 | 0x3F | 0x60
        | 0x61 | 0x62 | 0x82 | 0x9A | 0xC4 | 0xC5 | 0xCE | 0xD4 | 0xD5 | 0xD6 | 0xEA => {
            return invalid_step();
        }
        // Single-byte no-operand ops
        0x50..=0x5F
        | 0x90..=0x99
        | 0x9B..=0x9F
        | 0xA4..=0xA7
        | 0xAA..=0xAF
        | 0xC3
        | 0xC9
        | 0xCB
        | 0xCC
        | 0xCF
        | 0xD7
        | 0xEC..=0xEF
        | 0xF1
        | 0xF4
        | 0xF5
        | 0xF8..=0xFD => {
            return finalize(pos, IsaFeature::Baseline, "x86", bytes.len());
        }
        // Immediate 8-bit, no ModRM
        0x04
        | 0x0C
        | 0x14
        | 0x1C
        | 0x24
        | 0x2C
        | 0x34
        | 0x3C
        | 0x6A
        | 0x70..=0x7F
        | 0xA8
        | 0xB0..=0xB7
        | 0xCD
        | 0xE0..=0xE7
        | 0xEB => {
            return finalize(pos + 1, IsaFeature::Baseline, "x86", bytes.len());
        }
        // Immediate 16-bit, no ModRM (RET imm16)
        0xC2 | 0xCA => {
            return finalize(pos + 2, IsaFeature::Baseline, "ret", bytes.len());
        }
        // ENTER imm16, imm8
        0xC8 => {
            return finalize(pos + 3, IsaFeature::Baseline, "enter", bytes.len());
        }
        // Immediate z (16 if 66 && !REX.W else 32), no ModRM
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0x68 | 0xA9 => {
            return finalize(pos + imm_z, IsaFeature::Baseline, "x86", bytes.len());
        }
        // CALL / JMP rel32 (rel16 if 66)
        0xE8 | 0xE9 => {
            return finalize(pos + imm_z, IsaFeature::Baseline, "call/jmp", bytes.len());
        }
        // MOV r64/r32/r16, imm (imm64 when REX.W, imm16 when 66 && !REX.W, else imm32)
        0xB8..=0xBF => {
            let imm = if rex_w {
                8
            } else if pref.has_66 {
                2
            } else {
                4
            };
            return finalize(pos + imm, IsaFeature::Baseline, "mov-imm", bytes.len());
        }
        // MOV moffs (8 bytes in 64-bit mode, 4 bytes with 0x67 address-size override)
        0xA0..=0xA3 => {
            let addr_len = if pref.has_67 { 4 } else { 8 };
            return finalize(
                pos + addr_len,
                IsaFeature::Baseline,
                "mov-moffs",
                bytes.len(),
            );
        }
        _ => {}
    }

    // All remaining 1-byte opcodes require ModRM
    let Some(m_len) = modrm_len(bytes, pos) else {
        return invalid_step();
    };
    let reg_field = (bytes[pos] >> 3) & 0x07;

    let imm_len = match op {
        0x6B | 0x80 | 0x83 | 0xC0 | 0xC1 | 0xC6 => 1,
        0x69 | 0x81 | 0xC7 => imm_z,
        0xF6 if reg_field <= 1 => 1,
        0xF7 if reg_field <= 1 => imm_z,
        _ => 0,
    };

    finalize(
        pos + m_len + imm_len,
        IsaFeature::Baseline,
        "x86",
        bytes.len(),
    )
}
