use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// x86-64 CPU ISA extensions tracked by `isa-audit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsaFeature {
    Baseline,
    Sse3,
    Ssse3,
    Sse41,
    Sse42,
    Popcnt,
    Pclmulqdq,
    Aes,
    Movbe,
    Lzcnt,
    Bmi1,
    Bmi2,
    Adx,
    Sha,
    F16c,
    Avx,
    Avx2,
    Fma3,
    Avx512F,
    Avx512Vl,
    Avx512Bw,
    Avx512Dq,
}

impl IsaFeature {
    /// All non-baseline features in canonical display order.
    pub const ALL_EXTENSIONS: &'static [IsaFeature] = &[
        IsaFeature::Sse3,
        IsaFeature::Ssse3,
        IsaFeature::Sse41,
        IsaFeature::Sse42,
        IsaFeature::Popcnt,
        IsaFeature::Pclmulqdq,
        IsaFeature::Aes,
        IsaFeature::Movbe,
        IsaFeature::Lzcnt,
        IsaFeature::Bmi1,
        IsaFeature::Bmi2,
        IsaFeature::Adx,
        IsaFeature::Sha,
        IsaFeature::F16c,
        IsaFeature::Avx,
        IsaFeature::Avx2,
        IsaFeature::Fma3,
        IsaFeature::Avx512F,
        IsaFeature::Avx512Vl,
        IsaFeature::Avx512Bw,
        IsaFeature::Avx512Dq,
    ];

    /// Canonical lowercase CLI/JSON identifier.
    pub const fn id(self) -> &'static str {
        match self {
            IsaFeature::Baseline => "baseline",
            IsaFeature::Sse3 => "sse3",
            IsaFeature::Ssse3 => "ssse3",
            IsaFeature::Sse41 => "sse4.1",
            IsaFeature::Sse42 => "sse4.2",
            IsaFeature::Popcnt => "popcnt",
            IsaFeature::Pclmulqdq => "pclmulqdq",
            IsaFeature::Aes => "aes",
            IsaFeature::Movbe => "movbe",
            IsaFeature::Lzcnt => "lzcnt",
            IsaFeature::Bmi1 => "bmi1",
            IsaFeature::Bmi2 => "bmi2",
            IsaFeature::Adx => "adx",
            IsaFeature::Sha => "sha",
            IsaFeature::F16c => "f16c",
            IsaFeature::Avx => "avx",
            IsaFeature::Avx2 => "avx2",
            IsaFeature::Fma3 => "fma3",
            IsaFeature::Avx512F => "avx512f",
            IsaFeature::Avx512Vl => "avx512vl",
            IsaFeature::Avx512Bw => "avx512bw",
            IsaFeature::Avx512Dq => "avx512dq",
        }
    }

    /// Human-readable display label.
    pub const fn label(self) -> &'static str {
        match self {
            IsaFeature::Baseline => "x86-64 (SSE/SSE2)",
            IsaFeature::Sse3 => "SSE3",
            IsaFeature::Ssse3 => "SSSE3",
            IsaFeature::Sse41 => "SSE4.1",
            IsaFeature::Sse42 => "SSE4.2",
            IsaFeature::Popcnt => "POPCNT",
            IsaFeature::Pclmulqdq => "PCLMULQDQ",
            IsaFeature::Aes => "AES-NI",
            IsaFeature::Movbe => "MOVBE",
            IsaFeature::Lzcnt => "LZCNT",
            IsaFeature::Bmi1 => "BMI1",
            IsaFeature::Bmi2 => "BMI2",
            IsaFeature::Adx => "ADX",
            IsaFeature::Sha => "SHA",
            IsaFeature::F16c => "F16C",
            IsaFeature::Avx => "AVX",
            IsaFeature::Avx2 => "AVX2",
            IsaFeature::Fma3 => "FMA3",
            IsaFeature::Avx512F => "AVX-512F",
            IsaFeature::Avx512Vl => "AVX-512VL",
            IsaFeature::Avx512Bw => "AVX-512BW",
            IsaFeature::Avx512Dq => "AVX-512DQ",
        }
    }

    /// Returns true if this feature is part of the AVX-512 family.
    pub const fn is_avx512(self) -> bool {
        matches!(
            self,
            IsaFeature::Avx512F
                | IsaFeature::Avx512Vl
                | IsaFeature::Avx512Bw
                | IsaFeature::Avx512Dq
        )
    }
}

impl fmt::Display for IsaFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

impl FromStr for IsaFeature {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "baseline" | "sse2" => Ok(IsaFeature::Baseline),
            "sse3" => Ok(IsaFeature::Sse3),
            "ssse3" => Ok(IsaFeature::Ssse3),
            "sse4.1" | "sse41" | "sse4_1" => Ok(IsaFeature::Sse41),
            "sse4.2" | "sse42" | "sse4_2" => Ok(IsaFeature::Sse42),
            "popcnt" => Ok(IsaFeature::Popcnt),
            "pclmulqdq" | "pclmul" => Ok(IsaFeature::Pclmulqdq),
            "aes" | "aesni" | "aes-ni" => Ok(IsaFeature::Aes),
            "movbe" => Ok(IsaFeature::Movbe),
            "lzcnt" | "abm" => Ok(IsaFeature::Lzcnt),
            "bmi1" | "bmi" => Ok(IsaFeature::Bmi1),
            "bmi2" => Ok(IsaFeature::Bmi2),
            "adx" => Ok(IsaFeature::Adx),
            "sha" => Ok(IsaFeature::Sha),
            "f16c" => Ok(IsaFeature::F16c),
            "avx" => Ok(IsaFeature::Avx),
            "avx2" => Ok(IsaFeature::Avx2),
            "fma" | "fma3" => Ok(IsaFeature::Fma3),
            "avx512f" | "avx-512f" => Ok(IsaFeature::Avx512F),
            "avx512vl" | "avx-512vl" => Ok(IsaFeature::Avx512Vl),
            "avx512bw" | "avx-512bw" => Ok(IsaFeature::Avx512Bw),
            "avx512dq" | "avx-512dq" => Ok(IsaFeature::Avx512Dq),
            other => Err(format!("unknown ISA feature '{other}'")),
        }
    }
}

/// Parses a comma-separated list of features, expanding group aliases like `avx512`.
pub fn parse_feature_list(spec: &str) -> Result<BTreeSet<IsaFeature>, String> {
    let mut set = BTreeSet::new();
    for raw in spec.split(',') {
        let token = raw.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        match token.as_str() {
            "avx512" | "avx-512" => {
                set.insert(IsaFeature::Avx512F);
                set.insert(IsaFeature::Avx512Vl);
                set.insert(IsaFeature::Avx512Bw);
                set.insert(IsaFeature::Avx512Dq);
            }
            "bmi" => {
                set.insert(IsaFeature::Bmi1);
                set.insert(IsaFeature::Bmi2);
            }
            _ => {
                set.insert(IsaFeature::from_str(&token)?);
            }
        }
    }
    Ok(set)
}

/// Standard x86-64 microarchitecture compatibility profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProfile {
    X86_64V1,
    X86_64V2,
    AvxNoFma,
    X86_64V3,
    X86_64V4,
}

impl TargetProfile {
    pub const fn id(self) -> &'static str {
        match self {
            TargetProfile::X86_64V1 => "x86-64-v1",
            TargetProfile::X86_64V2 => "x86-64-v2",
            TargetProfile::AvxNoFma => "avx-no-fma",
            TargetProfile::X86_64V3 => "x86-64-v3",
            TargetProfile::X86_64V4 => "x86-64-v4",
        }
    }

    /// Returns the set of features permitted under this microarchitecture profile.
    pub fn allowed_features(self) -> BTreeSet<IsaFeature> {
        let mut s = BTreeSet::new();
        s.insert(IsaFeature::Baseline);

        if matches!(
            self,
            TargetProfile::X86_64V2
                | TargetProfile::AvxNoFma
                | TargetProfile::X86_64V3
                | TargetProfile::X86_64V4
        ) {
            s.extend([
                IsaFeature::Sse3,
                IsaFeature::Ssse3,
                IsaFeature::Sse41,
                IsaFeature::Sse42,
                IsaFeature::Popcnt,
            ]);
        }

        if matches!(self, TargetProfile::AvxNoFma) {
            s.extend([IsaFeature::Avx, IsaFeature::Aes, IsaFeature::Pclmulqdq]);
        }

        if matches!(self, TargetProfile::X86_64V3 | TargetProfile::X86_64V4) {
            s.extend([
                IsaFeature::Avx,
                IsaFeature::Avx2,
                IsaFeature::Fma3,
                IsaFeature::Bmi1,
                IsaFeature::Bmi2,
                IsaFeature::F16c,
                IsaFeature::Lzcnt,
                IsaFeature::Movbe,
                IsaFeature::Aes,
                IsaFeature::Pclmulqdq,
            ]);
        }

        if matches!(self, TargetProfile::X86_64V4) {
            s.extend([
                IsaFeature::Avx512F,
                IsaFeature::Avx512Vl,
                IsaFeature::Avx512Bw,
                IsaFeature::Avx512Dq,
            ]);
        }

        s
    }

    /// Returns all features forbidden under this target profile.
    pub fn forbidden_features(self) -> BTreeSet<IsaFeature> {
        let allowed = self.allowed_features();
        IsaFeature::ALL_EXTENSIONS
            .iter()
            .copied()
            .filter(|f| !allowed.contains(f))
            .collect()
    }
}

impl FromStr for TargetProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "x86-64-v1" | "v1" | "baseline" => Ok(TargetProfile::X86_64V1),
            "x86-64-v2" | "v2" => Ok(TargetProfile::X86_64V2),
            "avx-no-fma" | "avx" | "sandybridge" => Ok(TargetProfile::AvxNoFma),
            "x86-64-v3" | "v3" => Ok(TargetProfile::X86_64V3),
            "x86-64-v4" | "v4" => Ok(TargetProfile::X86_64V4),
            other => Err(format!(
                "unknown target profile '{other}' (expected: x86-64-v1, x86-64-v2, avx-no-fma, x86-64-v3, x86-64-v4)"
            )),
        }
    }
}

/// Infers the lowest standard microarchitecture level that supports every observed feature.
pub fn infer_min_profile(observed: &BTreeSet<IsaFeature>) -> &'static str {
    let profiles = [
        TargetProfile::X86_64V1,
        TargetProfile::X86_64V2,
        TargetProfile::AvxNoFma,
        TargetProfile::X86_64V3,
        TargetProfile::X86_64V4,
    ];
    for profile in profiles {
        let allowed = profile.allowed_features();
        if observed.iter().all(|f| allowed.contains(f)) {
            return profile.id();
        }
    }
    "custom"
}
