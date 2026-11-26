use std::collections::{BTreeMap, BTreeSet};

use crate::archive::{is_archive, Archive};
use crate::decoder::decode_one;
use crate::elf::{ElfBinary, ExecSection};
use crate::isa::{infer_min_profile, IsaFeature};

/// Configuration options controlling how an ELF binary is scanned.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Optional subset of executable sections to inspect (empty = all executable sections).
    pub section_filter: Option<String>,
    /// Set of ISA features considered policy violations.
    pub forbidden: BTreeSet<IsaFeature>,
    /// Maximum number of detailed offending instruction findings retained in the report.
    pub max_findings: usize,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            section_filter: None,
            forbidden: BTreeSet::new(),
            max_findings: 50,
        }
    }
}

/// A single instruction finding attributed to optional archive member, section, virtual address, and optional symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub member: Option<String>,
    pub feature: IsaFeature,
    pub mnemonic: &'static str,
    pub section: String,
    pub vaddr: u64,
    pub symbol: Option<String>,
    pub symbol_offset: u64,
    pub bytes: Vec<u8>,
}

/// Per-section scan summary.
#[derive(Debug, Clone)]
pub struct SectionSummary {
    pub name: String,
    pub vaddr: u64,
    pub size: usize,
    pub instructions: u64,
    pub invalid_steps: u64,
}

/// Complete result of auditing an x86-64 ELF64 binary or Unix `.a` static archive.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub path: String,
    pub members_scanned: Vec<String>,
    pub sections_scanned: Vec<SectionSummary>,
    pub total_bytes_scanned: usize,
    pub total_instructions: u64,
    pub invalid_steps: u64,
    pub feature_counts: BTreeMap<IsaFeature, u64>,
    pub min_profile: &'static str,
    pub forbidden_policy: BTreeSet<IsaFeature>,
    pub total_violations: u64,
    pub violations_truncated: bool,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// Returns true if zero forbidden instructions were observed.
    pub fn passed(&self) -> bool {
        self.total_violations == 0
    }
}

/// Per-feature instruction count delta between two audited binaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureDelta {
    pub feature: IsaFeature,
    pub before: u64,
    pub after: u64,
    pub delta: i64,
}

/// Comparison of ISA extension usage between a baseline (`before`) and updated (`after`) binary.
#[derive(Debug, Clone)]
pub struct DiffReport {
    pub before_path: String,
    pub after_path: String,
    pub before_min_profile: &'static str,
    pub after_min_profile: &'static str,
    pub before_instructions: u64,
    pub after_instructions: u64,
    pub deltas: Vec<FeatureDelta>,
    pub added_features: BTreeSet<IsaFeature>,
    pub removed_features: BTreeSet<IsaFeature>,
}

impl DiffReport {
    /// Returns true if `after` introduces at least one non-baseline ISA extension absent in `before`.
    pub fn has_regression(&self) -> bool {
        !self.added_features.is_empty()
    }
}

/// Compares two audit reports and computes per-feature deltas and ISA regressions.
pub fn diff_reports(before: &AuditReport, after: &AuditReport) -> DiffReport {
    let mut keys: BTreeSet<IsaFeature> = BTreeSet::new();
    keys.extend(before.feature_counts.keys().copied());
    keys.extend(after.feature_counts.keys().copied());

    let mut deltas = Vec::with_capacity(keys.len());
    let mut added_features = BTreeSet::new();
    let mut removed_features = BTreeSet::new();

    for feature in keys {
        let before_count = before.feature_counts.get(&feature).copied().unwrap_or(0);
        let after_count = after.feature_counts.get(&feature).copied().unwrap_or(0);
        let delta = after_count as i64 - before_count as i64;
        if feature != IsaFeature::Baseline {
            if before_count == 0 && after_count > 0 {
                added_features.insert(feature);
            } else if before_count > 0 && after_count == 0 {
                removed_features.insert(feature);
            }
        }
        deltas.push(FeatureDelta {
            feature,
            before: before_count,
            after: after_count,
            delta,
        });
    }

    DiffReport {
        before_path: before.path.clone(),
        after_path: after.path.clone(),
        before_min_profile: before.min_profile,
        after_min_profile: after.min_profile,
        before_instructions: before.total_instructions,
        after_instructions: after.total_instructions,
        deltas,
        added_features,
        removed_features,
    }
}

/// Runs a full ISA audit over a parsed x86-64 ELF64 binary.
pub fn audit_binary(
    path: impl Into<String>,
    elf: &ElfBinary<'_>,
    opts: &AuditOptions,
) -> AuditReport {
    let mut sections_scanned = Vec::new();
    let mut total_bytes_scanned = 0usize;
    let mut total_instructions = 0u64;
    let mut invalid_steps = 0u64;
    let mut feature_counts: BTreeMap<IsaFeature, u64> = BTreeMap::new();
    let mut total_violations = 0u64;
    let mut findings = Vec::new();

    scan_elf_into(
        None,
        elf,
        opts,
        &mut sections_scanned,
        &mut total_bytes_scanned,
        &mut total_instructions,
        &mut invalid_steps,
        &mut feature_counts,
        &mut total_violations,
        &mut findings,
    );

    let observed: BTreeSet<IsaFeature> = feature_counts.keys().copied().collect();
    let min_profile = infer_min_profile(&observed);
    let violations_truncated = (findings.len() as u64) < total_violations;

    AuditReport {
        path: path.into(),
        members_scanned: Vec::new(),
        sections_scanned,
        total_bytes_scanned,
        total_instructions,
        invalid_steps,
        feature_counts,
        min_profile,
        forbidden_policy: opts.forbidden.clone(),
        total_violations,
        violations_truncated,
        findings,
    }
}

/// Runs a full ISA audit across all ELF64 x86-64 object members in a Unix `.a` archive.
pub fn audit_archive(
    path: impl Into<String>,
    archive: &Archive<'_>,
    opts: &AuditOptions,
) -> Result<AuditReport, String> {
    let path_str = path.into();
    let mut members_scanned = Vec::new();
    let mut sections_scanned = Vec::new();
    let mut total_bytes_scanned = 0usize;
    let mut total_instructions = 0u64;
    let mut invalid_steps = 0u64;
    let mut feature_counts: BTreeMap<IsaFeature, u64> = BTreeMap::new();
    let mut total_violations = 0u64;
    let mut findings = Vec::new();

    for member in &archive.members {
        if !member.data.starts_with(b"\x7fELF") {
            continue;
        }
        let elf = ElfBinary::parse(member.data).map_err(|e| {
            format!(
                "failed to parse ELF member '{}' in '{path_str}': {e}",
                member.name
            )
        })?;
        members_scanned.push(member.name.clone());
        scan_elf_into(
            Some(member.name.as_str()),
            &elf,
            opts,
            &mut sections_scanned,
            &mut total_bytes_scanned,
            &mut total_instructions,
            &mut invalid_steps,
            &mut feature_counts,
            &mut total_violations,
            &mut findings,
        );
    }

    let observed: BTreeSet<IsaFeature> = feature_counts.keys().copied().collect();
    let min_profile = infer_min_profile(&observed);
    let violations_truncated = (findings.len() as u64) < total_violations;

    Ok(AuditReport {
        path: path_str,
        members_scanned,
        sections_scanned,
        total_bytes_scanned,
        total_instructions,
        invalid_steps,
        feature_counts,
        min_profile,
        forbidden_policy: opts.forbidden.clone(),
        total_violations,
        violations_truncated,
        findings,
    })
}

/// Detects whether raw bytes are a Unix `.a` archive or standalone ELF64 binary and audits them.
pub fn audit_input(
    path: impl Into<String>,
    raw: &[u8],
    opts: &AuditOptions,
) -> Result<AuditReport, String> {
    let path_str = path.into();
    if is_archive(raw) {
        let archive = Archive::parse(raw)
            .map_err(|e| format!("failed to parse archive '{path_str}': {e}"))?;
        audit_archive(path_str, &archive, opts)
    } else {
        let elf =
            ElfBinary::parse(raw).map_err(|e| format!("failed to parse ELF '{path_str}': {e}"))?;
        Ok(audit_binary(path_str, &elf, opts))
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_elf_into(
    member: Option<&str>,
    elf: &ElfBinary<'_>,
    opts: &AuditOptions,
    sections_scanned: &mut Vec<SectionSummary>,
    total_bytes_scanned: &mut usize,
    total_instructions: &mut u64,
    invalid_steps: &mut u64,
    feature_counts: &mut BTreeMap<IsaFeature, u64>,
    total_violations: &mut u64,
    findings: &mut Vec<Finding>,
) {
    for sec in &elf.exec_sections {
        if let Some(ref filter) = opts.section_filter {
            if sec.name != *filter {
                continue;
            }
        }
        let mut summary = scan_section(
            member,
            elf,
            sec,
            opts,
            feature_counts,
            total_violations,
            findings,
        );
        if let Some(member_name) = member {
            summary.name = format!("{member_name}:{}", summary.name);
        }
        *total_bytes_scanned += summary.size;
        *total_instructions += summary.instructions;
        *invalid_steps += summary.invalid_steps;
        sections_scanned.push(summary);
    }
}

fn scan_section(
    member: Option<&str>,
    elf: &ElfBinary<'_>,
    sec: &ExecSection<'_>,
    opts: &AuditOptions,
    feature_counts: &mut BTreeMap<IsaFeature, u64>,
    total_violations: &mut u64,
    findings: &mut Vec<Finding>,
) -> SectionSummary {
    let sec_start = sec.vaddr;
    let sec_end = sec.vaddr.saturating_add(sec.bytes.len() as u64);

    // Build sorted resynchronization slices using known STT_FUNC spans inside this section.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut func_spans: Vec<(usize, usize)> = elf
        .symbols
        .iter()
        .filter(|s| {
            s.section_index == sec.index && s.size > 0 && s.addr >= sec_start && s.addr < sec_end
        })
        .map(|s| {
            let start = (s.addr - sec_start) as usize;
            let end = ((s.addr.saturating_add(s.size)).min(sec_end) - sec_start) as usize;
            (start, end)
        })
        .filter(|(s, e)| s < e)
        .collect();

    if func_spans.is_empty() {
        ranges.push((0, sec.bytes.len()));
    } else {
        func_spans.sort_by_key(|&(s, _)| s);
        let mut cursor = 0usize;
        for (start, end) in func_spans {
            if start > cursor {
                ranges.push((cursor, start));
            }
            let effective_start = start.max(cursor);
            if end > effective_start {
                ranges.push((effective_start, end));
                cursor = end;
            }
        }
        if cursor < sec.bytes.len() {
            ranges.push((cursor, sec.bytes.len()));
        }
    }

    let mut sec_insns = 0u64;
    let mut sec_invalid = 0u64;

    for (range_start, range_end) in ranges {
        let mut pos = range_start;
        while pos < range_end {
            let insn = decode_one(&sec.bytes[pos..range_end]);
            let step = (insn.len as usize).max(1);
            if insn.invalid {
                sec_invalid += 1;
            } else {
                sec_insns += 1;
                *feature_counts.entry(insn.feature).or_insert(0) += 1;

                if opts.forbidden.contains(&insn.feature) {
                    *total_violations += 1;
                    if findings.len() < opts.max_findings {
                        let vaddr = sec.vaddr.saturating_add(pos as u64);
                        let (symbol, symbol_offset) = match elf.resolve_symbol(sec.index, vaddr) {
                            Some((name, off)) => (Some(name.to_string()), off),
                            None => (None, 0),
                        };
                        let end = (pos + step).min(range_end);
                        findings.push(Finding {
                            member: member.map(str::to_string),
                            feature: insn.feature,
                            mnemonic: insn.mnemonic,
                            section: sec.name.clone(),
                            vaddr,
                            symbol,
                            symbol_offset,
                            bytes: sec.bytes[pos..end].to_vec(),
                        });
                    }
                }
            }
            pos += step;
        }
    }

    SectionSummary {
        name: sec.name.clone(),
        vaddr: sec.vaddr,
        size: sec.bytes.len(),
        instructions: sec_insns,
        invalid_steps: sec_invalid,
    }
}
