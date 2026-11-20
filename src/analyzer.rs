use std::collections::{BTreeMap, BTreeSet};

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

/// A single instruction finding attributed to section, virtual address, and optional symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
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

/// Complete result of auditing an x86-64 ELF64 binary.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub path: String,
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

    for sec in &elf.exec_sections {
        if let Some(ref filter) = opts.section_filter {
            if sec.name != *filter {
                continue;
            }
        }
        let summary = scan_section(
            elf,
            sec,
            opts,
            &mut feature_counts,
            &mut total_violations,
            &mut findings,
        );
        total_bytes_scanned += summary.size;
        total_instructions += summary.instructions;
        invalid_steps += summary.invalid_steps;
        sections_scanned.push(summary);
    }

    let observed: BTreeSet<IsaFeature> = feature_counts.keys().copied().collect();
    let min_profile = infer_min_profile(&observed);
    let violations_truncated = (findings.len() as u64) < total_violations;

    AuditReport {
        path: path.into(),
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

fn scan_section(
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
