use std::fmt::Write as _;

use crate::analyzer::{AuditReport, DiffReport};
use crate::isa::IsaFeature;

/// Output report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
    Sarif,
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (idx, b) in bytes.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Renders a human-readable terminal report.
pub fn render_text(report: &AuditReport, top_n: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "isa-audit report: {}", report.path);
    let _ = writeln!(out, "  min-profile   : {}", report.min_profile);
    if !report.members_scanned.is_empty() {
        let _ = writeln!(out, "  members       : {}", report.members_scanned.len());
    }
    let _ = writeln!(
        out,
        "  sections      : {} ({} bytes decoded, {} instructions, {} recovery steps)",
        report.sections_scanned.len(),
        report.total_bytes_scanned,
        report.total_instructions,
        report.invalid_steps
    );

    if !report.forbidden_policy.is_empty() {
        let status = if report.passed() { "PASS" } else { "FAIL" };
        let forbidden_list: Vec<&str> = report.forbidden_policy.iter().map(|f| f.id()).collect();
        let _ = writeln!(
            out,
            "  policy-status : {status} (forbid: {}, violations: {})",
            forbidden_list.join(", "),
            report.total_violations
        );
    }

    let _ = writeln!(out, "\nISA Feature Breakdown:");
    let _ = writeln!(out, "  {:<18} {:>12}   {:>7}", "FEATURE", "COUNT", "STATUS");
    let _ = writeln!(out, "  {}", "-".repeat(42));

    let mut rows: Vec<(IsaFeature, u64)> = report
        .feature_counts
        .iter()
        .map(|(&f, &c)| (f, c))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (feat, count) in rows {
        let tag = if report.forbidden_policy.contains(&feat) {
            "FORBIDDEN"
        } else {
            "ok"
        };
        let _ = writeln!(out, "  {:<18} {:>12}   {:>7}", feat.label(), count, tag);
    }

    if !report.findings.is_empty() {
        let shown = report.findings.len().min(top_n);
        let _ = writeln!(
            out,
            "\nForbidden Instruction Sites (showing {shown} of {}):",
            report.total_violations
        );
        for f in report.findings.iter().take(shown) {
            let base_loc = match &f.symbol {
                Some(sym) => format!("{sym}+0x{:x}", f.symbol_offset),
                None => format!("{}@0x{:x}", f.section, f.vaddr),
            };
            let loc = match &f.member {
                Some(member) => format!("{member}:{base_loc}"),
                None => base_loc,
            };
            let _ = writeln!(
                out,
                "  0x{:012x}  {:<10} {:<14} {:<36} [{}]",
                f.vaddr,
                f.feature.label(),
                f.mnemonic,
                loc,
                hex_bytes(&f.bytes)
            );
        }
        if report.violations_truncated || shown < report.findings.len() {
            let _ = writeln!(
                out,
                "  ... ({} additional violation(s) omitted; increase --max-findings to inspect)",
                report.total_violations.saturating_sub(shown as u64)
            );
        }
    }

    out
}

/// Renders a strict RFC 8259 JSON report.
pub fn render_json(report: &AuditReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"tool\": \"isa-audit\",");
    let _ = writeln!(out, "  \"version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "  \"path\": {},", json_escape(&report.path));
    let _ = writeln!(out, "  \"passed\": {},", report.passed());
    let _ = writeln!(
        out,
        "  \"min_profile\": {},",
        json_escape(report.min_profile)
    );
    let _ = writeln!(
        out,
        "  \"total_bytes_scanned\": {},",
        report.total_bytes_scanned
    );
    let _ = writeln!(
        out,
        "  \"total_instructions\": {},",
        report.total_instructions
    );
    let _ = writeln!(out, "  \"invalid_steps\": {},", report.invalid_steps);
    let _ = writeln!(out, "  \"total_violations\": {},", report.total_violations);

    out.push_str("  \"members_scanned\": [");
    for (idx, m) in report.members_scanned.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_escape(m));
    }
    out.push_str("],\n");

    out.push_str("  \"forbidden_policy\": [");
    for (idx, f) in report.forbidden_policy.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_escape(f.id()));
    }
    out.push_str("],\n");

    out.push_str("  \"features\": {\n");
    let feat_len = report.feature_counts.len();
    for (idx, (feat, count)) in report.feature_counts.iter().enumerate() {
        let comma = if idx + 1 < feat_len { "," } else { "" };
        let _ = writeln!(out, "    {}: {}{comma}", json_escape(feat.id()), count);
    }
    out.push_str("  },\n");

    out.push_str("  \"findings\": [\n");
    for (idx, f) in report.findings.iter().enumerate() {
        let comma = if idx + 1 < report.findings.len() {
            ","
        } else {
            ""
        };
        let member_json = match &f.member {
            Some(m) => json_escape(m),
            None => "null".to_string(),
        };
        let sym_json = match &f.symbol {
            Some(s) => json_escape(s),
            None => "null".to_string(),
        };
        let _ = writeln!(
            out,
            "    {{\"member\": {}, \"feature\": {}, \"mnemonic\": {}, \"section\": {}, \"vaddr\": {}, \"symbol\": {}, \"symbol_offset\": {}, \"bytes\": {}}}{comma}",
            member_json,
            json_escape(f.feature.id()),
            json_escape(f.mnemonic),
            json_escape(&f.section),
            json_escape(&format!("0x{:x}", f.vaddr)),
            sym_json,
            f.symbol_offset,
            json_escape(&hex_bytes(&f.bytes))
        );
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// Renders a SARIF 2.1.0 report compatible with GitHub Code Scanning.
pub fn render_sarif(report: &AuditReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
    out.push_str("  \"version\": \"2.1.0\",\n");
    out.push_str("  \"runs\": [\n    {\n");
    out.push_str("      \"tool\": {\n        \"driver\": {\n");
    out.push_str("          \"name\": \"isa-audit\",\n");
    let _ = writeln!(
        out,
        "          \"version\": {},",
        json_escape(env!("CARGO_PKG_VERSION"))
    );
    out.push_str("          \"informationUri\": \"https://github.com/alexander-src/isa-audit\"\n");
    out.push_str("        }\n      },\n");
    out.push_str("      \"results\": [\n");

    for (idx, f) in report.findings.iter().enumerate() {
        let comma = if idx + 1 < report.findings.len() {
            ","
        } else {
            ""
        };
        let rule_id = format!("isa-audit/forbidden-{}", f.feature.id());
        let loc_part = match &f.member {
            Some(m) => format!("{m}:{}", f.section),
            None => f.section.clone(),
        };
        let sym_part = match &f.symbol {
            Some(s) => format!(" in {s}+0x{:x}", f.symbol_offset),
            None => String::new(),
        };
        let msg = format!(
            "Forbidden {} instruction ({}) at 0x{:x} ({loc_part}{sym_part}) [{}]",
            f.feature.label(),
            f.mnemonic,
            f.vaddr,
            hex_bytes(&f.bytes)
        );
        let _ = writeln!(out, "        {{");
        let _ = writeln!(out, "          \"ruleId\": {},", json_escape(&rule_id));
        let _ = writeln!(out, "          \"level\": \"error\",");
        let _ = writeln!(
            out,
            "          \"message\": {{\"text\": {}}},",
            json_escape(&msg)
        );
        let _ = writeln!(
            out,
            "          \"locations\": [{{\"physicalLocation\": {{\"artifactLocation\": {{\"uri\": {}}}}}}}]",
            json_escape(&report.path)
        );
        let _ = writeln!(out, "        }}{comma}");
    }

    out.push_str("      ]\n    }\n  ]\n}\n");
    out
}

/// Renders a human-readable terminal diff between two audited binaries.
pub fn render_diff_text(diff: &DiffReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "isa-audit diff:");
    let _ = writeln!(
        out,
        "  before        : {} ({}, {} instructions)",
        diff.before_path, diff.before_min_profile, diff.before_instructions
    );
    let _ = writeln!(
        out,
        "  after         : {} ({}, {} instructions)",
        diff.after_path, diff.after_min_profile, diff.after_instructions
    );
    let _ = writeln!(
        out,
        "  min-profile   : {} -> {}",
        diff.before_min_profile, diff.after_min_profile
    );

    if !diff.added_features.is_empty() {
        let added: Vec<&str> = diff.added_features.iter().map(|f| f.label()).collect();
        let _ = writeln!(out, "  added         : {}", added.join(", "));
    }
    if !diff.removed_features.is_empty() {
        let removed: Vec<&str> = diff.removed_features.iter().map(|f| f.label()).collect();
        let _ = writeln!(out, "  removed       : {}", removed.join(", "));
    }

    let _ = writeln!(out, "\nISA Feature Deltas:");
    let _ = writeln!(
        out,
        "  {:<18} {:>10} {:>10} {:>11}   STATUS",
        "FEATURE", "BEFORE", "AFTER", "DELTA"
    );
    let _ = writeln!(out, "  {}", "-".repeat(62));

    for row in &diff.deltas {
        let status = if diff.added_features.contains(&row.feature) {
            "ADDED"
        } else if diff.removed_features.contains(&row.feature) {
            "REMOVED"
        } else if row.delta != 0 {
            "changed"
        } else {
            "same"
        };
        let _ = writeln!(
            out,
            "  {:<18} {:>10} {:>10} {:>+11}   {}",
            row.feature.label(),
            row.before,
            row.after,
            row.delta,
            status
        );
    }

    out
}

/// Renders a strict RFC 8259 JSON diff report.
pub fn render_diff_json(diff: &DiffReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"tool\": \"isa-audit\",");
    let _ = writeln!(out, "  \"version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "  \"mode\": \"diff\",");
    let _ = writeln!(
        out,
        "  \"before_path\": {},",
        json_escape(&diff.before_path)
    );
    let _ = writeln!(out, "  \"after_path\": {},", json_escape(&diff.after_path));
    let _ = writeln!(
        out,
        "  \"before_min_profile\": {},",
        json_escape(diff.before_min_profile)
    );
    let _ = writeln!(
        out,
        "  \"after_min_profile\": {},",
        json_escape(diff.after_min_profile)
    );
    let _ = writeln!(
        out,
        "  \"before_instructions\": {},",
        diff.before_instructions
    );
    let _ = writeln!(
        out,
        "  \"after_instructions\": {},",
        diff.after_instructions
    );
    let _ = writeln!(out, "  \"regressed\": {},", diff.has_regression());

    out.push_str("  \"added_features\": [");
    for (idx, feat) in diff.added_features.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_escape(feat.id()));
    }
    out.push_str("],\n");

    out.push_str("  \"removed_features\": [");
    for (idx, feat) in diff.removed_features.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_escape(feat.id()));
    }
    out.push_str("],\n");

    out.push_str("  \"deltas\": [\n");
    for (idx, row) in diff.deltas.iter().enumerate() {
        let comma = if idx + 1 < diff.deltas.len() { "," } else { "" };
        let _ = writeln!(
            out,
            "    {{\"feature\": {}, \"before\": {}, \"after\": {}, \"delta\": {}}}{comma}",
            json_escape(row.feature.id()),
            row.before,
            row.after,
            row.delta
        );
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}
