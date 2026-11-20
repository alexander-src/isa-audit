#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Instant;

use isa_audit::analyzer::{audit_binary, AuditOptions};
use isa_audit::elf::ElfBinary;
use isa_audit::isa::{parse_feature_list, IsaFeature, TargetProfile};
use isa_audit::report::{render_json, render_sarif, render_text, ReportFormat};

fn usage() -> &'static str {
    "\
isa-audit — x86-64 ELF64 binary ISA feature auditor & CI gate

USAGE:
  isa-audit scan  <binary> [--format text|json|sarif] [--section NAME] [--top N]
  isa-audit check <binary> [--target PROFILE] [--forbid FEAT,...]
                           [--format text|json|sarif] [--section NAME]
                           [--max-findings N] [--top N]
  isa-audit bench <binary> [--iterations N]

PROFILES:
  x86-64-v1   Baseline x86-64 (SSE/SSE2)
  x86-64-v2   v1 + SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT
  avx-no-fma  v2 + AVX, AES-NI, PCLMULQDQ (forbids FMA3/AVX2/AVX-512)
  x86-64-v3   v2 + AVX, AVX2, FMA3, BMI1, BMI2, F16C, LZCNT, MOVBE
  x86-64-v4   v3 + AVX-512F/VL/BW/DQ

EXIT CODES:
  0  Scan succeeded / binary complies with ISA policy
  1  Policy check failed (forbidden instructions found)
  2  CLI argument, I/O, or ELF parse error
"
}

fn parse_format(val: &str) -> Result<ReportFormat, String> {
    match val.to_ascii_lowercase().as_str() {
        "text" => Ok(ReportFormat::Text),
        "json" => Ok(ReportFormat::Json),
        "sarif" => Ok(ReportFormat::Sarif),
        other => Err(format!(
            "unsupported --format '{other}' (expected text, json, or sarif)"
        )),
    }
}

fn next_arg(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print!("{}", usage());
        return Ok(ExitCode::SUCCESS);
    }
    if matches!(args[0].as_str(), "-V" | "--version") {
        println!("isa-audit {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }

    let cmd = args[0].as_str();
    match cmd {
        "scan" | "check" => {
            let mut path: Option<String> = None;
            let mut format = ReportFormat::Text;
            let mut section_filter: Option<String> = None;
            let mut forbidden: BTreeSet<IsaFeature> = BTreeSet::new();
            let mut max_findings: usize = 50;
            let mut top_n: usize = 25;

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--format" | "-f" => {
                        let v = next_arg(&args, &mut i, "--format")?;
                        format = parse_format(&v)?;
                    }
                    "--section" | "-s" => {
                        section_filter = Some(next_arg(&args, &mut i, "--section")?);
                    }
                    "--target" | "-t" => {
                        let v = next_arg(&args, &mut i, "--target")?;
                        let profile = TargetProfile::from_str(&v)?;
                        forbidden.extend(profile.forbidden_features());
                    }
                    "--forbid" => {
                        let v = next_arg(&args, &mut i, "--forbid")?;
                        forbidden.extend(parse_feature_list(&v)?);
                    }
                    "--max-findings" => {
                        let v = next_arg(&args, &mut i, "--max-findings")?;
                        max_findings = v
                            .parse::<usize>()
                            .map_err(|_| format!("invalid --max-findings '{v}'"))?;
                    }
                    "--top" => {
                        let v = next_arg(&args, &mut i, "--top")?;
                        top_n = v
                            .parse::<usize>()
                            .map_err(|_| format!("invalid --top '{v}'"))?;
                    }
                    flag if flag.starts_with('-') => {
                        return Err(format!("unknown flag '{flag}'"));
                    }
                    positional => {
                        if path.is_some() {
                            return Err(format!("unexpected positional argument '{positional}'"));
                        }
                        path = Some(positional.to_string());
                    }
                }
                i += 1;
            }

            let binary_path =
                path.ok_or_else(|| format!("missing <binary> argument for '{cmd}'"))?;
            if cmd == "check" && forbidden.is_empty() {
                return Err(
                    "check requires at least one of --target <profile> or --forbid <features>"
                        .to_string(),
                );
            }

            let raw = fs::read(&binary_path)
                .map_err(|e| format!("failed to read '{binary_path}': {e}"))?;
            let elf = ElfBinary::parse(&raw)
                .map_err(|e| format!("failed to parse ELF '{binary_path}': {e}"))?;

            let opts = AuditOptions {
                section_filter,
                forbidden,
                max_findings,
            };
            let report = audit_binary(&binary_path, &elf, &opts);

            let rendered = match format {
                ReportFormat::Text => render_text(&report, top_n),
                ReportFormat::Json => render_json(&report),
                ReportFormat::Sarif => render_sarif(&report),
            };
            print!("{rendered}");

            if cmd == "check" && !report.passed() {
                Ok(ExitCode::from(1))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        "bench" => {
            let mut path: Option<String> = None;
            let mut iterations: usize = 50;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--iterations" | "-n" => {
                        let v = next_arg(&args, &mut i, "--iterations")?;
                        iterations = v
                            .parse::<usize>()
                            .ok()
                            .filter(|&n| n > 0)
                            .ok_or_else(|| format!("invalid --iterations '{v}'"))?;
                    }
                    flag if flag.starts_with('-') => {
                        return Err(format!("unknown flag '{flag}'"));
                    }
                    positional => {
                        if path.is_some() {
                            return Err(format!("unexpected positional argument '{positional}'"));
                        }
                        path = Some(positional.to_string());
                    }
                }
                i += 1;
            }

            let binary_path =
                path.ok_or_else(|| "missing <binary> argument for 'bench'".to_string())?;
            let raw = fs::read(&binary_path)
                .map_err(|e| format!("failed to read '{binary_path}': {e}"))?;
            let elf = ElfBinary::parse(&raw)
                .map_err(|e| format!("failed to parse ELF '{binary_path}': {e}"))?;

            let opts = AuditOptions::default();
            // Warmup pass
            let warmup = audit_binary(&binary_path, &elf, &opts);

            let start = Instant::now();
            let mut total_insns = 0u64;
            let mut total_bytes = 0usize;
            for _ in 0..iterations {
                let r = audit_binary(&binary_path, &elf, &opts);
                total_insns += r.total_instructions;
                total_bytes += r.total_bytes_scanned;
            }
            let elapsed = start.elapsed().as_secs_f64().max(1e-9);
            let mb_per_sec = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed;
            let mins_per_sec = (total_insns as f64 / 1_000_000.0) / elapsed;

            println!("isa-audit benchmark: {binary_path}");
            println!(
                "  executable bytes : {} ({} instructions/pass)",
                warmup.total_bytes_scanned, warmup.total_instructions
            );
            println!("  iterations       : {iterations}");
            println!("  elapsed          : {:.4} s", elapsed);
            println!(
                "  throughput       : {:.2} MiB/s ({:.2} M insns/s)",
                mb_per_sec, mins_per_sec
            );
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!(
            "unknown subcommand '{other}' (run --help for usage)"
        )),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}
