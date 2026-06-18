use std::path::PathBuf;

use clap::Parser;

mod classifier;
mod features;
mod heuristics;
mod scanner;

use crate::classifier::Model;
use scanner::ScanResult;

/// ELF Anti-Virus Scanner - Heuristic + ML detection for Linux binaries
#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// Path(s) to scan (file or directory)
    path: Vec<PathBuf>,

    /// Recursively scan directories
    #[arg(short, long)]
    recursive: bool,

    /// Show detailed analysis
    #[arg(short, long)]
    verbose: bool,

    /// Output format (text or json)
    #[arg(short = 'o', long, default_value = "text")]
    output: String,
}

fn print_banner() {
    println!(" ╔══════════════════════════════════════╗");
    println!(" ║       ELF Antivirus Scanner          ║");
    println!(" ║   Heuristic + ML Detection Engine    ║");
    println!(" ╚══════════════════════════════════════╝");
    println!();
}

fn display_result_text(result: &ScanResult, verbose: bool) {
    let model = Model::default();
    let filename = result.path.display();

    println!("┌──────────────────────────────────────────────────────────┐");
    println!("│ ELF Scanner v0.1.0                                       │");
    println!("├──────────────────────────────────────────────────────────┤");
    println!("│ File: {}", filename);
    println!("│ Size: {} bytes", result.file_size);
    println!("├──────────────────────────────────────────────────────────┤");

    if result.is_elf {
        println!(
            "│ Heuristics: {:.1}/100                                      │",
            result.heuristic_normalized
        );

        println!(
            "│ ML Score:   {:.1}/100                                      │",
            result.ml_score
        );

        println!(
            "│ Combined:   {:.1}/100                                      │",
            result.combined_score
        );

        println!(
            "│ Verdict:    {} (threshold: {:.0})                   │",
            result.classification,
            model.threshold
        );

        println!("├──────────────────────────────────────────────────────────┤");
        println!("│ Findings:                                                 │");

        if verbose || result.heuristic_results.len() <= 5 {
            for hr in &result.heuristic_results {
                println!(
                    "│ \u{2022} [{:>8}] {:<39} {:>7.0} pts │",
                    hr.severity.as_str(),
                    hr.name,
                    hr.score
                );

                if verbose {
                    println!("│   {}", hr.detail);
                }
            }
        } else {
            let mut sorted = result.heuristic_results.clone();

            sorted.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            for hr in sorted.iter().take(4) {
                println!(
                    "│ \u{2022} [{:>8}] {:<39} {:>7.0} pts │",
                    hr.severity.as_str(),
                    hr.name,
                    hr.score
                );
            }

            let remaining = sorted.len().saturating_sub(4);

            if remaining > 0 {
                println!(
                    "│   ... and {} more findings (use -v for all)                │",
                    remaining
                );
            }
        }

        println!("├──────────────────────────────────────────────────────────┤");
        println!("│ Top ML features:                                          │");

        let mut sorted_explanations = result.explanation_lines.clone();

        sorted_explanations.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        if verbose {
            for (name, contrib) in &sorted_explanations {
                println!(
                    "│ \u{2022} {:<40} {:>+7.1}           │",
                    name,
                    contrib
                );
            }
        } else {
            for (name, contrib) in sorted_explanations.iter().take(4) {
                println!(
                    "│ \u{2022} {:<40} {:>+7.1}           │",
                    name,
                    contrib
                );
            }
        }

        println!("│                                                          │");

        println!(
            "│ Explanation: {}",
            generate_explanation(result)
        );

        println!("└──────────────────────────────────────────────────────────┘");
    } else {
        println!("│ Status:  Not an ELF binary                               │");
        println!("└──────────────────────────────────────────────────────────┘");
    }

    println!();
}

fn generate_explanation(result: &ScanResult) -> String {
    let parts: Vec<&str> = result
        .heuristic_results
        .iter()
        .take(3)
        .map(|hr| hr.name.as_str())
        .collect();

    if parts.is_empty() {
        "No suspicious indicators found.".into()
    } else {
        format!(
            "The binary has {} and combined with other indicators {}",
            parts.join(", "),
            if result.combined_score > 50.0 {
                "this strongly suggests malicious intent or heavy obfuscation."
            } else {
                "overall risk appears low."
            }
        )
    }
}

fn print_summary(results: &[ScanResult], verbose: bool) {
    let total = results.len();

    let elfs: Vec<&ScanResult> = results.iter().filter(|r| r.is_elf).collect();

    let malicious = elfs
        .iter()
        .filter(|r| r.classification == "Malicious")
        .count();

    let suspicious = elfs
        .iter()
        .filter(|r| r.classification == "Suspicious")
        .count();

    let benign = elfs
        .iter()
        .filter(|r| r.classification == "Benign")
        .count();

    let not_elf = total - elfs.len();

    println!(
        "Scan complete: {} files scanned, {} malicious, {} suspicious, {} benign{}",
        total,
        malicious,
        suspicious,
        benign,
        if not_elf > 0 && !verbose {
            format!(" ({} non-ELF skipped)", not_elf)
        } else {
            String::new()
        }
    );
}

fn main() {
    let args = Args::parse();

    if args.output == "text" {
        print_banner();
    }

    if args.path.is_empty() {
        eprintln!("Error: No paths specified. Use --help for usage.");
        std::process::exit(1);
    }

    let results = scanner::scan_paths(&args.path, args.recursive);

    if args.output == "json" {
        let json = serde_json::to_string_pretty(&results).unwrap_or_else(|e| {
            eprintln!("JSON serialization error: {}", e);
            std::process::exit(1);
        });

        println!("{}", json);
    } else {
        for result in &results {
            if result.is_elf || args.verbose {
                display_result_text(result, args.verbose);
            }
        }

        print_summary(&results, args.verbose);
    }
}
