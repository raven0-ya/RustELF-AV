use serde::Serialize;

use crate::features::ElfFeatures;

#[derive(Debug, Clone, Serialize)]
pub struct HeuristicResult {
    pub name: String,
    pub score: f64,
    pub detail: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    #[allow(dead_code)]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

pub fn run_heuristics(features: &ElfFeatures) -> Vec<HeuristicResult> {
    let mut results = Vec::new();

    if features.has_wx_section {
        results.push(HeuristicResult {
            name: "Writable + Executable Section".into(),
            score: 40.0,
            detail: "Section has both writable and executable permissions".into(),
            severity: Severity::Critical,
        });
    }

    if features.has_executable_stack {
        results.push(HeuristicResult {
            name: "Executable Stack".into(),
            score: 25.0,
            detail: "Stack is executable or GNU_STACK missing".into(),
            severity: Severity::High,
        });
    }

    if features.text_entropy > 6.5 {
        let capped_entropy = features.text_entropy.min(8.0);
        let score = 25.0 * ((capped_entropy - 6.5) / 1.5);
        results.push(HeuristicResult {
            name: "High Text Section Entropy".into(),
            score: score.min(25.0),
            detail: format!("Likely packed/encrypted (entropy: {:.2})", features.text_entropy),
            severity: Severity::High,
        });
    }

    if features.overall_entropy > 7.0 {
        let capped_entropy = features.overall_entropy.min(8.0);
        let score = 20.0 * ((capped_entropy - 7.0) / 1.0);
        results.push(HeuristicResult {
            name: "High Overall Entropy".into(),
            score: score.min(20.0),
            detail: format!(
                "Overall file entropy unusually high ({:.2})",
                features.overall_entropy
            ),
            severity: Severity::Medium,
        });
    }

    if !features.suspicious_strings.is_empty() {
        let count = features.suspicious_strings.len();
        let score = (count as f64 * 3.0).min(25.0);
        let samples: Vec<&str> = features
            .suspicious_strings
            .iter()
            .take(3)
            .map(|s| s.as_str())
            .collect();
        results.push(HeuristicResult {
            name: "Suspicious Strings Found".into(),
            score,
            detail: format!(
                "Found {} suspicious strings (e.g., {})",
                count,
                samples.join(", ")
            ),
            severity: Severity::Medium,
        });
    }

    if features.num_suspicious_syscalls > 0 {
        let count = features.num_suspicious_syscalls;
        let score = (count as f64 * 2.0).min(20.0);
        results.push(HeuristicResult {
            name: "Suspicious Imports".into(),
            score,
            detail: format!("Found {} suspicious imported functions", count),
            severity: Severity::Medium,
        });
    }

    if features.has_overlay && features.overlay_entropy > 6.0 {
        results.push(HeuristicResult {
            name: "Overlay Data Present".into(),
            score: 15.0,
            detail: format!(
                "Appended data with high entropy ({:.2})",
                features.overlay_entropy
            ),
            severity: Severity::Low,
        });
    }

    if features.entry_in_header {
        results.push(HeuristicResult {
            name: "Entry Point Anomaly".into(),
            score: 35.0,
            detail: "Entry point in header region".into(),
            severity: Severity::Critical,
        });
    }

    if features.num_section_anomalies > 0 {
        let count = features.num_section_anomalies;
        let score = (count as f64 * 10.0).min(30.0);
        results.push(HeuristicResult {
            name: "Section Anomalies".into(),
            score,
            detail: format!("Found {} section anomalies", count),
            severity: Severity::Medium,
        });
    }

    if features.suspicious_section_names {
        results.push(HeuristicResult {
            name: "Packer Indicators".into(),
            score: 30.0,
            detail: "Sections named like packed binary".into(),
            severity: Severity::High,
        });
    }

    if features.has_rpath {
        results.push(HeuristicResult {
            name: "Suspicious RPATH".into(),
            score: 10.0,
            detail: "RPATH/RUNPATH set - potential for library hijacking".into(),
            severity: Severity::Low,
        });
    }

    if features.is_stripped && features.num_suspicious_syscalls > 3 {
        results.push(HeuristicResult {
            name: "Stripped with Suspicious Imports".into(),
            score: 15.0,
            detail: format!("Stripped binary with {} unusual imports", features.num_suspicious_syscalls),
            severity: Severity::Medium,
        });
    }

    if features.unusual_ehdr_section_count {
        results.push(HeuristicResult {
            name: "Unusual Section Count".into(),
            score: 10.0,
            detail: format!(
                "Abnormal number of sections ({})",
                features.num_sections
            ),
            severity: Severity::Low,
        });
    }

    if let Some(ref interp) = features.interp_section {
        if !interp.starts_with("/lib64/ld-linux-") && !interp.starts_with("/lib/ld-linux-") {
            results.push(HeuristicResult {
                name: "Unusual Interpreter".into(),
                score: 15.0,
                detail: format!("Unusual interpreter: {}", interp),
                severity: Severity::Low,
            });
        }
    }

    results
}
