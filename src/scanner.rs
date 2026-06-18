use std::path::{Path, PathBuf};

use serde::Serialize;
use walkdir::WalkDir;

use crate::classifier::Model;
use crate::features::extract_features;
use crate::heuristics::{run_heuristics, HeuristicResult};

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub file_size: u64,
    pub is_elf: bool,
    pub heuristic_results: Vec<HeuristicResult>,
    pub heuristic_total: f64,
    pub heuristic_normalized: f64,
    pub ml_score: f64,
    pub combined_score: f64,
    pub classification: String,
    pub explanation_lines: Vec<(String, f64)>,
}

pub fn scan_file(path: &Path) -> Result<ScanResult, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;

    if data.len() < 4
        || data[0] != 0x7f
        || data[1] != b'E'
        || data[2] != b'L'
        || data[3] != b'F'
    {
        return Ok(ScanResult {
            path: path.to_path_buf(),
            file_size: data.len() as u64,
            is_elf: false,
            heuristic_results: Vec::new(),
            heuristic_total: 0.0,
            heuristic_normalized: 0.0,
            ml_score: 0.0,
            combined_score: 0.0,
            classification: "Not ELF".into(),
            explanation_lines: Vec::new(),
        });
    }

    let features = extract_features(&data)?;
    let model = Model::default();

    let heuristic_results = run_heuristics(&features);

    let heuristic_total: f64 = heuristic_results.iter().map(|r| r.score).sum();

    let heuristic_normalized = (heuristic_total / 3.5).min(100.0);

    let ml_score = model.predict(&features);

    let explanation_lines = model.explain(&features);

    let combined_score = 0.4 * heuristic_normalized + 0.6 * ml_score;

    let classification = model.classify(combined_score).to_string();

    Ok(ScanResult {
        path: path.to_path_buf(),
        file_size: data.len() as u64,
        is_elf: true,
        heuristic_results,
        heuristic_total,
        heuristic_normalized,
        ml_score,
        combined_score,
        classification,
        explanation_lines,
    })
}

pub fn scan_paths(paths: &[PathBuf], recursive: bool) -> Vec<ScanResult> {
    let mut results = Vec::new();

    for path in paths {
        if path.is_dir() {
            let walker = if recursive {
                WalkDir::new(path).into_iter()
            } else {
                WalkDir::new(path).max_depth(1).into_iter()
            };

            for entry in walker.filter_map(Result::ok) {
                if entry.file_type().is_file() {
                    match scan_file(entry.path()) {
                        Ok(r) => results.push(r),
                        Err(e) => eprintln!("Warning: {} - skipping", e),
                    }
                }
            }
        } else if path.is_file() {
            match scan_file(path) {
                Ok(r) => results.push(r),
                Err(e) => eprintln!("Warning: {} - skipping", e),
            }
        } else {
            eprintln!("Warning: {} does not exist - skipping", path.display());
        }
    }

    results
}
