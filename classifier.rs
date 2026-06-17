use crate::features::ElfFeatures;

pub struct Model {
    pub weights: Vec<f64>,
    pub feature_names: Vec<String>,
    pub bias: f64,
    pub threshold: f64,
    pub high_threshold: f64,
}

impl Model {
    pub fn default() -> Self {
        Model {
            weights: vec![
                2.0, 40.0, 25.0, 4.0, 3.0, 1.0, 1.5, 15.0, 2.0, 35.0, 10.0, -2.0, 10.0, 30.0,
                10.0, -5.0, 5.0, -15.0,
            ],
            feature_names: vec![
                "num_sections".into(),
                "has_wx_section".into(),
                "has_executable_stack".into(),
                "text_entropy".into(),
                "overall_entropy".into(),
                "num_suspicious_strings".into(),
                "num_suspicious_syscalls".into(),
                "has_overlay".into(),
                "overlay_entropy".into(),
                "entry_in_header".into(),
                "num_section_anomalies".into(),
                "is_pie".into(),
                "has_rpath".into(),
                "suspicious_section_names".into(),
                "unusual_ehdr_section_count".into(),
                "has_dt_needed".into(),
                "file_size_anomaly".into(),
                "compiler_fingerprints".into(),
            ],
            bias: 0.0,
            threshold: 45.0,
            high_threshold: 70.0,
        }
    }

    fn to_feature_vector(&self, features: &ElfFeatures) -> Vec<f64> {
        let section_anomaly = if features.num_sections < 20.0 {
            (20.0 - features.num_sections) / 20.0
        } else if features.num_sections > 40.0 {
            (features.num_sections - 40.0) / 40.0
        } else {
            0.0
        };

        let file_size_anomaly = (features.file_size as f64 / 100_000_000.0).min(1.0);

        vec![
            section_anomaly,
            if features.has_wx_section { 1.0 } else { 0.0 },
            if features.has_executable_stack { 1.0 } else { 0.0 },
            features.text_entropy,
            features.overall_entropy,
            (features.suspicious_strings.len() as f64).min(15.0),
            (features.num_suspicious_syscalls as f64).min(10.0),
            if features.has_overlay { 1.0 } else { 0.0 },
            features.overlay_entropy,
            if features.entry_in_header { 1.0 } else { 0.0 },
            (features.num_section_anomalies as f64).min(5.0),
            if features.is_pie { 1.0 } else { 0.0 },
            if features.has_rpath { 1.0 } else { 0.0 },
            if features.suspicious_section_names {
                1.0
            } else {
                0.0
            },
            if features.unusual_ehdr_section_count {
                1.0
            } else {
                0.0
            },
            if features.has_dt_needed { 1.0 } else { 0.0 },
            file_size_anomaly,
            if features.has_compiler_fingerprints {
                1.0
            } else {
                0.0
            },
        ]
    }

    pub fn predict(&self, features: &ElfFeatures) -> f64 {
        let fv = self.to_feature_vector(features);
        let mut score = self.bias;
        for (i, &val) in fv.iter().enumerate() {
            score += self.weights[i] * val;
        }
        score.clamp(0.0, 100.0)
    }

    pub fn explain(&self, features: &ElfFeatures) -> Vec<(String, f64)> {
        let fv = self.to_feature_vector(features);
        let mut contributions = Vec::new();
        for (i, &val) in fv.iter().enumerate() {
            let contrib = self.weights[i] * val;
            if contrib.abs() > 0.01 {
                contributions.push((self.feature_names[i].clone(), contrib));
            }
        }
        contributions
    }

    pub fn classify(&self, score: f64) -> &'static str {
        if score >= self.high_threshold {
            "Malicious"
        } else if score >= self.threshold {
            "Suspicious"
        } else {
            "Benign"
        }
    }
}
