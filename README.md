# 🛡️ RustELF-AV

`RustELF-AV` is a fast, lightweight, and highly customizable command-line Anti-Virus (AV) scanner for Linux systems, written entirely in Rust. It specializes in parsing ELF binaries and detecting anomalies, known threats, and zero-day malware using a hybrid approach of **Heuristic Analysis** and **Machine Learning**.

Disclaimer: This is only a hobby project and I DON'T recommend this for malware analysis.

![Language: Rust](https://img.shields.io/badge/Language-Rust-000000?logo=rust&logoColor=red)
![Platform: Linux](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black)

---

## 🏗️ Project Architecture & Modules

The project is structured modularly to ensure high performance and easy maintainability:

* **`main.rs`**: Entry point. Handles CLI arguments, user configurations, and orchestrates the scanning pipeline.
* **`scanner.rs`**: Directory traversal engine. Uses `walkdir` to efficiently discover ELF binaries across the filesystem.
* **`features.rs`**: Binary extraction layer. Leverages `goblin` to safely parse ELF headers, sections, and symbols to build feature vectors.
* **`heuristics.rs`**: Rule-based detection engine. Analyzes static anomalies, suspicious syscalls, and entry-point deviations.
* **`classifier.rs`**: Machine Learning inference module. Classifies extracted feature vectors to detect zero-day or heavily obfuscated malware.

---

## ✨ Features

* **🦀 Powered by Rust & Goblin:** Blazing-fast execution, zero-cost abstractions, and memory safety.
* **🧠 Hybrid Detection:** Combined power of heuristic rule matching and statistical ML classification.
* **🎛️ Highly Customizable:** Fully adjustable detection thresholds. Devs can tweak weights inside the classifier or add custom heuristic rules easily.
* **📊 Structured Output:** Ready to be paired with `serde_json` for structured telemetry output (perfect for SIEM integration).

---

## 🛠️ Installation & Build

Ensure you have Rust and `cargo` installed on your Linux machine. Please know that this is only a hobby project.

```bash
# 1. Clone the repository
git clone https://github.com/raven0-ya/RustELF-AV.git

# 2. Change into the newly created directory
cd RustELF-AV

# 3. Build the Rust project
cargo build --release
```

---

## ✅ How to Use

```bash
./target/release/elf-scanner --help
```
