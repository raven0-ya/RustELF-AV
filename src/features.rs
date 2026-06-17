use std::collections::HashMap;

use goblin::elf::Elf;

#[derive(Debug, Clone, Default)]
pub struct ElfFeatures {
    pub num_sections: f64,
    pub has_wx_section: bool,
    pub has_executable_stack: bool,
    pub text_entropy: f64,
    pub overall_entropy: f64,
    pub suspicious_strings: Vec<String>,
    pub num_suspicious_syscalls: usize,
    pub has_overlay: bool,
    pub overlay_entropy: f64,
    pub entry_in_header: bool,
    pub num_section_anomalies: usize,
    pub is_pie: bool,
    pub has_rpath: bool,
    pub suspicious_section_names: bool,
    pub unusual_ehdr_section_count: bool,
    pub has_dt_needed: bool,
    pub file_size: u64,
    pub interp_section: Option<String>,
    pub is_stripped: bool,
    pub has_compiler_fingerprints: bool,
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let len = data.len() as f64;
    let mut freq = HashMap::new();
    for &byte in data {
        *freq.entry(byte).or_insert(0u64) += 1;
    }
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for &byte in data {
        if byte >= 0x20 && byte <= 0x7e {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }
    strings
}

pub fn find_suspicious_strings(strings: &[String]) -> Vec<String> {
    let patterns = [
        "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "sh -c", "bash -c",
        "setuid", "setgid", "/etc/shadow", "/etc/sudoers",
        "/etc/init.d", "/etc/systemd", "/etc/cron", "/etc/rc", "crontab", "systemctl",
        "connect(", "socket(", "bind(", "listen(", "accept(", "AF_INET", "SOCK_STREAM", "INADDR_ANY",
        "execve(", "execvp(", "clone(", "ptrace", "PTRACE_TRACEME", "SIGTRAP",
        "mprotect", "PROT_EXEC", "PROT_READ|PROT_WRITE",
        "/tmp/", "unlink(", "creat(",
        "xor", "rc4", "aes", "crypt", "decrypt", "encrypt",
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PR_SET_DUMPABLE",
    ];
    let mut found = Vec::new();
    for s in strings {
        for pattern in &patterns {
            if s.contains(pattern) {
                found.push(s.clone());
                break;
            }
        }
    }
    found
}

pub fn find_suspicious_imports(
    dynsyms: &goblin::elf::Symtab,
    dynstr: &goblin::strtab::Strtab,
) -> Vec<String> {
    let suspicious = [
        "system", "ptrace", "mprotect", "clone",
        "popen", "dlopen", "dlsym", "socket", "connect", "bind", "listen", "accept",
        "sendto", "recvfrom", "vfork", "daemon", "setuid",
        "setgid", "geteuid", "getegid",
    ];
    let mut found = Vec::new();
    for sym in dynsyms.iter() {
        if let Some(name) = dynstr.get_at(sym.st_name as usize) {
            if suspicious.contains(&name) {
                found.push(name.to_string());
            }
        }
    }
    found
}

fn contains_word(name: &str, pat: &str) -> bool {
    if let Some(i) = name.find(pat) {
        let before = i == 0 || !name.as_bytes()[i - 1].is_ascii_alphanumeric();
        let after = i + pat.len() >= name.len()
            || !name.as_bytes()[i + pat.len()].is_ascii_alphanumeric();
        before && after
    } else {
        false
    }
}

pub fn has_suspicious_section_names(
    shdr: &[goblin::elf::SectionHeader],
    strtab: &goblin::strtab::Strtab,
) -> bool {
    let exact = ["UPX0", "UPX1", "UPX2"];
    let substrings = ["pack", "crypt", "protect"];
    let word_match = ["pe", "vmp"];
    for section in shdr {
        if let Some(name) = strtab.get_at(section.sh_name as usize) {
            if exact.contains(&name) {
                return true;
            }
            for pat in &substrings {
                if name.contains(pat) {
                    return true;
                }
            }
            for pat in &word_match {
                if contains_word(name, pat) {
                    return true;
                }
            }
        }
    }
    false
}

pub fn extract_features(data: &[u8]) -> Result<ElfFeatures, String> {
    let elf = Elf::parse(data).map_err(|e| format!("ELF parse error: {}", e))?;

    let num_sections = elf.section_headers.len() as f64;

    let has_wx_section = elf.section_headers.iter().any(|sh| {
        let wx = goblin::elf::section_header::SHF_WRITE as u64
            | goblin::elf::section_header::SHF_EXECINSTR as u64;
        sh.sh_flags & wx == wx
    });

    let gnu_stack = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK);
    let has_executable_stack = match gnu_stack {
        Some(ph) => ph.p_flags & goblin::elf::program_header::PF_X != 0,
        None => true,
    };

    let text_data = elf
        .section_headers
        .iter()
        .find(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name as usize) {
                name == ".text"
            } else {
                false
            }
        })
        .and_then(|sh| {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            if end <= data.len() {
                Some(&data[start..end])
            } else {
                None
            }
        });
    let text_entropy = text_data.map(shannon_entropy).unwrap_or(0.0);

    let overall_entropy = shannon_entropy(data);

    let strings = extract_strings(data, 6);
    let suspicious_strings = find_suspicious_strings(&strings);

    let suspicious_imports = find_suspicious_imports(&elf.dynsyms, &elf.dynstrtab);
    let num_suspicious_syscalls = suspicious_imports.len();

    let max_section_end = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_type != goblin::elf::section_header::SHT_NOBITS)
        .filter_map(|sh| sh.sh_offset.checked_add(sh.sh_size))
        .map(|end| end as usize)
        .max()
        .unwrap_or(0);

    let max_ph_end = elf
        .program_headers
        .iter()
        .filter(|ph| {
            ph.p_type == goblin::elf::program_header::PT_LOAD && ph.p_filesz > 0
        })
        .filter_map(|ph| ph.p_offset.checked_add(ph.p_filesz))
        .map(|end| end as usize)
        .max()
        .unwrap_or(0);

    let shdr_table_end = elf.header.e_shoff as usize
        + elf.header.e_shnum as usize * elf.header.e_shentsize as usize;

    let overlay_start = max_section_end.max(max_ph_end).max(shdr_table_end);
    let has_overlay = overlay_start < data.len();
    let overlay_entropy = if has_overlay {
        shannon_entropy(&data[overlay_start..])
    } else {
        0.0
    };

    let entry_in_header = elf.entry <= 0x100;

    let mut num_section_anomalies = 0;
    for sh in &elf.section_headers {
        if sh.sh_size > data.len() as u64 {
            num_section_anomalies += 1;
        }
        if sh.sh_type != goblin::elf::section_header::SHT_NOBITS && sh.sh_offset > data.len() as u64 {
            num_section_anomalies += 1;
        }
        if sh.sh_addr < 64 && sh.sh_size > 0
            && sh.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0
        {
            num_section_anomalies += 1;
        }
        if sh.sh_type == goblin::elf::section_header::SHT_NULL && sh.sh_size > 0 {
            num_section_anomalies += 1;
        }
        if sh.sh_addralign > 0x10000 {
            num_section_anomalies += 1;
        }
    }

    let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    let has_rpath = !elf.rpaths.is_empty() || !elf.runpaths.is_empty();

    let suspicious_section_names =
        has_suspicious_section_names(&elf.section_headers, &elf.shdr_strtab);

    let section_count = elf.section_headers.len();
    let unusual_ehdr_section_count = section_count < 5 || section_count > 60;

    let has_dt_needed = !elf.libraries.is_empty();

    let file_size = data.len() as u64;

    let interp_section = elf.interpreter.map(|s| s.to_string());

    let compiler_strings = [
        "GCC: (", "(GCC)", "clang version", "Free Software Foundation",
        "LLVM", "ubuntu", "debian", "Red Hat", "Fedora",
    ];
    let has_compiler_fingerprints = strings.iter().any(|s| {
        compiler_strings.iter().any(|pat| s.contains(pat))
    });

    let has_symtab = elf.section_headers.iter().any(|sh| {
        if sh.sh_type == goblin::elf::section_header::SHT_SYMTAB {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name as usize) {
                return name == ".symtab";
            }
        }
        false
    });
    let is_stripped = !has_symtab;

    Ok(ElfFeatures {
        num_sections,
        has_wx_section,
        has_executable_stack,
        text_entropy,
        overall_entropy,
        suspicious_strings,
        num_suspicious_syscalls,
        has_overlay,
        overlay_entropy,
        entry_in_header,
        num_section_anomalies,
        is_pie,
        has_rpath,
        suspicious_section_names,
        unusual_ehdr_section_count,
        has_dt_needed,
        file_size,
        interp_section,
        is_stripped,
        has_compiler_fingerprints,
    })
}
