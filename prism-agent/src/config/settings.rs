use std::{env, path::PathBuf};

use crate::bpf::BpfLoaderConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub bpf: BpfLoaderConfig,
}

impl AgentConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let object_path =
            env::var_os("PRISM_EBPF_OBJECT").map_or_else(default_ebpf_object_path, PathBuf::from);
        let pin_path = env::var_os("PRISM_BPF_PIN_PATH")
            .map_or_else(|| PathBuf::from("/sys/fs/bpf/prism"), PathBuf::from);

        Self {
            bpf: BpfLoaderConfig::new(object_path, pin_path),
        }
    }
}

fn default_ebpf_object_path() -> PathBuf {
    PathBuf::from("target/bpfel-unknown-none/release/prism-ebpf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_object_path_matches_makefile_target() {
        assert_eq!(
            default_ebpf_object_path(),
            PathBuf::from("target/bpfel-unknown-none/release/prism-ebpf")
        );
    }
}
