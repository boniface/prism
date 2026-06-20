use std::{path::PathBuf, str::FromStr};

use thiserror::Error;

pub const DEFAULT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const DEFAULT_TRACEPOINT_NAME: &str = "sys_enter_nanosleep";
pub const LIFECYCLE_MAP_NAME: &str = "LIFECYCLE_COUNTER";
pub const LIFECYCLE_PROGRAM_NAME: &str = "prism_lifecycle";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfLoaderConfig {
    pub object_path: PathBuf,
    pub pin_path: PathBuf,
    pub ephemeral: bool,
    pub tracepoint_category: String,
    pub tracepoint_name: String,
}

impl BpfLoaderConfig {
    #[must_use]
    pub fn new(object_path: PathBuf, pin_path: PathBuf) -> Self {
        Self {
            object_path,
            pin_path,
            ephemeral: true,
            tracepoint_category: DEFAULT_TRACEPOINT_CATEGORY.to_owned(),
            tracepoint_name: DEFAULT_TRACEPOINT_NAME.to_owned(),
        }
    }

    #[must_use]
    pub fn with_ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }
}

#[derive(Debug, Error)]
pub enum BpfLifecycleError {
    #[error("eBPF object path does not exist: {0}")]
    MissingObject(PathBuf),
    #[error("eBPF program not found: {0}")]
    MissingProgram(&'static str),
    #[error("eBPF map not found: {0}")]
    MissingMap(&'static str),
    #[error("eBPF lifecycle proof requires Linux")]
    UnsupportedPlatform,
    #[cfg(target_os = "linux")]
    #[error("failed to load eBPF object")]
    LoadObject(#[source] aya::EbpfError),
    #[cfg(target_os = "linux")]
    #[error("failed to load or attach eBPF program")]
    Program(#[from] aya::programs::ProgramError),
    #[cfg(target_os = "linux")]
    #[error("failed to access eBPF map")]
    Map(#[from] aya::maps::MapError),
}

#[cfg(target_os = "linux")]
mod linux {
    use aya::{Ebpf, maps::Array, programs::TracePoint};

    use super::{BpfLifecycleError, BpfLoaderConfig, LIFECYCLE_MAP_NAME, LIFECYCLE_PROGRAM_NAME};

    pub struct LoadedBpf {
        ebpf: Ebpf,
    }

    impl LoadedBpf {
        /// Loads the eBPF lifecycle proof program and attaches it to the
        /// configured tracepoint.
        ///
        /// # Errors
        ///
        /// Returns an error when the object file is missing, the object cannot
        /// be loaded, the program or map cannot be found, or attachment fails.
        pub fn load(config: &BpfLoaderConfig) -> Result<Self, BpfLifecycleError> {
            if !config.object_path.exists() {
                return Err(BpfLifecycleError::MissingObject(config.object_path.clone()));
            }

            let mut ebpf =
                Ebpf::load_file(&config.object_path).map_err(BpfLifecycleError::LoadObject)?;
            attach_lifecycle_program(&mut ebpf, config)?;
            initialize_lifecycle_map(&mut ebpf)?;

            Ok(Self { ebpf })
        }

        pub fn shutdown(self) {
            drop(self.ebpf);
        }
    }

    fn attach_lifecycle_program(
        ebpf: &mut Ebpf,
        config: &BpfLoaderConfig,
    ) -> Result<(), BpfLifecycleError> {
        let program = ebpf
            .program_mut(LIFECYCLE_PROGRAM_NAME)
            .ok_or(BpfLifecycleError::MissingProgram(LIFECYCLE_PROGRAM_NAME))?;
        let tracepoint: &mut TracePoint = program.try_into()?;
        tracepoint.load()?;
        tracepoint.attach(&config.tracepoint_category, &config.tracepoint_name)?;
        Ok(())
    }

    fn initialize_lifecycle_map(ebpf: &mut Ebpf) -> Result<(), BpfLifecycleError> {
        let map = ebpf
            .map_mut(LIFECYCLE_MAP_NAME)
            .ok_or(BpfLifecycleError::MissingMap(LIFECYCLE_MAP_NAME))?;
        let mut lifecycle_counter = Array::<_, u64>::try_from(map)?;
        lifecycle_counter.set(0, 0, 0)?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod non_linux {
    use super::{BpfLifecycleError, BpfLoaderConfig};

    #[derive(Debug)]
    pub struct LoadedBpf;

    impl LoadedBpf {
        /// Reports that the eBPF lifecycle proof cannot run on non-Linux hosts.
        ///
        /// # Errors
        ///
        /// Always returns [`BpfLifecycleError::UnsupportedPlatform`] outside
        /// Linux.
        pub fn load(_config: &BpfLoaderConfig) -> Result<Self, BpfLifecycleError> {
            Err(BpfLifecycleError::UnsupportedPlatform)
        }

        pub fn shutdown(self) {}
    }
}

#[cfg(target_os = "linux")]
pub use linux::LoadedBpf;
#[cfg(not(target_os = "linux"))]
pub use non_linux::LoadedBpf;

impl FromStr for BpfLoaderConfig {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(
            PathBuf::from(value),
            PathBuf::from("/sys/fs/bpf/prism"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn config_uses_expected_tracepoint_defaults() {
        let config = BpfLoaderConfig::new(PathBuf::from("object"), PathBuf::from("pins"));

        assert!(config.ephemeral);
        assert_eq!(config.tracepoint_category, "syscalls");
        assert_eq!(config.tracepoint_name, "sys_enter_nanosleep");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_object_returns_typed_error() {
        let config = BpfLoaderConfig::new(
            PathBuf::from("/tmp/prism-missing-ebpf-object"),
            PathBuf::from("/tmp/prism-pins"),
        );

        let result = LoadedBpf::load(&config);

        assert!(matches!(result, Err(BpfLifecycleError::MissingObject(_))));
    }
}
