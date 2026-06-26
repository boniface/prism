use std::{path::PathBuf, str::FromStr};

use thiserror::Error;

pub const FILE_OPEN_PROGRAM_NAME: &str = "prism_file_open";
pub const FILE_ACCESS_RING_BUF_NAME: &str = "FILE_ACCESS_EVENTS";
pub const DEFAULT_TRACEPOINT_CATEGORY: &str = "syscalls";
pub const DEFAULT_TRACEPOINT_NAME: &str = "sys_enter_nanosleep";
pub const CGROUP_METRICS_MAP_NAME: &str = "CGROUP_METRICS";
pub const CPU_SCHED_PROGRAM_NAME: &str = "prism_sched_switch";
pub const CPU_SCHED_TRACEPOINT_CATEGORY: &str = "sched";
pub const CPU_SCHED_TRACEPOINT_NAME: &str = "sched_switch";
pub const EGRESS_TC_PROGRAM_NAME: &str = "prism_tc_egress";
pub const EXECVE_PROGRAM_NAME: &str = "prism_execve";
pub const INGRESS_TC_PROGRAM_NAME: &str = "prism_tc_ingress";
pub const LIFECYCLE_MAP_NAME: &str = "LIFECYCLE_COUNTER";
pub const LIFECYCLE_PROGRAM_NAME: &str = "prism_lifecycle";
pub const METRIC_RING_DROPS_MAP_NAME: &str = "METRIC_RING_DROPS";
pub const TCP_CONNECT_PROGRAM_NAME: &str = "prism_tcp_connect";
pub const NETWORK_SECURITY_RING_BUF_NAME: &str = "NETWORK_SECURITY_EVENTS";

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
    use aya::{
        Ebpf,
        maps::Array,
        maps::HashMap as BpfHashMap,
        programs::{SchedClassifier, TcAttachType, TracePoint},
    };
    use prism_core::events::metrics::METRIC_COUNTER_FIELDS;

    use super::{
        BpfLifecycleError, BpfLoaderConfig, CGROUP_METRICS_MAP_NAME, CPU_SCHED_PROGRAM_NAME,
        CPU_SCHED_TRACEPOINT_CATEGORY, CPU_SCHED_TRACEPOINT_NAME, EGRESS_TC_PROGRAM_NAME,
        EXECVE_PROGRAM_NAME, FILE_OPEN_PROGRAM_NAME, INGRESS_TC_PROGRAM_NAME, LIFECYCLE_MAP_NAME,
        LIFECYCLE_PROGRAM_NAME, METRIC_RING_DROPS_MAP_NAME, TCP_CONNECT_PROGRAM_NAME,
    };
    use crate::metrics::MetricSnapshot;

    pub struct LoadedBpf {
        ebpf: Ebpf,
    }

    impl LoadedBpf {
        /// Loads the eBPF programs and attaches them to their tracepoints.
        ///
        /// # Errors
        ///
        /// Returns an error when the object file is missing, the object cannot
        /// be loaded, the program or map cannot be found, or attachment fails.
        pub fn load(config: &BpfLoaderConfig) -> Result<Self, BpfLifecycleError> {
            Self::load_inner(config, &[])
        }

        /// Loads the eBPF programs and attaches optional TC network hooks.
        ///
        /// # Errors
        ///
        /// Returns an error when the object file is missing, programs or maps
        /// cannot be loaded, or TC attachment fails.
        pub fn load_with_tc_hooks(
            config: &BpfLoaderConfig,
            interfaces: &[String],
        ) -> Result<Self, BpfLifecycleError> {
            Self::load_inner(config, interfaces)
        }

        fn load_inner(
            config: &BpfLoaderConfig,
            tc_interfaces: &[String],
        ) -> Result<Self, BpfLifecycleError> {
            if !config.object_path.exists() {
                return Err(BpfLifecycleError::MissingObject(config.object_path.clone()));
            }

            let mut ebpf =
                Ebpf::load_file(&config.object_path).map_err(BpfLifecycleError::LoadObject)?;
            attach_lifecycle_program(&mut ebpf, config)?;
            attach_tracepoint_program(
                &mut ebpf,
                CPU_SCHED_PROGRAM_NAME,
                CPU_SCHED_TRACEPOINT_CATEGORY,
                CPU_SCHED_TRACEPOINT_NAME,
            )?;
            attach_execve_program(&mut ebpf)?;
            attach_file_open_program(&mut ebpf)?;
            attach_tcp_connect_program(&mut ebpf)?;
            attach_tc_program(
                &mut ebpf,
                INGRESS_TC_PROGRAM_NAME,
                tc_interfaces,
                TcAttachType::Ingress,
            )?;
            attach_tc_program(
                &mut ebpf,
                EGRESS_TC_PROGRAM_NAME,
                tc_interfaces,
                TcAttachType::Egress,
            )?;
            initialize_lifecycle_map(&mut ebpf)?;

            Ok(Self { ebpf })
        }

        pub fn shutdown(self) {
            drop(self.ebpf);
        }

        pub fn ebpf_mut(&mut self) -> &mut Ebpf {
            &mut self.ebpf
        }

        /// Reads a point-in-time copy of the kernel per-cgroup metric map.
        ///
        /// # Errors
        ///
        /// Returns an error when the metric map is missing or cannot be read.
        pub fn metric_snapshots(&self) -> Result<Vec<MetricSnapshot>, BpfLifecycleError> {
            let map = self
                .ebpf
                .map(CGROUP_METRICS_MAP_NAME)
                .ok_or(BpfLifecycleError::MissingMap(CGROUP_METRICS_MAP_NAME))?;
            let metrics = BpfHashMap::<_, u64, [u64; METRIC_COUNTER_FIELDS]>::try_from(map)?;

            metrics
                .iter()
                .map(|entry| {
                    entry
                        .map(|(cgroup_id, raw)| MetricSnapshot::from_raw(cgroup_id, raw))
                        .map_err(BpfLifecycleError::Map)
                })
                .collect()
        }
    }

    fn attach_lifecycle_program(
        ebpf: &mut Ebpf,
        config: &BpfLoaderConfig,
    ) -> Result<(), BpfLifecycleError> {
        let program = ebpf
            .program_mut(LIFECYCLE_PROGRAM_NAME)
            .ok_or(BpfLifecycleError::MissingProgram(LIFECYCLE_PROGRAM_NAME))?;
        attach_tracepoint(
            program,
            &config.tracepoint_category,
            &config.tracepoint_name,
        )
    }

    fn attach_tracepoint_program(
        ebpf: &mut Ebpf,
        program_name: &'static str,
        category: &str,
        name: &str,
    ) -> Result<(), BpfLifecycleError> {
        let program = ebpf
            .program_mut(program_name)
            .ok_or(BpfLifecycleError::MissingProgram(program_name))?;
        attach_tracepoint(program, category, name)
    }

    fn attach_tracepoint(
        program: &mut aya::programs::Program,
        category: &str,
        name: &str,
    ) -> Result<(), BpfLifecycleError> {
        let tracepoint: &mut TracePoint = program.try_into()?;
        tracepoint.load()?;
        tracepoint.attach(category, name)?;
        Ok(())
    }

    fn attach_execve_program(ebpf: &mut Ebpf) -> Result<(), BpfLifecycleError> {
        let program = ebpf
            .program_mut(EXECVE_PROGRAM_NAME)
            .ok_or(BpfLifecycleError::MissingProgram(EXECVE_PROGRAM_NAME))?;
        let tracepoint: &mut TracePoint = program.try_into()?;
        tracepoint.load()?;
        tracepoint.attach("syscalls", "sys_enter_execve")?;
        Ok(())
    }

    fn attach_file_open_program(ebpf: &mut Ebpf) -> Result<(), BpfLifecycleError> {
        let program = ebpf
            .program_mut(FILE_OPEN_PROGRAM_NAME)
            .ok_or(BpfLifecycleError::MissingProgram(FILE_OPEN_PROGRAM_NAME))?;
        let tracepoint: &mut TracePoint = program.try_into()?;
        tracepoint.load()?;
        tracepoint.attach("syscalls", "sys_enter_openat")?;
        Ok(())
    }

    fn attach_tcp_connect_program(ebpf: &mut Ebpf) -> Result<(), BpfLifecycleError> {
        let program = ebpf
            .program_mut(TCP_CONNECT_PROGRAM_NAME)
            .ok_or(BpfLifecycleError::MissingProgram(TCP_CONNECT_PROGRAM_NAME))?;
        let tracepoint: &mut TracePoint = program.try_into()?;
        tracepoint.load()?;
        tracepoint.attach("syscalls", "sys_enter_connect")?;
        Ok(())
    }

    fn initialize_lifecycle_map(ebpf: &mut Ebpf) -> Result<(), BpfLifecycleError> {
        let map = ebpf
            .map_mut(LIFECYCLE_MAP_NAME)
            .ok_or(BpfLifecycleError::MissingMap(LIFECYCLE_MAP_NAME))?;
        let mut lifecycle_counter = Array::<_, u64>::try_from(map)?;
        lifecycle_counter.set(0, 0, 0)?;

        let map = ebpf
            .map_mut(METRIC_RING_DROPS_MAP_NAME)
            .ok_or(BpfLifecycleError::MissingMap(METRIC_RING_DROPS_MAP_NAME))?;
        let mut metric_ring_drops = Array::<_, u64>::try_from(map)?;
        metric_ring_drops.set(0, 0, 0)?;
        Ok(())
    }

    fn attach_tc_program(
        ebpf: &mut Ebpf,
        program_name: &'static str,
        interfaces: &[String],
        attach_type: TcAttachType,
    ) -> Result<(), BpfLifecycleError> {
        if interfaces.is_empty() {
            return Ok(());
        }

        let program = ebpf
            .program_mut(program_name)
            .ok_or(BpfLifecycleError::MissingProgram(program_name))?;
        let classifier: &mut SchedClassifier = program.try_into()?;
        classifier.load()?;
        for interface in interfaces {
            classifier.attach(interface, attach_type)?;
        }
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
        /// Always returns [`BpfLifecycleError::UnsupportedPlatform`] outside Linux.
        pub fn load(_config: &BpfLoaderConfig) -> Result<Self, BpfLifecycleError> {
            Err(BpfLifecycleError::UnsupportedPlatform)
        }

        /// Reports that eBPF TC hooks cannot run on non-Linux hosts.
        ///
        /// # Errors
        ///
        /// Always returns [`BpfLifecycleError::UnsupportedPlatform`] outside Linux.
        pub fn load_with_tc_hooks(
            _config: &BpfLoaderConfig,
            _interfaces: &[String],
        ) -> Result<Self, BpfLifecycleError> {
            Err(BpfLifecycleError::UnsupportedPlatform)
        }

        pub fn shutdown(self) {}

        /// Reports that kernel metric maps cannot be read on non-Linux hosts.
        ///
        /// # Errors
        ///
        /// Always returns [`BpfLifecycleError::UnsupportedPlatform`] outside Linux.
        pub fn metric_snapshots(
            &self,
        ) -> Result<Vec<crate::metrics::MetricSnapshot>, BpfLifecycleError> {
            Err(BpfLifecycleError::UnsupportedPlatform)
        }
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

    #[test]
    fn cpu_scheduler_tracepoint_uses_sched_switch() {
        assert_eq!(CPU_SCHED_PROGRAM_NAME, "prism_sched_switch");
        assert_eq!(CPU_SCHED_TRACEPOINT_CATEGORY, "sched");
        assert_eq!(CPU_SCHED_TRACEPOINT_NAME, "sched_switch");
    }

    #[test]
    fn network_tc_program_names_match_kernel_symbols() {
        assert_eq!(INGRESS_TC_PROGRAM_NAME, "prism_tc_ingress");
        assert_eq!(EGRESS_TC_PROGRAM_NAME, "prism_tc_egress");
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
