use bytemuck::{Pod, Zeroable};

pub const COMM_LEN: usize = 16;
pub const EXE_PATH_LEN: usize = 128;
pub const FILE_PATH_LEN: usize = 128;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
pub struct ProcessExecEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm_len: u16,
    pub exe_path_len: u16,
    pub reserved: [u8; 4],
    pub comm: [u8; COMM_LEN],
    pub exe_path: [u8; EXE_PATH_LEN],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
pub struct FileAccessEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub uid: u32,
    pub path_len: u16,
    pub reserved: [u8; 6],
    pub path: [u8; FILE_PATH_LEN],
}

/// Network connection open event captured from the kernel.
///
/// `dst_addr` holds an IPv4 address in network byte order stored in the
/// first four bytes. IPv6 support is deferred to a future phase.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
pub struct NetworkConnectionEvent {
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub uid: u32,
    /// Destination IPv4 address in network byte order.
    pub dst_addr: [u8; 4],
    /// Destination port in host byte order.
    pub dst_port: u16,
    pub comm_len: u16,
    pub comm: [u8; COMM_LEN],
    pub reserved: [u8; 8],
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn process_exec_event_has_stable_layout() {
        assert_eq!(size_of::<ProcessExecEvent>(), 184);
        assert_eq!(align_of::<ProcessExecEvent>(), 8);
    }

    #[test]
    fn file_access_event_has_stable_layout() {
        assert_eq!(size_of::<FileAccessEvent>(), 160);
        assert_eq!(align_of::<FileAccessEvent>(), 8);
    }

    #[test]
    fn network_connection_event_has_stable_layout() {
        assert_eq!(size_of::<NetworkConnectionEvent>(), 56);
        assert_eq!(align_of::<NetworkConnectionEvent>(), 8);
    }
}
