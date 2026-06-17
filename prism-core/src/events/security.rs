use bytemuck::{Pod, Zeroable};

pub const COMM_LEN: usize = 16;
pub const EXE_PATH_LEN: usize = 128;

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

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn process_exec_event_has_stable_layout() {
        assert_eq!(size_of::<ProcessExecEvent>(), 184);
        assert_eq!(align_of::<ProcessExecEvent>(), 8);
    }
}
