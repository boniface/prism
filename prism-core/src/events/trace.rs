use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
pub struct SpanEvent {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: [u8; 8],
    pub cgroup_id: u64,
    pub start_ns: u64,
    pub duration_ns: u64,
    pub http_status: u16,
    pub protocol: u8,
    pub reserved: [u8; 5],
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn span_event_has_stable_layout() {
        assert_eq!(size_of::<SpanEvent>(), 64);
        assert_eq!(align_of::<SpanEvent>(), 8);
    }
}
