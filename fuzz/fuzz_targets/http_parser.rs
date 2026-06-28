#![no_main]

use libfuzzer_sys::fuzz_target;
use prism_agent::telemetry::parse_http1_metadata;

fuzz_target!(|data: &[u8]| {
    let _ = parse_http1_metadata(data);
});
