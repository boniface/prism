#![no_main]

use libfuzzer_sys::fuzz_target;
use prism_agent::telemetry::parse_redis_metadata;

fuzz_target!(|data: &[u8]| {
    let _ = parse_redis_metadata(data);
});
