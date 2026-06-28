#![no_main]

use libfuzzer_sys::fuzz_target;
use prism_agent::telemetry::parse_postgres_metadata;

fuzz_target!(|data: &[u8]| {
    let _ = parse_postgres_metadata(data);
});
