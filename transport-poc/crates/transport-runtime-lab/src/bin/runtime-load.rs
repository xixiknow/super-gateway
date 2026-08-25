#![forbid(unsafe_code)]

use std::{env, fs, path::PathBuf};
use transport_runtime_lab::run_mock_load;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args_os().nth(1).map_or_else(
        || PathBuf::from("var/e2e-v2/runtime-load.json"),
        PathBuf::from,
    );
    let report = run_mock_load(1_200, 2_500).await?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    println!(
        "mock load: sse={}/{}, peak={}, requests={}, rps={:.1}, unfinished={}",
        report.sse_connections_completed,
        report.sse_connections_requested,
        report.peak_sse_connections,
        report.short_requests_completed,
        report.measured_requests_per_second,
        report.unfinished_tasks
    );
    Ok(())
}
