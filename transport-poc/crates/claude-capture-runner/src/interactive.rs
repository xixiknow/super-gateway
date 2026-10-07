use super::{ChildProtocolSummary, ChildSummary};
use anyhow::{Context, Result, ensure};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::{
    io::{Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) async fn run(
    command: tokio::process::Command,
    prompt: String,
    timeout: Duration,
    captured: Arc<AtomicBool>,
    require_response: bool,
) -> Result<ChildSummary> {
    tokio::task::spawn_blocking(move || {
        let source = command.as_std();
        let mut launch = CommandBuilder::new(source.get_program());
        launch.args(source.get_args());
        if let Some(cwd) = source.get_current_dir() {
            launch.cwd(cwd);
        }
        for (key, value) in source.get_envs() {
            if let Some(value) = value {
                launch.env(key, value);
            } else {
                launch.env_remove(key);
            }
        }
        // This configuration exists only in the already isolated capture directory.
        if let Some((_, Some(config))) = source.get_envs().find(|(key, _)| *key == "CLAUDE_CONFIG_DIR") {
            let cwd = source
                .get_current_dir()
                .context("interactive capture cwd")?
                .to_string_lossy();
            let mut projects = serde_json::Map::new();
            projects.insert(cwd.into_owned(), serde_json::json!({"hasTrustDialogAccepted":true}));
            std::fs::write(
                std::path::Path::new(config).join(".claude.json"),
                serde_json::to_vec(&serde_json::json!({
                    "hasCompletedOnboarding":true, "theme":"dark", "projects":projects
                }))?,
            )?;
        }
        let pair = native_pty_system().openpty(PtySize {
            rows: 40,
            cols: 160,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut reader = pair.master.try_clone_reader()?;
        let mut writer = pair.master.take_writer()?;
        let mut child = pair.slave.spawn_command(launch)?;
        drop(pair.slave);
        let (sender, receiver) = std::sync::mpsc::sync_channel(64);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 8192];
            while let Ok(size) = reader.read(&mut buffer) {
                if size == 0 || sender.send(buffer[..size].to_vec()).is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        let mut screen = String::new();
        let mut terminal = vt100::Parser::new(40, 160, 0);
        let mut total = 0;
        let mut prompt_sent = false;
        let mut trust_answered = false;
        let mut completed_at = None;
        let mut success = false;
        while start.elapsed() < timeout {
            if let Ok(bytes) = receiver.recv_timeout(Duration::from_millis(100)) {
                total += bytes.len();
                terminal.process(&bytes);
                screen = terminal.screen().contents();
                if bytes.windows(4).any(|part| part == b"\x1b[6n") {
                    writer.write_all(b"\x1b[1;1R")?;
                    writer.flush()?;
                }
                if screen.len() > 256 * 1024 {
                    screen.clear();
                }
            }
            // Only answer the trust prompt for the temporary, empty capture workspace.
            if !trust_answered && screen.contains("trust this folder") {
                writer.write_all(b"\r")?;
                writer.flush()?;
                trust_answered = true;
                eprintln!("interactive capture: accepted isolated workspace trust");
            }
            if !prompt_sent && screen.contains("Welcome") && screen.contains('>') {
                // Keep the expected mock response out of the echoed prompt.
                let input = if require_response {
                    "Reply briefly."
                } else {
                    prompt.as_str()
                };
                writer.write_all(input.as_bytes())?;
                writer.flush()?;
                std::thread::sleep(Duration::from_millis(300));
                writer.write_all(b"\r")?;
                writer.flush()?;
                prompt_sent = true;
                screen.clear();
            }
            if captured.load(Ordering::Acquire) && completed_at.is_none() {
                completed_at = Some(Instant::now());
            }
            if let Some(when) = completed_at {
                if (!require_response || screen.contains("capture complete")) && when.elapsed() > Duration::from_secs(2)
                {
                    success = true;
                    break;
                }
            }
            if child.try_wait()?.is_some() {
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        if !success {
            for marker in [
                "trust",
                "Welcome",
                "theme",
                "API key",
                "login",
                "log in",
                "Enter",
                "security",
                "terminal",
                "capture complete",
                "Reply briefly",
                "error",
                "Error",
            ] {
                eprintln!("interactive screen marker {marker}: {}", screen.contains(marker));
            }
        }
        ensure!(
            success,
            "interactive capture did not complete: request_seen={}, trust_answered={}, output_bytes={total}",
            captured.load(Ordering::Acquire),
            trust_answered
        );
        Ok(ChildSummary {
            interactive_completed: true,
            exit_code: None,
            stdout_bytes: total,
            stderr_bytes: 0,
            timed_out: false,
            protocol: ChildProtocolSummary::default(),
        })
    })
    .await
    .context("join interactive capture")?
}
