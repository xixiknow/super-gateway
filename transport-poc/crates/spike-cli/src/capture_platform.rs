use anyhow::{Result, bail};

/// One observed platform maps to one target, never to an unobserved second architecture.
pub(crate) fn target_for(os: &str, arch: &str) -> Result<&'static str> {
    match (os.to_ascii_lowercase().as_str(), arch.to_ascii_lowercase().as_str()) {
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        ("windows", "aarch64" | "arm64") => Ok("aarch64-pc-windows-msvc"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64" | "arm64") => Ok("aarch64-unknown-linux-gnu"),
        ("macos" | "darwin", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos" | "darwin", "aarch64" | "arm64") => Ok("aarch64-apple-darwin"),
        _ => bail!("unsupported capture platform: {os}/{arch}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn platforms_have_exact_targets() -> Result<()> {
        assert_eq!(target_for("macos", "aarch64")?, "aarch64-apple-darwin");
        assert_eq!(target_for("Linux", "x86_64")?, "x86_64-unknown-linux-gnu");
        assert_eq!(target_for("Windows", "x86_64")?, "x86_64-pc-windows-msvc");
        assert!(target_for("linux", "mips").is_err());
        Ok(())
    }
}
