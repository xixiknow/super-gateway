fn main() {
    // Debug command dispatch includes several large protocol futures. Windows'
    // default executable stack is too small even for the preflight command.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg-bin=spike-cli=/STACK:16777216");
    }
}
