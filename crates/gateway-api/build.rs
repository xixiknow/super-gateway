//! Rebuild the embedded management console whenever its generated assets change.

fn main() {
    println!("cargo:rerun-if-changed=../../web/admin-console/dist");
}
