fn main() {
    // `sqlx::migrate!` embeds the migrations directory at compile time but does
    // not register the directory as a change trigger; without this, a newly
    // added migration file silently misses the rebuild and the binary keeps
    // the stale embedded migration list.
    println!("cargo:rerun-if-changed=migrations");
}
