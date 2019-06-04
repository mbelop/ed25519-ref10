extern crate cc;

use std::env;
use std::path::PathBuf;

fn main() {
    let mut path: PathBuf =
        PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());
    path.push("ref");

    let mut build = cc::Build::new();
    build
        .files(vec![
            "src/crypto_api.c",
            "src/fe.c",
            "src/ge.c",
            "src/keypair.c",
            "src/open.c",
            "src/sc.c",
            "src/sign.c",
        ])
        .opt_level(2)
        .flag("-Wno-unused-parameter")
        .compile("ed25519")
}
