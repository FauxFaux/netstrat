extern crate gcc;

const SRC: &str = "native.c";

fn main() {
    println!("cargo:rerun-if-changed={}", SRC);

    gcc::Build::new()
        .file(SRC)
        .flag("-std=gnu11")
        .compile("netstrat-native");
}
