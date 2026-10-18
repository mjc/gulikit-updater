fn main() {
    println!("cargo:rerun-if-changed=src/macos.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/macos.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .flag("-Wall")
            .flag("-Wextra")
            .flag("-Werror")
            .compile("gulikit_macos");
        for framework in ["Foundation", "IOKit", "IOUSBHost", "DiskArbitration"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
}
