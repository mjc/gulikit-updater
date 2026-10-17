fn main() {
    println!("cargo:rerun-if-changed=src/macos.m");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        pkg_config::Config::new().atleast_version("1.0.29").cargo_metadata(false).probe("libusb-1.0").expect("Install libusb >=1.0.29 and pkg-config; the updater does not use a silent bundled fallback");
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
