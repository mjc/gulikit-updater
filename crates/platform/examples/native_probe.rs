#[cfg(target_os = "macos")]
fn main() -> Result<(), String> {
    use gulikit_core::update::BluetoothPort;
    use gulikit_platform::macos::{Session, discover};
    println!(
        "{}",
        serde_json::to_string_pretty(&discover()?).map_err(|e| e.to_string())?
    );
    if std::env::args().any(|arg| arg == "--confirm-ns39-read-only") {
        let mut session = Session::open(true)?.bluetooth()?;
        println!("GET_MAX_LUN: {:?}", session.max_lun());
        let inquiry = session.inquiry();
        println!("INQUIRY: {inquiry:02x?}");
        // A failed transport command invalidates BOT state: no implicit recovery/reset.
        if inquiry.is_ok() {
            println!("F1: {:02x?}", session.read_info());
        }
        session.finish()?;
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Native qualification adapter currently supports macOS only");
}
