#[cfg(target_os = "macos")]
fn main() -> Result<(), String> {
    use gulikit_core::update::BluetoothPort;
    use gulikit_platform::macos::{Session, discover};
    println!(
        "{}",
        serde_json::to_string_pretty(&discover()?).map_err(|e| e.to_string())?
    );
    if std::env::args().any(|arg| arg == "--confirm-ns39-read-only") {
        let selected = Session::open(true, gulikit_core::package::Component::Bluetooth)?;
        println!(
            "Selected attachment before claim: {}",
            serde_json::to_string_pretty(&selected.target).map_err(|e| e.to_string())?
        );
        let mut session = selected.bluetooth().map_err(|error| error.to_string())?;
        println!("Claimed: {}", session.enable_diagnostics()?);
        println!("GET_MAX_LUN: {:?}", session.max_lun());
        let inquiry = session.inquiry();
        println!("INQUIRY: {inquiry:02x?}");
        // A failed transport command invalidates BOT state: no implicit recovery/reset.
        if inquiry.is_ok() {
            let info = session.read_info();
            println!("F1: {info:02x?}");
            if info.is_err() {
                if session.diagnostic_sense_eligible() {
                    println!(
                        "Original failed F1 CSW: {:02x?}",
                        session.failed_f1_status()
                    );
                    let sense = session.diagnostic_request_sense();
                    println!("REQUEST SENSE: {sense:02x?}");
                    if let Ok(raw) = sense {
                        println!(
                            "Decoded sense: {:?}",
                            gulikit_core::scsi::decode_sense(&raw)
                        );
                    }
                } else {
                    println!(
                        "Endpoint IN GET_STATUS: {:?}",
                        session.endpoint_status(true)
                    );
                    println!(
                        "Endpoint OUT GET_STATUS: {:?}",
                        session.endpoint_status(false)
                    );
                    println!(
                        "Original transaction continuation: {:?}",
                        session.diagnostic_continuation()
                    );
                }
            }
        }
        let cleanup = session.finish();
        println!("Cleanup result: {cleanup:?}");
        println!(
            "After release: {}",
            serde_json::to_string_pretty(&discover()?).map_err(|e| e.to_string())?
        );
        cleanup?;
    }
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Native qualification adapter currently supports macOS only");
}
