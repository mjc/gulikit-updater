use super::Command;
use gulikit_core::package::VerifiedPackage;
use serde_json::Value;

#[cfg(not(target_os = "macos"))]
pub fn execute(_command: Command, _package: Option<VerifiedPackage>) -> Result<Value, String> {
    Err(
        "Native device access currently supports macOS only; package inspection works on this OS"
            .into(),
    )
}

#[cfg(target_os = "macos")]
pub fn execute(command: Command, package: Option<VerifiedPackage>) -> Result<Value, String> {
    use gulikit_core::{
        package::Component,
        update::{
            BluetoothPort, Outcome, Verification, update_bluetooth, update_main, verify_restart,
        },
        version::bluetooth_info,
    };
    use gulikit_platform::macos::{Session, discover, read_main};
    use serde_json::json;
    use std::{
        fs::File,
        io::{Read, Write},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    match command {
        Command::Devices { .. } => Ok(
            json!({"discovery":discover()?,"coverage":"Observed GuliKit update profiles and correlated GuliKit volumes. Put only one device in update mode; future unknown identities may not be recognized."}),
        ),
        Command::Probe {
            component,
            confirm_ns39,
            ..
        } => {
            let (target, raw, version) = match component {
                Component::Main => {
                    let (target, raw, version) = read_main(confirm_ns39)?;
                    (target, raw, version.to_string())
                }
                Component::Bluetooth => {
                    let mut port = Session::open(confirm_ns39)?.bluetooth()?;
                    let target = port.target().clone();
                    let raw = port.read_info();
                    let cleanup = port.finish();
                    let raw = raw.map_err(|e| format!("{e}; cleanup={cleanup:?}"))?;
                    cleanup?;
                    let version = bluetooth_info(&raw).map_err(|e| e.to_string())?.to_string();
                    (target, raw, version)
                }
            };
            Ok(
                json!({"component":component,"installed_version":version,"raw_version_bytes":raw,"target":target,"identity_provenance":"user-confirmed NS39; observed update profile"}),
            )
        }
        Command::Update {
            component,
            confirm_ns39,
            record,
            ..
        } => {
            let package = package.ok_or("Missing verified package")?;
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&cancelled);
            ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
                .map_err(|e| e.to_string())?;
            let mut session = Session::open(confirm_ns39)?;
            let target = session.target.clone();
            let mut journal = session.create_record(&record)?;
            let header = json!({"event":"attempt_started","schema_version":1,"target":target,"package":package.info(),"identity_provenance":"user-confirmed NS39; observed update profile","post_restart_association":"pending; no USB serial is available"});
            serde_json::to_writer(&mut journal, &header).map_err(|e| e.to_string())?;
            writeln!(journal).map_err(|e| e.to_string())?;
            journal.sync_all().map_err(|e| e.to_string())?;
            let mut result = match component {
                Component::Main => {
                    let mut port = session.main()?;
                    update_main(&mut port, &package, || cancelled.load(Ordering::SeqCst))
                }
                Component::Bluetooth => {
                    let mut port = session.bluetooth()?;
                    update_bluetooth(&mut port, &package, || cancelled.load(Ordering::SeqCst))
                }
            };
            let value = json!({"event":"attempt_result","schema_version":1,"target":target,"package":package.info(),"transfer":result,"restart":"Power off and on normally, re-enter update mode, then use verify with this record and confirm the same physical controller. Transfer completion does not verify installation."});
            if let Err(e) = (|| -> Result<(), String> {
                serde_json::to_writer(&mut journal, &value).map_err(|e| e.to_string())?;
                writeln!(journal).map_err(|e| e.to_string())?;
                journal.sync_all().map_err(|e| e.to_string())?;
                Ok(())
            })() {
                result
                    .cleanup_errors
                    .push(format!("Attempt record could not be finalized: {e}"));
                return Ok(json!({"target":target,"package":package.info(),"transfer":result}));
            }
            Ok(value)
        }
        Command::Verify {
            attempt,
            confirm_ns39,
            confirm_same_controller,
            ..
        } => {
            let file = File::open(&attempt).map_err(|e| e.to_string())?;
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("Attempt record must be a regular file".into());
            }
            let mut bytes = Vec::new();
            file.take(1_048_577)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 1_048_576 {
                return Err("Attempt record exceeds its size bound".into());
            }
            let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            let records: Vec<Value> = text
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            let prior=records.last().filter(|v|v["event"]=="attempt_result").ok_or("Attempt has no complete result; use probe for an independent version observation")?;
            let component = prior["package"]["component"]
                .as_str()
                .ok_or("Missing component")?
                .parse::<Component>()
                .map_err(|e| e.to_string())?;
            let previous: Outcome = serde_json::from_value(prior["transfer"]["outcome"].clone())
                .map_err(|e| e.to_string())?;
            let generation = prior["target"]["generation"]
                .as_u64()
                .ok_or("Missing attachment generation")?;
            let (target, version) = match component {
                Component::Main => {
                    let (target, _, version) = read_main(confirm_ns39)?;
                    (target, version.to_string())
                }
                Component::Bluetooth => {
                    let mut port = Session::open(confirm_ns39)?.bluetooth()?;
                    let target = port.target().clone();
                    let raw = port.read_info();
                    let cleanup = port.finish();
                    let raw = raw.map_err(|e| format!("{e};cleanup={cleanup:?}"))?;
                    cleanup?;
                    (
                        target,
                        bluetooth_info(&raw).map_err(|e| e.to_string())?.to_string(),
                    )
                }
            };
            let observation = Verification {
                component,
                previous_generation: generation,
                generation: target.generation,
                same_unit_confirmed: confirm_same_controller,
                model_confirmed: confirm_ns39,
                version,
            };
            Ok(
                json!({"verification":observation,"target":target,"same_unit_association":"user-confirmed; attachment generation bound; no machine-proven unique serial identity","transfer":{"outcome":verify_restart(previous,&observation)}}),
            )
        }
        _ => Err("Not a native command".into()),
    }
}
