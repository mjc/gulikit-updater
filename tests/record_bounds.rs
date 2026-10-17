//! Receipt persistence only: these fixtures never acquire a device or host lease.
#![cfg(unix)]

use gulikit_core::{
    bot::{CommandEvidence, MaxLun, StallClear, TransferError, TransferFailureKind},
    package::{Component, catalog},
    update::{BluetoothPort, CommandRecord, Outcome, SubmissionError, TransferRecord},
};
use gulikit_platform::journal::{Recorded, finalize_record, read_attempt, write_event};
use gulikit_updater::updater::PriorAttempt;
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Default)]
struct RecoveredCommands {
    tag: u32,
    evidence: Option<CommandEvidence>,
}

impl BluetoothPort for RecoveredCommands {
    fn qualified_lun(&self) -> Option<u8> {
        Some(0)
    }

    fn lun_evidence(&self) -> Option<MaxLun> {
        Some(MaxLun::Reported(0))
    }

    fn take_transport_evidence(&mut self) -> Option<CommandEvidence> {
        self.evidence.take()
    }

    fn prepare_write(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn check_session(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, SubmissionError> {
        self.tag += 1;
        let response = match opcode {
            0xf0 => {
                assert_eq!(data.len(), 512);
                Vec::new()
            }
            0xf1 => vec![
                0xa1, 0xca, 0x51, 0xda, 0x72, 0x4c, 0xb6, 0x10, 0x36, 0x58, 0xc0, 0x5d, 0x7d, 0x4e,
                0x15, 0x96, 0x43, 0x01, 0, 0,
            ],
            0xf2 => {
                let mut response = vec![255; 20];
                response[0] = 0;
                response
            }
            _ => panic!("unexpected fixture opcode"),
        };
        let mut csw = b"USBS".to_vec();
        csw.extend(self.tag.to_le_bytes());
        csw.extend([0; 5]);
        let requested = if opcode == 0xf0 { 512 } else { 20 };
        self.evidence = Some(CommandEvidence {
            tag: self.tag,
            opcode,
            requested,
            cbw_actual: Some(31),
            cbw_error: None,
            data_actual: Some(requested),
            data_in: (opcode != 0xf0).then(|| response.clone()),
            csw_reads: 2,
            csw_raw: csw,
            csw_actual: Some(13),
            csw_errors: vec![TransferError {
                kind: TransferFailureKind::Stall,
                actual: 0,
                raw: Vec::new(),
                // The native buffer holds 1023 non-NUL bytes. Each of these
                // control bytes expands to six bytes when JSON-escaped.
                message: format!("USB status=-1 requested=13 error={}", "\u{1}".repeat(1023)),
            }],
            stall_clear: Some(StallClear::Passed),
            stall_clear_elapsed: Some(Duration::new(4, 999_999_999)),
        });
        Ok(response)
    }

    fn finish(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn full_bluetooth_receipt_with_escaped_recovery_evidence_can_be_reopened_and_parsed() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    let mut journal = temporary.reopen().unwrap();
    let release = catalog()
        .iter()
        .find(|release| release.component == Component::Bluetooth && release.version == "3.24")
        .unwrap();
    let package = serde_json::to_value(release).unwrap();
    let target = json!({"ancestor":42,"generation":42});
    write_event(
        &mut journal,
        &json!({"event":"attempt_started","schema_version":1,"package":package,"target":target}),
    )
    .unwrap();

    let mut transfer = TransferRecord {
        outcome: Outcome::TransferCompletedAwaitingVerification,
        prewrite_version: Some("3.23".into()),
        bytes_submitted: 361_472,
        bytes_confirmed: 361_472,
        ..TransferRecord::default()
    };
    {
        let mut port = Recorded::new(RecoveredCommands::default(), &mut journal);
        let opcodes = [0xf1, 0xf0, 0xf2]
            .into_iter()
            .chain(std::iter::repeat_n(0xf0, 705))
            .chain([0xf2]);
        let block = [0xa5; 512];
        for (index, opcode) in opcodes.enumerate() {
            let response = port
                .command(opcode, if opcode == 0xf0 { &block } else { &[] })
                .unwrap();
            let requested = if opcode == 0xf0 { 512 } else { 20 };
            transfer.commands.push(CommandRecord {
                index,
                opcode,
                requested,
                confirmed: if opcode == 0xf0 { 512 } else { response.len() },
                error: None,
            });
        }
        port.finish().unwrap();
    }
    assert_eq!(transfer.commands.len(), 709);
    let final_record = finalize_record(
        &mut journal,
        json!({"event":"attempt_result","schema_version":1,"package":package,"target":target,"transfer":transfer}),
    );
    assert_eq!(final_record["transfer"]["cleanup_errors"], json!([]));
    // This lower bound catches an accidentally omitted trace or ASCII-only
    // fixture; this test must exercise the old reader limit, not merely parse.
    let size = temporary.as_file().metadata().unwrap().len();
    assert!(
        size > 4_500_000,
        "journal fixture unexpectedly small: {size}"
    );
    let bytes = read_attempt(temporary.path()).unwrap();
    let prior = PriorAttempt::parse(&bytes).unwrap();
    assert_eq!(prior.component, Component::Bluetooth);
    assert_eq!(prior.expected_version, "3.24");
    assert_eq!(
        prior.outcome,
        Outcome::TransferCompletedAwaitingVerification
    );
    assert_eq!(
        prior.record["transfer"]["commands"]
            .as_array()
            .unwrap()
            .len(),
        709
    );

    let results: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| event["event"] == "command_result")
        .collect();
    assert_eq!(results.len(), 709);
    assert_eq!(
        results
            .iter()
            .filter(|event| event["transport"]["opcode"] == 0xf0)
            .count(),
        706
    );
    for event in results {
        let transport = &event["transport"];
        assert_eq!(transport["csw_reads"], 2);
        assert_eq!(transport["stall_clear"]["outcome"], "passed");
        assert!(
            transport["csw_errors"][0]["message"]
                .as_str()
                .unwrap()
                .ends_with(&"\u{1}".repeat(1023))
        );
        if transport["opcode"] == 0xf0 {
            assert!(transport["data_in"].is_null());
            assert_eq!(event["actual"]["response"], json!([]));
        }
    }
}

#[test]
fn oversized_attempt_is_refused_before_reading_or_parsing() {
    let temporary = tempfile::NamedTempFile::new().unwrap();
    temporary.as_file().set_len(16 * 1024 * 1024 + 1).unwrap();
    assert_eq!(
        read_attempt(temporary.path()).unwrap_err(),
        "Attempt record exceeds its size bound"
    );
}
