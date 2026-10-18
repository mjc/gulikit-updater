use gulikit_core::bot::{BulkIo, Direction, MaxLun, Session, TransferError, TransferFailureKind};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

struct Fake {
    reads: VecDeque<Vec<u8>>,
    clock: Instant,
    costs: VecDeque<Duration>,
    allowances: Vec<Duration>,
    address_queries: usize,
    max_lun: Result<MaxLun, String>,
    calls: Vec<Direction>,
    fail_at: Option<usize>,
    short_cbw: bool,
    mutate_out: bool,
    error_after_read: bool,
    writes: Vec<Vec<u8>>,
    stalls: Vec<usize>,
    stall_actual: usize,
    clears: usize,
    clear_cost: Duration,
    clear_error: Option<String>,
}
impl BulkIo for Fake {
    fn max_lun(&mut self) -> Result<MaxLun, String> {
        self.address_queries += 1;
        self.max_lun.clone()
    }
    fn clear_stall(&mut self, _budget: Duration) -> Result<(), TransferError> {
        self.clears += 1;
        self.clock += self.clear_cost;
        self.clear_error
            .clone()
            .map_or(Ok(()), |error| Err(error.into()))
    }
    fn now(&self) -> Instant {
        self.clock
    }
    fn transfer(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransferError> {
        self.allowances.push(timeout);
        self.clock += self.costs.pop_front().unwrap_or(Duration::ZERO);
        self.calls.push(direction);
        if self.stalls.contains(&self.calls.len()) {
            return Err(TransferError {
                kind: TransferFailureKind::Stall,
                actual: self.stall_actual,
                raw: vec![0x55; self.stall_actual.min(bytes.len())],
                message: "pipe stalled".into(),
            });
        }
        if self.fail_at == Some(self.calls.len()) {
            return Err(TransferError {
                kind: TransferFailureKind::Timeout,
                actual: 0,
                raw: vec![],
                message: "timeout".into(),
            });
        }
        if direction == Direction::Out {
            self.writes.push(bytes.to_vec());
            if self.mutate_out && bytes.len() != 31 {
                bytes.fill(0xdd);
            }
            Ok(if self.short_cbw && bytes.len() == 31 {
                30
            } else {
                bytes.len()
            })
        } else {
            let response = self.reads.pop_front().unwrap();
            bytes[..response.len()].copy_from_slice(&response);
            if self.error_after_read {
                Err(format!("OS error actual={} raw={response:02x?}", response.len()).into())
            } else {
                Ok(response.len())
            }
        }
    }
}
fn io() -> Fake {
    Fake {
        reads: VecDeque::from([vec![0xa1; 20], b"USBS\x01\0\0\0\0\0\0\0\0".to_vec()]),
        clock: Instant::now(),
        costs: VecDeque::new(),
        allowances: vec![],
        address_queries: 0,
        max_lun: Ok(MaxLun::Reported(0)),
        calls: vec![],
        fail_at: None,
        short_cbw: false,
        mutate_out: false,
        error_after_read: false,
        writes: vec![],
        stalls: vec![],
        stall_actual: 0,
        clears: 0,
        clear_cost: Duration::ZERO,
        clear_error: None,
    }
}

#[test]
fn exact_bot_stages_and_zero_tail_cdb_are_shared() {
    let mut session = Session::new(io());
    let mut cdb = [0; 10];
    cdb[0] = 0xf1;
    assert_eq!(
        session.command(&cdb, Direction::In, &[], 20).unwrap(),
        vec![0xa1; 20]
    );
    assert_eq!(
        session.io_mut().writes[0],
        b"USBC\x01\0\0\0\x14\0\0\0\x80\0\x0a\xf1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    );
    assert!(!session.firmware_may_have_been_submitted());
}

#[test]
fn out_data_is_exact_and_private_at_the_firmware_buffer_boundary() {
    for length in [0, 1, 511, 512, 513, 1024] {
        let payload: Vec<u8> = (0..length)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let mut fake = io();
        fake.reads = VecDeque::from([b"USBS\x01\0\0\0\0\0\0\0\0".to_vec()]);
        fake.mutate_out = true;
        let mut session = Session::new(fake);
        let response = session
            .command(
                &[0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                Direction::Out,
                &payload,
                length,
            )
            .unwrap();
        assert!(response.is_empty());
        assert_eq!(session.io_mut().writes[1], payload);
        assert!(
            payload
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == u8::try_from(index % 251).unwrap())
        );
        let evidence = session.take_evidence().unwrap();
        assert_eq!(evidence.data_actual, Some(length));
        assert!(evidence.data_in.is_none());
        assert_eq!(evidence.csw_actual, Some(13));
        assert!(session.firmware_may_have_been_submitted());
        assert!(!session.failed());
    }
}
#[test]
fn every_failed_stage_latches_failure_and_prevents_a_new_command() {
    for stage in 1..=3 {
        let mut fake = io();
        fake.fail_at = Some(stage);
        let mut session = Session::new(fake);
        assert!(
            session
                .command(&[0xf1; 10], Direction::In, &[], 20)
                .is_err()
        );
        assert!(
            session
                .command(&[0xf1; 10], Direction::In, &[], 20)
                .is_err()
        );
        assert_eq!(session.io_mut().calls.len(), stage);
    }
}
#[test]
fn f0_is_latched_before_even_a_failing_cbw_submission() {
    let mut fake = io();
    fake.fail_at = Some(1);
    let mut session = Session::new(fake);
    assert!(
        session
            .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
            .is_err()
    );
    assert!(session.firmware_may_have_been_submitted());
}
#[test]
fn short_data_and_early_status_never_become_vendor_success() {
    for data in [vec![0; 7], b"USBS\x01\0\0\0\x14\0\0\0\0".to_vec()] {
        let mut fake = io();
        fake.reads[0] = data;
        let mut session = Session::new(fake);
        assert!(
            session
                .command(&[0xf1; 10], Direction::In, &[], 20)
                .is_err()
        );
    }
}

#[test]
fn qualifies_each_attachment_before_any_bot_command_and_refuses_ambiguous_addressing() {
    for advertised in [
        Err("GET_MAX_LUN failed".into()),
        Ok(MaxLun::Reported(1)),
        Ok(MaxLun::Reported(16)),
    ] {
        let mut fake = io();
        fake.max_lun = advertised;
        let mut session = Session::new(fake);
        assert!(
            session
                .command(&[0xf1; 10], Direction::In, &[], 20)
                .is_err()
        );
        assert_eq!(session.io_mut().address_queries, 1);
        assert!(session.io_mut().calls.is_empty());
        assert!(!session.firmware_may_have_been_submitted());
    }
    for _ in 0..2 {
        let mut session = Session::new(io());
        session
            .command(&[0xf1; 10], Direction::In, &[], 20)
            .unwrap();
        assert_eq!(session.io_mut().address_queries, 1);
    }
}

#[test]
fn one_command_deadline_is_shared_by_all_stages_without_retry() {
    let mut fake = io();
    fake.costs = VecDeque::from([Duration::from_secs(2); 3]);
    let mut session = Session::new(fake);
    assert!(
        session
            .command(&[0xf1; 10], Direction::In, &[], 20)
            .is_err()
    );
    assert_eq!(
        session.io_mut().allowances,
        [5, 3, 1].map(Duration::from_secs)
    );
    assert!(session.failed());
    assert!(
        session
            .command(&[0xf1; 10], Direction::In, &[], 20)
            .is_err()
    );
    assert_eq!(session.io_mut().calls.len(), 3);

    let mut fake = io();
    fake.costs = VecDeque::from([Duration::from_secs(3); 2]);
    let mut session = Session::new(fake);
    assert!(
        session
            .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
            .is_err()
    );
    assert_eq!(session.io_mut().calls.len(), 2);
    assert!(session.firmware_may_have_been_submitted());
}

fn status(tag: u32, residue: u32, result: u8) -> Vec<u8> {
    let mut bytes = b"USBS".to_vec();
    bytes.extend(tag.to_le_bytes());
    bytes.extend(residue.to_le_bytes());
    bytes.push(result);
    bytes
}
fn f1() -> [u8; 10] {
    let mut cdb = [0; 10];
    cdb[0] = 0xf1;
    cdb
}

#[test]
fn one_sense_after_exact_failed_f1_preserves_the_failure_and_write_block() {
    let mut fake = io();
    let mut sense = vec![0; 18];
    sense[0] = 0x70;
    sense[2] = 5;
    sense[7] = 10;
    sense[12] = 0x20;
    fake.reads = VecDeque::from([status(1, 0, 1), sense.clone(), status(2, 0, 0)]);
    let mut session = Session::new(fake);
    assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
    assert!(session.failed());
    assert_eq!(session.diagnostic_request_sense().unwrap(), sense);
    assert!(session.failed());
    assert!(!session.firmware_may_have_been_submitted());
    let traffic = session.io_mut().calls.len();
    assert!(session.diagnostic_request_sense().is_err());
    assert!(
        session
            .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
            .is_err()
    );
    assert_eq!(session.io_mut().calls.len(), traffic);
    let cbw = &session.io_mut().writes[1];
    assert_eq!(&cbw[..15], b"USBC\x02\0\0\0\x12\0\0\0\x80\0\x06");
    assert_eq!(
        &cbw[15..],
        &[3, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn sense_diagnostic_requires_the_exact_completed_failed_f1_frame() {
    for bad in [
        status(2, 0, 1),
        status(1, 0, 2),
        status(1, 20, 1),
        status(1, 21, 1),
        status(1, 0, 0),
        status(1, 20, 0),
    ] {
        let mut fake = io();
        fake.reads = VecDeque::from([bad]);
        let mut session = Session::new(fake);
        assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
        let count = session.io_mut().calls.len();
        assert!(!session.request_sense_eligible());
        assert!(session.diagnostic_request_sense().is_err());
        assert_eq!(session.io_mut().calls.len(), count);
    }
    for (cdb, length) in [
        (vec![0xf1; 10], 20),
        (f1().to_vec(), 18),
        (vec![0xf1, 0, 0, 0, 0, 0], 20),
    ] {
        let mut fake = io();
        fake.reads = VecDeque::from([status(1, 0, 1)]);
        let mut session = Session::new(fake);
        assert!(session.command(&cdb, Direction::In, &[], length).is_err());
        let count = session.io_mut().calls.len();
        assert!(session.diagnostic_request_sense().is_err());
        assert_eq!(session.io_mut().calls.len(), count);
    }
    let mut fake = io();
    let mut invalid = status(1, 0, 1);
    invalid[0] = 0;
    fake.reads = VecDeque::from([invalid, status(1, 7, 0)]);
    let mut session = Session::new(fake);
    assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
    let count = session.io_mut().calls.len();
    assert!(session.diagnostic_request_sense().is_err());
    assert_eq!(session.io_mut().calls.len(), count);
}

#[test]
fn timeout_partial_cbw_and_failed_os_read_never_authorize_sense() {
    for stage in 1..=2 {
        let mut fake = io();
        fake.fail_at = Some(stage);
        fake.reads = VecDeque::from([status(1, 0, 1)]);
        let mut session = Session::new(fake);
        assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
        assert!(session.diagnostic_request_sense().is_err());
        assert_eq!(session.io_mut().calls.len(), stage);
    }
    for short_cbw in [true, false] {
        let mut fake = io();
        fake.short_cbw = short_cbw;
        fake.error_after_read = !short_cbw;
        fake.reads = VecDeque::from([status(1, 0, 1)]);
        let mut session = Session::new(fake);
        assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
        let count = session.io_mut().calls.len();
        assert!(session.diagnostic_request_sense().is_err());
        assert_eq!(session.io_mut().calls.len(), count);
    }
    let mut session = Session::new(io());
    assert!(session.diagnostic_request_sense().is_err());
    assert!(session.io_mut().calls.is_empty());
}

#[test]
fn sense_allowance_is_consumed_before_any_failed_submission_or_status() {
    for stage in 3..=5 {
        let mut fake = io();
        fake.fail_at = Some(stage);
        fake.reads = VecDeque::from([status(1, 0, 1), vec![0; 18], status(2, 0, 0)]);
        let mut session = Session::new(fake);
        assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
        assert!(session.diagnostic_request_sense().is_err());
        assert!(session.diagnostic_request_sense().is_err());
        assert_eq!(session.io_mut().calls.len(), stage);
        assert!(session.failed());
    }
    for bad in [
        status(3, 0, 0),
        status(2, 1, 0),
        status(2, 0, 1),
        status(2, 0, 0)[..12].to_vec(),
    ] {
        let mut fake = io();
        fake.reads = VecDeque::from([status(1, 0, 1), vec![0; 18], bad]);
        let mut session = Session::new(fake);
        assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
        assert!(session.diagnostic_request_sense().is_err());
        let count = session.io_mut().calls.len();
        assert!(session.diagnostic_request_sense().is_err());
        assert_eq!(session.io_mut().calls.len(), count);
    }
}

#[test]
fn short_complete_sense_is_validated_by_its_own_status_and_does_not_resume_firmware() {
    let mut fake = io();
    let sense = vec![0x72, 5, 0x24, 0, 0, 0, 0, 0];
    fake.reads = VecDeque::from([status(1, 0, 1), sense.clone(), status(2, 10, 0)]);
    let mut session = Session::new(fake);
    assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
    assert_eq!(
        session.failed_f1_status().unwrap().as_slice(),
        status(1, 0, 1)
    );
    let raw = session.diagnostic_request_sense().unwrap();
    assert_eq!(raw, sense);
    assert_eq!(gulikit_core::scsi::decode_sense(&raw).unwrap().asc, 0x24);
    assert!(session.failed());
    assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
    let mut fake = io();
    fake.reads = VecDeque::from([status(1, 0, 0), status(2, 0, 1)]);
    let mut session = Session::new(fake);
    session
        .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
        .unwrap();
    assert!(session.command(&f1(), Direction::In, &[], 20).is_err());
    let count = session.io_mut().calls.len();
    assert!(session.diagnostic_request_sense().is_err());
    assert_eq!(session.io_mut().calls.len(), count);
    assert!(session.firmware_may_have_been_submitted());
}

#[test]
fn standard_single_lun_stall_is_qualified_and_retained_as_distinct_evidence() {
    let mut fake = io();
    fake.max_lun = Ok(MaxLun::SingleLunStall);
    let mut session = Session::new(fake);
    assert_eq!(session.qualify_addressing().unwrap(), 0);
    assert_eq!(session.lun_evidence(), Some(MaxLun::SingleLunStall));
    session.command(&f1(), Direction::In, &[], 20).unwrap();
    assert_eq!(session.io_mut().address_queries, 1);
    assert_eq!(session.io_mut().writes[0][13], 0);
}

#[test]
fn first_csw_stall_clears_once_and_retries_only_the_original_status() {
    let mut fake = io();
    fake.reads = VecDeque::from([status(1, 0, 0), vec![0; 20], status(2, 0, 0)]);
    fake.stalls = vec![6];
    let mut session = Session::new(fake);
    session
        .command(
            &[0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Direction::Out,
            &[0; 512],
            512,
        )
        .unwrap();
    assert_eq!(
        session
            .command(&[0xf2, 0, 0, 0, 0, 0, 0, 0, 0, 0], Direction::In, &[], 20)
            .unwrap(),
        vec![0; 20]
    );
    assert!(!session.failed());
    assert!(session.firmware_may_have_been_submitted());
    assert_eq!(session.io_mut().clears, 1);
    assert_eq!(session.io_mut().calls.len(), 7);
    assert_eq!(session.io_mut().writes.len(), 3); // F0 CBW, its payload, F2 CBW; no CBW replay.
}

#[test]
fn f2_short_status_uses_the_received_byte_with_exact_transport_residue() {
    for length in [1, 4, 19] {
        let mut fake = io();
        fake.reads = VecDeque::from([
            vec![0; length],
            status(1, 20 - u32::try_from(length).unwrap(), 0),
        ]);
        let mut session = Session::new(fake);
        assert_eq!(
            session
                .command(&[0xf2, 0, 0, 0, 0, 0, 0, 0, 0, 0], Direction::In, &[], 20)
                .unwrap(),
            vec![0; length]
        );
    }
}

fn after_first_f0(data: Vec<u8>, csw: Vec<u8>) -> Session<Fake> {
    let mut fake = io();
    fake.reads = VecDeque::from([status(1, 0, 0), data, csw]);
    fake.stalls = vec![6];
    let mut session = Session::new(fake);
    session
        .command(
            &[0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Direction::Out,
            &[0; 512],
            512,
        )
        .unwrap();
    session
}
fn f2() -> [u8; 10] {
    [0xf2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
#[test]
fn observed_ns39_f2_one_byte_success_accepts_zero_residue_without_changing_evidence() {
    // The second real 3.24 attempt: F1 tag1, F0 tag2, F2 tag3.
    let mut fake = io();
    let mut identity = gulikit_core::version::BT_SIGNATURE.to_vec();
    identity.extend([0x43, 0x01, 0, 0]);
    fake.reads = VecDeque::from([
        identity,
        status(1, 0, 0),
        status(2, 0, 0),
        vec![0],
        status(3, 0, 0),
    ]);
    fake.stalls = vec![9];
    let mut session = Session::new(fake);
    session.command(&f1(), Direction::In, &[], 20).unwrap();
    session
        .command(
            &[0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Direction::Out,
            &[0xa5; 512],
            512,
        )
        .unwrap();
    assert_eq!(session.command(&f2(), Direction::In, &[], 20).unwrap(), [0]);
    let evidence = session.take_evidence().unwrap();
    assert_eq!(evidence.tag, 3);
    assert_eq!(evidence.data_actual, Some(1));
    assert_eq!(evidence.data_in, Some(vec![0]));
    assert_eq!(evidence.csw_raw, status(3, 0, 0));
    assert_eq!(evidence.csw_reads, 2);
    assert!(evidence.f2_zero_residue_quirk);
    let recorded = serde_json::to_value(&evidence).unwrap();
    assert_eq!(recorded["data_actual"], 1);
    assert_eq!(recorded["data_in"], serde_json::json!([0]));
    assert_eq!(recorded["f2_zero_residue_quirk"], true);
    assert!(!session.failed());
    assert!(session.firmware_may_have_been_submitted());
    assert_eq!(session.io_mut().clears, 1);
    assert_eq!(session.io_mut().writes.len(), 4); // Three CBWs + one payload, no replay.
}
#[test]
fn csw_recovery_retains_short_f2_data_and_refuses_empty_or_inconsistent_status() {
    let mut session = after_first_f0(vec![0], status(2, 19, 0));
    assert_eq!(session.command(&f2(), Direction::In, &[], 20).unwrap(), [0]);
    let evidence = session.take_evidence().unwrap();
    assert_eq!(evidence.data_actual, Some(1));
    assert_eq!(evidence.data_in, Some(vec![0]));
    assert_eq!(evidence.csw_raw, status(2, 19, 0));
    assert_eq!(evidence.csw_reads, 2);
    for (data, csw) in [
        (vec![], status(2, 20, 0)),
        (vec![0], status(2, 18, 0)),
        (vec![0, 0], status(2, 0, 0)),
        (vec![1], status(2, 0, 0)),
        (vec![], status(2, 0, 0)),
        (vec![0], status(3, 0, 0)),
        (vec![0], status(2, 0, 1)),
        (vec![0], status(2, 0, 2)),
        (vec![0], status(2, 21, 0)),
        (vec![0], status(2, 0, 4)),
        (vec![0], status(2, 0, 0)[..12].to_vec()),
        (vec![0], status(3, 19, 0)),
        (vec![0], status(2, 19, 1)),
        (vec![0], status(2, 19, 2)),
    ] {
        let mut session = after_first_f0(data.clone(), csw.clone());
        let error = session.command(&f2(), Direction::In, &[], 20).unwrap_err();
        assert!(session.failed());
        assert!(session.firmware_may_have_been_submitted());
        let evidence = session.take_evidence().unwrap();
        assert_eq!(evidence.data_actual, Some(data.len()));
        assert_eq!(evidence.data_in, Some(data));
        assert_eq!(evidence.csw_raw, csw);
        assert_eq!(evidence.csw_reads, 2);
        let calls = session.io_mut().calls.len();
        assert!(
            session
                .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
                .is_err(),
            "{error}"
        );
        assert_eq!(session.io_mut().calls.len(), calls);
    }
}
#[test]
fn csw_second_stall_clear_failure_and_data_errors_never_replay_or_reset() {
    for case in 0..3 {
        let mut session = after_first_f0(vec![0; 20], status(2, 0, 0));
        match case {
            0 => session.io_mut().stalls.push(7),
            1 => session.io_mut().clear_error = Some("clear failed".into()),
            _ => session.io_mut().stalls = vec![5],
        }
        let error = session.command(&f2(), Direction::In, &[], 20).unwrap_err();
        assert!(session.failed());
        assert!(session.firmware_may_have_been_submitted());
        assert_eq!(session.io_mut().clears, usize::from(case != 2));
        assert_eq!(session.io_mut().writes.len(), 3); // No replayed CBW or payload.
        if case != 2 {
            assert!(error.contains("data_actual=20"), "{error}");
        }
    }
}
#[test]
fn clearance_overrun_keeps_ownership_and_prevents_a_late_second_status_read() {
    let mut session = after_first_f0(vec![0; 20], status(2, 0, 0));
    session.io_mut().costs = VecDeque::from([
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::ZERO,
    ]);
    session.io_mut().clear_cost = Duration::from_secs(4);
    let error = session.command(&f2(), Direction::In, &[], 20).unwrap_err();
    assert!(error.contains("budget expired"), "{error}");
    assert_eq!(session.io_mut().clears, 1);
    assert_eq!(session.io_mut().calls.len(), 6); // The second CSW was never scheduled.
    assert!(session.failed());
    assert!(session.firmware_may_have_been_submitted());
}
#[test]
fn short_f1_and_noncanonical_f2_remain_exact_length_commands() {
    for cdb in [f1(), [0xf2, 1, 0, 0, 0, 0, 0, 0, 0, 0]] {
        let mut fake = io();
        fake.reads = VecDeque::from([vec![0], status(1, 19, 0)]);
        assert!(
            Session::new(fake)
                .command(&cdb, Direction::In, &[], 20)
                .is_err()
        );
    }
}

#[test]
fn partial_status_stall_timeout_and_expired_budget_are_not_recovered() {
    for case in 0..3 {
        let mut session = after_first_f0(vec![0; 20], status(2, 0, 0));
        match case {
            0 => session.io_mut().stall_actual = 5,
            1 => {
                session.io_mut().stalls.clear();
                session.io_mut().fail_at = Some(6);
            }
            _ => {
                session.io_mut().costs =
                    VecDeque::from([Duration::ZERO, Duration::ZERO, Duration::from_secs(5)]);
            }
        }
        assert!(session.command(&f2(), Direction::In, &[], 20).is_err());
        assert_eq!(session.io_mut().clears, 0);
        assert_eq!(session.io_mut().calls.len(), 6);
        assert!(session.failed());
        assert!(session.firmware_may_have_been_submitted());
        if case == 0 {
            let evidence = session.take_evidence().unwrap();
            assert_eq!(evidence.csw_actual, Some(5));
            assert_eq!(evidence.csw_raw, vec![0x55; 5]);
        }
    }
}

#[test]
fn f0_missing_status_requires_successful_exact_data_and_zero_status_bytes() {
    for stage in 1..=3 {
        let mut fake = io();
        fake.fail_at = Some(stage);
        let mut session = Session::new(fake);
        assert!(
            session
                .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
                .is_err()
        );
        assert_eq!(session.data_sent_status_missing(), stage == 3);
        let count = session.io_mut().calls.len();
        assert!(
            session
                .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
                .is_err()
        );
        assert_eq!(session.io_mut().calls.len(), count);
    }
    for response in [
        vec![0; 5],
        status(1, 0, 1),
        status(2, 0, 0),
        status(1, 1, 0),
    ] {
        let mut fake = io();
        fake.reads = VecDeque::from([response]);
        let mut session = Session::new(fake);
        assert!(
            session
                .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
                .is_err()
        );
        assert!(!session.data_sent_status_missing());
    }
    let mut fake = io();
    fake.reads = VecDeque::from([status(1, 0, 0)]);
    let mut session = Session::new(fake);
    session
        .command(&[0xf0; 10], Direction::Out, &[0; 512], 512)
        .unwrap();
    assert!(!session.data_sent_status_missing());
}
