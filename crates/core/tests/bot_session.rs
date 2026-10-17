use gulikit_core::bot::{BulkIo, Direction, Session};
use std::collections::VecDeque;

struct Fake {
    reads: VecDeque<Vec<u8>>,
    calls: Vec<Direction>,
    fail_at: Option<usize>,
    writes: Vec<Vec<u8>>,
}
impl BulkIo for Fake {
    fn transfer(&mut self, direction: Direction, bytes: &mut [u8]) -> Result<usize, String> {
        self.calls.push(direction);
        if self.fail_at == Some(self.calls.len()) {
            return Err("timeout actual=0 raw=[]".into());
        }
        if direction == Direction::Out {
            self.writes.push(bytes.to_vec());
            Ok(bytes.len())
        } else {
            let response = self.reads.pop_front().unwrap();
            bytes[..response.len()].copy_from_slice(&response);
            Ok(response.len())
        }
    }
}
fn io() -> Fake {
    Fake {
        reads: VecDeque::from([vec![0xa1; 20], b"USBS\x01\0\0\0\0\0\0\0\0".to_vec()]),
        calls: vec![],
        fail_at: None,
        writes: vec![],
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
