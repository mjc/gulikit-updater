use gulikit_core::update::{CompletionDecision, CompletionObservation};

/// Observe the host registry only. Accepting the last firmware block can reboot
/// the KK3 before its CSW arrives; the registry notification can arrive later.
pub(crate) fn wait_for_expected_reboot(
    mut observe: impl FnMut() -> Result<CompletionObservation, String>,
    mut wait: impl FnMut() -> bool,
) -> Result<bool, String> {
    loop {
        match observe()?.decision() {
            CompletionDecision::ExpectedDetach => return Ok(true),
            CompletionDecision::Invalidated => {
                return Err("Unexpected USB topology while observing the controller reboot".into());
            }
            CompletionDecision::Pending => {}
        }
        if !wait() {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(present: bool, events: u64) -> CompletionObservation {
        CompletionObservation {
            selected_present: present,
            other_candidate_present: false,
            discovery_complete: true,
            usb_events: events,
            usb_arrivals: 0,
        }
    }

    #[test]
    fn normal_final_block_reboot_waits_for_delayed_registry_removal() {
        for observations in [
            [
                observation(true, 0),
                observation(false, 0),
                observation(false, 1),
            ],
            [
                observation(true, 0),
                observation(true, 1),
                observation(false, 1),
            ],
        ] {
            let mut observations = observations.into_iter();
            let mut waits = 0;
            let detached = wait_for_expected_reboot(
                || Ok(observations.next().expect("bounded host observation")),
                || {
                    waits += 1;
                    assert!(waits <= 2);
                    true
                },
            )
            .unwrap();
            assert!(
                detached,
                "normal reboot may precede the OS removal notification"
            );
            assert_eq!(waits, 2);
        }
    }

    #[test]
    fn no_detach_before_the_deadline_does_not_claim_a_reboot() {
        let mut waits = 0;
        assert!(
            !wait_for_expected_reboot(
                || Ok(observation(true, 0)),
                || {
                    waits += 1;
                    waits < 3
                },
            )
            .unwrap()
        );
        assert_eq!(waits, 3);
    }

    #[test]
    fn unrelated_or_incomplete_topology_is_not_a_normal_reboot() {
        for invalid in [
            CompletionObservation {
                usb_arrivals: 1,
                ..observation(false, 1)
            },
            CompletionObservation {
                other_candidate_present: true,
                ..observation(false, 1)
            },
            CompletionObservation {
                discovery_complete: false,
                ..observation(false, 1)
            },
            observation(false, 2),
        ] {
            assert!(
                wait_for_expected_reboot(
                    || Ok(CompletionObservation { ..invalid }),
                    || panic!("invalid topology must stop observation immediately"),
                )
                .is_err()
            );
        }
        assert!(
            wait_for_expected_reboot(
                || Err("host registry unavailable".into()),
                || panic!("an observation error cannot establish a normal reboot"),
            )
            .is_err()
        );
    }
}
