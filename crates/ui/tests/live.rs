use gulikit_core::{
    package::Component,
    update::{Outcome, Progress},
    version::VersionDecision,
};
use gulikit_ui::Page;
use gulikit_ui::live::{Event, LiveApp, Work};
mod common;
use common::{attempt, inspection, package, readback};

fn ready() -> LiveApp {
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.connect();
    app.accept(Event::Inspected(inspection()));
    app.choose_package();
    app.accept(Event::Package {
        path: "official.zip".into(),
        info: package(),
    });
    app
}

#[test]
fn borrowed_view_preserves_unicode_filename_and_recent_log_entries() {
    let mut app = LiveApp::default();
    app.confirm_model(true);
    for value in 0..205 {
        app.connect().unwrap();
        let mut read = inspection();
        read.installed_version = format!("observed {value} 🚲\n\nline 2");
        app.accept(Event::Inspected(read));
    }
    let view = app.view();
    assert_eq!(view.log.len(), 200);
    assert!(
        view.log
            .first()
            .unwrap()
            .contains("observed 5 🚲\n\nline 2")
    );
    assert!(
        view.log
            .last()
            .unwrap()
            .contains("observed 204 🚲\n\nline 2")
    );
    app.choose_package().unwrap();
    app.accept(Event::Package {
        path: "nested/contrôleur-固件.zip".into(),
        info: package(),
    });
    let view = app.view();
    assert_eq!(view.filename, "contrôleur-固件.zip");
    assert!(matches!(view.filename, std::borrow::Cow::Borrowed(_)));
}

#[cfg(unix)]
#[test]
fn borrowed_view_keeps_lossy_non_utf8_filename_behavior() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};
    let mut app = ready();
    app.choose_package().unwrap();
    app.accept(Event::Package {
        path: PathBuf::from(OsString::from_vec(b"firmware-\xff.zip".to_vec())),
        info: package(),
    });
    assert_eq!(app.view().filename, "firmware-�.zip");
}

#[test]
fn selected_package_payload_label_is_borrowed_and_refreshes_on_replacement() {
    let mut app = ready();
    let pointer = {
        let view = app.view();
        assert_eq!(view.payload, "51500 bytes");
        view.payload.as_ptr()
    };
    app.start().unwrap();
    for confirmed in [79, 158, 237] {
        app.accept(Event::Progress(Progress {
            submitted: 4096,
            confirmed,
            total: 51500,
        }));
        assert_eq!(app.view().payload.as_ptr(), pointer);
    }

    let mut app = ready();
    app.choose_package().unwrap();
    let mut replacement = package();
    replacement.payload_size = 1234;
    app.accept(Event::Package {
        path: "replacement.zip".into(),
        info: replacement,
    });
    assert_eq!(app.view().payload, "1234 bytes");
    app.select_component(Component::Bluetooth);
    assert_eq!(app.view().payload, "");
}
fn pending() -> LiveApp {
    let mut app = ready();
    app.start();
    app.accept(Event::Transferred {
        record: "attempt.jsonl".into(),
        result: attempt(Outcome::TransferCompletedAwaitingVerification),
    });
    app
}

#[test]
fn pending_receipt_survives_record_replacement_and_failed_readback() {
    for failed_readback in [false, true] {
        let mut app = pending();
        if failed_readback {
            app.confirm_same_controller(true);
            app.primary().unwrap();
            app.accept(Event::Verified(readback(8, "5.8")));
        }
        assert!(
            app.open_attempt().is_none(),
            "an active receipt cannot be replaced"
        );
        app.accept(Event::Prior {
            path: "old-refusal.jsonl".into(),
            prior: reopen_finalized_attempt(Outcome::Refused),
        });
        assert!(
            app.connect().is_none(),
            "pending verification cannot become a new probe"
        );
        app.select_component(Component::Bluetooth);
        assert_eq!(app.view().component, Component::Main);
        assert!(!app.view().can_update);
        app.confirm_model(false);
        app.confirm_model(true);
        assert!(app.open_attempt().is_none());
        assert!(app.connect().is_none());
    }
}

#[test]
fn verified_receipt_allows_opening_the_next_record() {
    let mut app = pending();
    app.confirm_same_controller(true);
    app.primary().unwrap();
    app.accept(Event::Verified(readback(8, "5.9")));
    assert_eq!(app.view().page, Page::Verified);
    assert!(matches!(app.open_attempt(), Some(Work::OpenAttempt)));
    app.accept(Event::Prior {
        path: "next-attempt.jsonl".into(),
        prior: reopen_finalized_attempt(Outcome::TransferSubmittedPendingCompletion),
    });
    assert_eq!(app.view().page, Page::Restart);
    assert!(app.open_attempt().is_none());
}

#[test]
fn failed_record_selection_does_not_make_a_verified_receipt_pending_again() {
    for error in [
        Event::Error("malformed record".into()),
        Event::WorkerFailed("record worker stopped".into()),
    ] {
        let mut app = pending();
        app.confirm_same_controller(true);
        app.primary().unwrap();
        app.accept(Event::Verified(readback(8, "5.9")));
        app.open_attempt().unwrap();
        app.accept(error);
        assert_eq!(app.view().page, Page::Failed);
        assert_eq!(app.view().target, "5.9");
        assert!(app.view().can_open_attempt);
        assert!(app.view().can_switch_component);
        assert_ne!(app.view().primary_label, "Back to verification");
        app.open_attempt().unwrap();
        app.accept(Event::Cancelled);
        app.select_component(Component::Bluetooth);
        assert_eq!(app.view().component, Component::Bluetooth);
    }
}

#[test]
fn cancelled_record_selection_preserves_verification_without_restoring_a_hold() {
    let mut app = pending();
    app.confirm_same_controller(true);
    app.primary().unwrap();
    app.accept(Event::Verified(readback(8, "5.9")));
    app.open_attempt().unwrap();
    app.accept(Event::Cancelled);
    assert_eq!(app.view().page, Page::Verified);
    assert_eq!(app.view().target, "5.9");
    assert!(app.view().can_open_attempt);
    assert!(app.view().can_switch_component);
}

#[test]
fn revoking_model_confirmation_does_not_make_a_verified_receipt_pending() {
    let mut app = pending();
    app.confirm_same_controller(true);
    app.primary().unwrap();
    app.accept(Event::Verified(readback(8, "5.9")));
    app.confirm_model(false);
    assert_eq!(app.view().page, Page::Connect);
    assert!(app.view().can_open_attempt);
    assert!(app.view().can_switch_component);
    app.confirm_model(true);
    assert!(matches!(app.primary(), Some(Work::Inspect { .. })));
}

#[test]
fn new_inspection_cannot_resurrect_a_verified_receipt_hold() {
    for failed in [false, true] {
        let mut app = pending();
        app.confirm_same_controller(true);
        app.primary().unwrap();
        app.accept(Event::Verified(readback(8, "5.9")));
        app.connect().unwrap();
        app.accept(if failed {
            Event::Error("inspection failed".into())
        } else {
            Event::Inspected(inspection())
        });
        assert!(app.view().can_open_attempt);
        assert!(app.view().can_switch_component);
        assert_ne!(app.view().primary_label, "Back to verification");
        assert!(app.choose_package().is_some());
    }
}

#[test]
fn completed_transfer_notice_describes_pending_verification() {
    for outcome in [
        Outcome::TransferCompletedAwaitingVerification,
        Outcome::TransferSubmittedPendingCompletion,
    ] {
        let mut app = ready();
        app.start().unwrap();
        app.accept(Event::Transferred {
            record: "attempt.jsonl".into(),
            result: attempt(outcome),
        });
        assert_eq!(app.view().page, Page::Restart);
        assert!(app.view().notice.contains("Verification pending"));
        assert!(!app.view().notice.contains("Ready."));
    }
}

#[test]
fn preflight_results_with_write_effects_cannot_release_recovery_holds() {
    for outcome in [
        Outcome::AlreadyCurrent,
        Outcome::NewerThanSupported,
        Outcome::Refused,
        Outcome::CancelledBeforeWrite,
    ] {
        for (submitted, destination_created) in [(1, false), (0, true)] {
            let mut app = ready();
            app.start().unwrap();
            let mut result = attempt(outcome);
            result.transfer.bytes_submitted = submitted;
            result.transfer.bytes_confirmed = 0;
            result.transfer.main_destination_created = destination_created;
            app.accept(Event::Transferred {
                record: "attempt.jsonl".into(),
                result,
            });
            assert_eq!(app.view().page, Page::Failed, "{outcome:?}");
            assert!(
                !app.view().can_primary,
                "{outcome:?} {submitted} {destination_created}"
            );
            assert!(app.connect().is_none());
            assert!(app.open_attempt().is_none());
        }
    }
}

#[test]
fn inspection_requires_operator_confirmation_and_only_emits_a_read_request() {
    let mut app = LiveApp::default();
    assert!(app.connect().is_none());
    app.confirm_model(true);
    assert!(matches!(
        app.connect(),
        Some(Work::Inspect {
            component: Component::Main,
            confirmed: true
        })
    ));
    assert!(
        app.connect().is_none(),
        "a second operation cannot race inspection"
    );
}

#[test]
fn unknown_current_newer_and_failed_cleanup_never_enable_update() {
    for decision in [
        VersionDecision::AlreadyCurrent,
        VersionDecision::NewerThanSupported,
    ] {
        let mut app = LiveApp::default();
        app.confirm_model(true);
        app.connect();
        let mut read = inspection();
        read.decision = decision;
        read.installed_version = if decision == VersionDecision::AlreadyCurrent {
            "5.9"
        } else {
            "6.0"
        }
        .into();
        app.accept(Event::Inspected(read));
        app.choose_package();
        app.accept(Event::Package {
            path: "official.zip".into(),
            info: package(),
        });
        assert!(!app.can_update());
        assert!(app.start().is_none());
    }
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.connect();
    let mut read = inspection();
    read.cleanup_errors
        .push("driver restoration pending".into());
    app.accept(Event::Inspected(read));
    app.choose_package();
    app.accept(Event::Package {
        path: "official.zip".into(),
        info: package(),
    });
    assert!(!app.can_update());
    assert!(app.view().notice.contains("restoration"));
    app.confirm_model(false);
    assert!(app.connect().is_none());
}

#[test]
fn busy_state_locks_requests_and_only_observed_progress_moves_the_bar() {
    let mut app = ready();
    app.start();
    assert!(app.choose_package().is_none());
    assert!(app.select_component(Component::Bluetooth).is_none());
    assert!(app.open_attempt().is_none());
    app.accept(Event::Progress(Progress {
        submitted: 4096,
        confirmed: 79,
        total: 51500,
    }));
    assert_eq!(app.view().progress.confirmed, 79);
    assert_eq!(app.view().page, Page::Writing);
    app.accept(Event::Transferred {
        record: "attempt.jsonl".into(),
        result: attempt(Outcome::TransferCompletedAwaitingVerification),
    });
    assert_eq!(app.view().page, Page::Restart);
    assert_eq!(app.view().installed, "5.8");
    assert!(app.primary().is_none());
}

#[test]
fn verified_requires_explicit_association_fresh_generation_matching_version_and_clean_result() {
    for (generation, version, cleanup) in [
        (7, "5.9", false),
        (8, "5.8", false),
        (8, "5.9", true),
        (8, "5.9", false),
    ] {
        let mut app = pending();
        assert!(app.primary().is_none());
        app.confirm_same_controller(true);
        assert!(matches!(
            app.primary(),
            Some(Work::Verify {
                same_controller: true,
                ..
            })
        ));
        let mut result = readback(generation, version);
        if cleanup {
            result
                .transfer
                .cleanup_errors
                .push("record sync failed".into());
        }
        app.accept(Event::Verified(result));
        assert_eq!(
            app.view().page == Page::Verified,
            generation == 8 && version == "5.9" && !cleanup
        );
    }
}

#[test]
fn uncertain_transfer_cannot_be_retried_by_reinspection_or_package_changes() {
    let mut app = ready();
    app.start();
    app.accept(Event::Transferred {
        record: "attempt.jsonl".into(),
        result: attempt(Outcome::OutcomeUnknown),
    });
    assert_eq!(app.view().page, Page::Failed);
    app.connect();
    app.accept(Event::Inspected(inspection()));
    app.choose_package();
    app.accept(Event::Package {
        path: "official.zip".into(),
        info: package(),
    });
    assert!(!app.can_update());
    assert!(app.start().is_none());
    assert!(app.view().notice.contains("No retry"));
}

#[test]
fn cancelled_picker_preserves_selection_but_rejected_file_clears_it() {
    let mut app = ready();
    app.choose_package();
    app.accept(Event::Cancelled);
    assert!(app.can_update());
    app.choose_package();
    app.accept(Event::Error("wrong archive digest".into()));
    assert!(!app.can_update());
    assert!(app.view().filename.contains("No firmware"));
}

#[test]
fn inconsistent_transfer_result_cannot_enable_restart_verification() {
    let mut app = ready();
    app.start();
    let mut result = attempt(Outcome::TransferCompletedAwaitingVerification);
    result.transfer.bytes_confirmed = 51501;
    app.accept(Event::Transferred {
        record: "attempt.jsonl".into(),
        result,
    });
    assert_eq!(app.view().page, Page::Failed);
    assert!(!app.view().can_update);
}

#[test]
fn package_and_inspection_never_start_writing_without_explicit_action() {
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.connect();
    app.accept(Event::Inspected(inspection()));
    assert!(!app.can_update());
    app.choose_package();
    app.accept(Event::Package {
        path: "official.zip".into(),
        info: package(),
    });
    assert!(app.can_update());
    assert!(matches!(
        app.start(),
        Some(Work::Update {
            component: Component::Main,
            ..
        })
    ));
    assert!(
        app.start().is_none(),
        "double activation must not submit twice"
    );
}

#[test]
fn invalid_progress_stays_locked_until_the_worker_finishes() {
    let mut app = ready();
    app.start();
    app.accept(Event::Progress(Progress {
        submitted: 4096,
        confirmed: 51501,
        total: 51500,
    }));
    assert!(app.view().busy);
    assert!(app.primary().is_none());
    assert!(app.select_component(Component::Bluetooth).is_none());
    app.accept(Event::Error("worker cleanup finished".into()));
    assert!(!app.view().busy);
    assert_eq!(app.view().page, Page::Failed);
    assert!(!app.can_update());
}
#[test]
fn unknown_readback_and_revoked_confirmation_cannot_enable_an_update() {
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.connect();
    app.accept(Event::Error("unknown installed version".into()));
    assert_eq!(app.view().page, Page::Failed);
    assert!(!app.can_update());
    let mut app = ready();
    app.confirm_model(false);
    assert_eq!(app.view().page, Page::Connect);
    assert!(!app.can_update());
    app.confirm_model(true);
    assert!(matches!(app.primary(), Some(Work::Inspect { .. })));
}
fn reopen_finalized_attempt(outcome: Outcome) -> gulikit_updater::updater::PriorAttempt {
    let file = tempfile::NamedTempFile::new().unwrap();
    let value = serde_json::to_value(attempt(outcome)).unwrap();
    let result = gulikit_platform::journal::finalize_record(&mut file.reopen().unwrap(), value);
    assert_eq!(result["record_finalized"], true);
    gulikit_updater::updater::PriorAttempt::parse(&std::fs::read(file.path()).unwrap()).unwrap()
}

#[test]
fn a_loaded_receipt_still_requires_fresh_observation_and_updates_the_display() {
    let mut app = LiveApp::default();
    app.open_attempt();
    let prior = reopen_finalized_attempt(Outcome::TransferCompletedAwaitingVerification);
    app.accept(Event::Prior {
        path: "attempt.jsonl".into(),
        prior,
    });
    assert!(app.primary().is_none());
    app.confirm_model(true);
    assert!(app.primary().is_none());
    app.confirm_same_controller(true);
    assert!(matches!(app.primary(), Some(Work::Verify { .. })));
    app.accept(Event::Verified(readback(8, "5.9")));
    assert_eq!(app.view().page, Page::Verified);
    assert_eq!(app.view().installed, "5.9");
}

#[test]
fn choosing_the_other_mode_waits_for_instructions_then_explicit_inspection() {
    for mut app in [ready(), {
        let mut app = pending();
        app.confirm_same_controller(true);
        app.primary();
        app.accept(Event::Verified(readback(8, "5.9")));
        app
    }] {
        assert!(
            app.select_component(Component::Bluetooth).is_none(),
            "component selection must not start discovery before mode instructions"
        );
        let view = app.view();
        assert_eq!(view.page, Page::Connect);
        assert!(!view.busy);
        assert!(!view.connected);
        assert!(!view.can_update);
        assert_eq!(view.main_version, "Version unknown");
        assert_eq!(view.bt_version, "Version unknown");
        assert!(view.filename.contains("No firmware"));
        assert!(matches!(
            app.primary(),
            Some(Work::Inspect {
                component: Component::Bluetooth,
                confirmed: true
            })
        ));
    }
}

#[test]
fn verification_is_bound_to_the_release_in_the_original_desktop_receipt() {
    let mut app = pending();
    app.confirm_same_controller(true);
    app.primary();
    let mut result = readback(8, "5.8");
    result.verification.as_mut().unwrap().expected_version = "5.8".into();
    app.accept(Event::Verified(result));
    assert_ne!(app.view().page, Page::Verified);
}

#[test]
fn created_main_destination_blocks_a_new_desktop_attempt_without_claiming_payload_submission() {
    let mut app = ready();
    app.start();
    let mut result = attempt(Outcome::DestinationCreatedWithoutPayload);
    result.transfer.main_destination_created = true;
    result.transfer.bytes_submitted = 0;
    result.transfer.bytes_confirmed = 0;
    app.accept(Event::Transferred {
        record: "attempt.jsonl".into(),
        result,
    });
    assert_eq!(app.view().page, Page::Failed);
    app.connect();
    app.accept(Event::Inspected(inspection()));
    app.choose_package();
    app.accept(Event::Package {
        path: "official.zip".into(),
        info: package(),
    });
    assert!(!app.can_update());
    assert!(app.start().is_none());
}

#[test]
fn unknown_outcome_holds_native_reads_across_mode_changes_and_saved_records() {
    let mut app = ready();
    app.start();
    app.accept(Event::Transferred {
        record: "attempt.jsonl".into(),
        result: attempt(Outcome::OutcomeUnknown),
    });
    assert!(
        app.connect().is_none(),
        "a new inspection can claim/reset USB after a partial transfer"
    );
    app.select_component(Component::Bluetooth);
    assert!(!app.view().can_primary);
    assert!(app.primary().is_none());
    app.open_attempt();
    let prior = reopen_finalized_attempt(Outcome::TransferCompletedAwaitingVerification);
    app.accept(Event::Prior {
        path: "earlier-attempt.jsonl".into(),
        prior,
    });
    app.confirm_same_controller(true);
    assert!(!app.view().can_primary);
    assert!(
        app.primary().is_none(),
        "an earlier record cannot release the recovery hold"
    );
}

#[test]
fn selected_bluetooth_release_drives_the_version_and_update_label() {
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.select_component(Component::Bluetooth);
    app.connect();
    let mut read = inspection();
    read.component = Component::Bluetooth;
    read.installed_version = "3.23".into();
    app.accept(Event::Inspected(read));
    app.choose_package();
    let mut info = package();
    info.component = Component::Bluetooth;
    info.version = "3.24".into();
    info.payload_size = 361_472;
    app.accept(Event::Package {
        path: "NS38_NS39_BT_V3.24.zip".into(),
        info,
    });
    assert_eq!(app.view().target, "3.24");
    assert_eq!(app.view().primary_label, "Update to 3.24  →");
}

#[test]
fn loaded_bluetooth_receipt_displays_its_release_before_and_after_readback() {
    for expected in ["3.23", "3.24"] {
        let release = gulikit_core::package::catalog()
            .iter()
            .find(|r| r.component == Component::Bluetooth && r.version == expected)
            .unwrap();
        let record = serde_json::json!({"event":"attempt_result", "package":release, "target":{"generation":7}, "transfer":{"outcome":"transfer_completed_awaiting_verification"}});
        let prior =
            gulikit_updater::updater::PriorAttempt::parse(&serde_json::to_vec(&record).unwrap())
                .unwrap();
        let mut app = LiveApp::default();
        app.confirm_model(true);
        app.open_attempt().unwrap();
        app.accept(Event::Prior {
            path: "attempt.jsonl".into(),
            prior,
        });
        assert_eq!(app.view().target, expected);
        app.confirm_same_controller(true);
        app.primary().unwrap();
        let mut result = readback(8, expected);
        let observation = result.verification.as_mut().unwrap();
        observation.component = Component::Bluetooth;
        observation.expected_version = expected.into();
        app.accept(Event::Verified(result));
        assert_eq!(app.view().page, Page::Verified);
        assert_eq!(app.view().target, expected);
        assert_eq!(app.view().installed, expected);
        app.open_attempt().unwrap();
        app.accept(Event::Cancelled);
        assert_eq!(app.view().page, Page::Verified);
        assert_eq!(app.view().target, expected);
        assert_eq!(app.view().installed, expected);
        assert!(app.view().can_open_attempt);
        assert!(app.view().can_switch_component);
    }
}

#[test]
fn pending_receipts_require_exact_submitted_and_confirmed_payload_counts() {
    for (outcome, submitted, confirmed, accepted) in [
        (
            Outcome::TransferCompletedAwaitingVerification,
            51500,
            51500,
            true,
        ),
        (
            Outcome::TransferCompletedAwaitingVerification,
            51500,
            51499,
            false,
        ),
        (
            Outcome::TransferCompletedAwaitingVerification,
            51499,
            51499,
            false,
        ),
        (
            Outcome::TransferCompletedAwaitingVerification,
            51501,
            51500,
            false,
        ),
        (
            Outcome::TransferSubmittedPendingCompletion,
            51500,
            51200,
            true,
        ),
        (
            Outcome::TransferSubmittedPendingCompletion,
            51499,
            51200,
            false,
        ),
        (
            Outcome::TransferSubmittedPendingCompletion,
            51501,
            51500,
            false,
        ),
    ] {
        let mut app = ready();
        app.start().unwrap();
        let mut result = attempt(outcome);
        result.transfer.bytes_submitted = submitted;
        result.transfer.bytes_confirmed = confirmed;
        app.accept(Event::Transferred {
            record: "attempt.jsonl".into(),
            result,
        });
        assert_eq!(
            app.view().page == Page::Restart,
            accepted,
            "{outcome:?} {submitted}/{confirmed}"
        );
        if !accepted {
            assert!(!app.view().can_primary);
            assert!(app.connect().is_none());
        }
    }
}

#[test]
fn progress_cannot_erase_submission_or_exceed_payload_bounds() {
    for submitted in [0, 51501] {
        let mut app = ready();
        app.start().unwrap();
        app.accept(Event::Progress(Progress {
            submitted: 512,
            confirmed: 0,
            total: 51500,
        }));
        app.accept(Event::Progress(Progress {
            submitted,
            confirmed: 0,
            total: 51500,
        }));
        app.accept(Event::Error("worker ended after invalid progress".into()));
        assert!(!app.view().can_primary);
        assert!(app.connect().is_none());
    }
}

#[test]
fn cleanup_failure_allows_same_component_reinspection() {
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.connect().unwrap();
    let mut read = inspection();
    read.cleanup_errors.push("remount failed".into());
    app.accept(Event::Inspected(read));
    assert_eq!(app.view().page, Page::Failed);
    assert_eq!(app.view().installed, "5.8");
    assert!(matches!(
        app.primary(),
        Some(Work::Inspect {
            component: Component::Main,
            ..
        })
    ));
    app.accept(Event::Inspected(inspection()));
    assert_eq!(app.view().page, Page::Ready);
}

#[test]
fn package_inspection_is_available_without_native_access_but_cannot_enable_writes() {
    let mut app = LiveApp::default();
    app.choose_package()
        .expect("offline packages do not require native discovery");
    app.accept(Event::Package {
        path: "official.zip".into(),
        info: package(),
    });
    assert_eq!(app.view().filename, "official.zip");
    assert_eq!(app.view().page, Page::Ready);
    assert!(!app.can_update());
    assert!(app.start().is_none());
}

#[test]
fn unfinalized_transfer_cannot_offer_verification() {
    let mut app = ready();
    app.start().unwrap();
    let mut result = attempt(Outcome::TransferCompletedAwaitingVerification);
    result.record_finalized = false;
    result
        .transfer
        .cleanup_errors
        .push("Host record could not be finalized: disk full".into());
    app.accept(Event::Transferred {
        record: "incomplete.jsonl".into(),
        result,
    });
    assert_eq!(app.view().page, Page::Failed);
    assert!(!app.view().can_primary);
}

#[test]
fn eligibility_tracks_each_selected_bluetooth_release() {
    for (installed, older_allowed) in [("3.23", true), ("3.24", false), ("5.06", false)] {
        let mut app = LiveApp::default();
        app.confirm_model(true);
        app.select_component(Component::Bluetooth);
        app.connect().unwrap();
        let mut read = inspection();
        read.component = Component::Bluetooth;
        read.installed_version = installed.into();
        app.accept(Event::Inspected(read));
        for selected in ["3.24", "5.07", "3.24", "5.07"] {
            app.choose_package().unwrap();
            let mut info = package();
            info.component = Component::Bluetooth;
            info.version = selected.into();
            app.accept(Event::Package {
                path: "reviewed.zip".into(),
                info,
            });
            assert_eq!(
                app.can_update(),
                selected == "5.07" || older_allowed,
                "{installed} to {selected}"
            );
        }
    }
}
