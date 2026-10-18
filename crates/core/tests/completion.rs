use gulikit_core::update::{CompletionDecision, CompletionObservation};

#[test]
fn main_detach_requires_one_expected_removal_and_no_transient_arrival() {
    let mut event = CompletionObservation {
        selected_present: true,
        other_candidate_present: false,
        discovery_complete: true,
        usb_events: 0,
        usb_arrivals: 0,
    };
    assert_eq!(event.decision(), CompletionDecision::Pending);
    event.selected_present = false;
    assert_eq!(event.decision(), CompletionDecision::Pending);
    event.usb_events = 1;
    assert_eq!(event.decision(), CompletionDecision::ExpectedDetach);
    event.selected_present = true;
    assert_eq!(event.decision(), CompletionDecision::Pending);
    event.selected_present = false;
    assert_eq!(event.decision(), CompletionDecision::ExpectedDetach);
    event.usb_events = 2;
    assert_eq!(event.decision(), CompletionDecision::Invalidated);
    event.usb_events = 3;
    event.usb_arrivals = 1;
    assert_eq!(event.decision(), CompletionDecision::Invalidated);
    event.usb_events = 1;
    event.usb_arrivals = 0;
    event.discovery_complete = false;
    assert_eq!(event.decision(), CompletionDecision::Invalidated);
}

#[test]
fn deadline_requires_removal_evidence_to_converge() {
    let mut observation = CompletionObservation {
        selected_present: true,
        other_candidate_present: false,
        discovery_complete: true,
        usb_events: 0,
        usb_arrivals: 0,
    };
    assert_eq!(observation.at_deadline(), Ok(false));
    observation.usb_events = 1;
    assert!(observation.at_deadline().is_err());
    observation.selected_present = false;
    assert_eq!(observation.at_deadline(), Ok(true));
    observation.usb_events = 0;
    assert!(observation.at_deadline().is_err());
}
