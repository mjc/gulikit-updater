//! Automated demo launch and normal close for native lifecycle profiling.
use super::AppWindow;
use slint::{ComponentHandle, PlatformError, platform::WindowEvent};
use std::{
    cell::Cell,
    rc::Rc,
    time::{Duration, Instant},
};

pub struct LifecycleProfile {
    started: Instant,
    idle: Duration,
    shown: Cell<Option<Instant>>,
    closing: Rc<Cell<Option<Instant>>>,
}

impl LifecycleProfile {
    pub fn from_environment(demo: bool, started: Instant) -> Result<Option<Self>, PlatformError> {
        let value = std::env::var_os("GULIKIT_PROFILE_LIFECYCLE_MS");
        let Some(idle) = profile_duration(value.as_deref(), demo)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            started,
            idle,
            shown: Cell::new(None),
            closing: Rc::new(Cell::new(None)),
        }))
    }

    pub fn close_after_idle(&self, ui: &AppWindow) {
        self.shown.set(Some(Instant::now()));
        let weak = ui.as_weak();
        let closing = self.closing.clone();
        slint::Timer::single_shot(self.idle, move || {
            if let Some(ui) = weak.upgrade() {
                closing.set(Some(Instant::now()));
                ui.window().dispatch_event(WindowEvent::CloseRequested);
            }
        });
    }

    pub fn report(self) {
        let finished = Instant::now();
        let Some(shown) = self.shown.get() else {
            return;
        };
        let Some(closing) = self.closing.get() else {
            return;
        };
        println!(
            "{}",
            serde_json::json!({
                "lifecycle_profile": {
                    "window_shown_ns": shown.duration_since(self.started).as_nanos(),
                    "idle_ns": closing.duration_since(shown).as_nanos(),
                    "shutdown_ns": finished.duration_since(closing).as_nanos(),
                    "total_ns": finished.duration_since(self.started).as_nanos(),
                }
            })
        );
    }
}

fn profile_duration(
    value: Option<&std::ffi::OsStr>,
    demo: bool,
) -> Result<Option<Duration>, PlatformError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !demo {
        return Err(PlatformError::Other(
            "Lifecycle profiling requires --demo".into(),
        ));
    }
    let milliseconds = value
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (50..=60_000).contains(value))
        .ok_or_else(|| {
            PlatformError::Other("GULIKIT_PROFILE_LIFECYCLE_MS must be between 50 and 60000".into())
        })?;
    Ok(Some(Duration::from_millis(milliseconds)))
}

#[cfg(test)]
mod tests {
    use super::{LifecycleProfile, profile_duration};
    use slint::ComponentHandle;
    use std::{
        cell::Cell,
        ffi::OsStr,
        rc::Rc,
        time::{Duration, Instant},
    };

    #[test]
    fn automated_close_requires_demo_and_a_bounded_duration() {
        assert!(profile_duration(Some(OsStr::new("1000")), false).is_err());
        assert_eq!(profile_duration(None, false).unwrap(), None);
        assert_eq!(
            profile_duration(Some(OsStr::new("1000")), true).unwrap(),
            Some(Duration::from_secs(1))
        );
        for value in ["", "0", "49", "60001", "-1", "forever"] {
            assert!(profile_duration(Some(OsStr::new(value)), true).is_err());
        }
    }

    #[test]
    fn timed_close_obeys_the_window_close_handler() {
        use i_slint_backend_testing::{TestingBackend, TestingBackendOptions, mock_elapsed_time};
        slint::platform::set_platform(Box::new(TestingBackend::new(TestingBackendOptions {
            mock_time: true,
            ..Default::default()
        })))
        .unwrap();
        let ui = crate::AppWindow::new().unwrap();
        ui.show().unwrap();
        let requests = Rc::new(Cell::new(0));
        let observed = requests.clone();
        ui.window().on_close_requested(move || {
            observed.set(observed.get() + 1);
            slint::CloseRequestResponse::KeepWindowShown
        });
        let profile = LifecycleProfile {
            started: Instant::now(),
            idle: Duration::from_millis(50),
            shown: Cell::new(None),
            closing: Rc::new(Cell::new(None)),
        };
        profile.close_after_idle(&ui);
        mock_elapsed_time(Duration::from_millis(49));
        slint::platform::update_timers_and_animations();
        assert_eq!(requests.get(), 0);
        mock_elapsed_time(Duration::from_millis(1));
        slint::platform::update_timers_and_animations();
        assert_eq!(requests.get(), 1);
        assert!(
            ui.window().is_visible(),
            "a rejected close must keep the window open"
        );
        ui.hide().unwrap();
    }
}
