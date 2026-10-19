use super::{AppWindow, Page, Palette};
use gulikit_core::{package::Component, update::Progress};
use gulikit_ui::{
    Page as ModelPage,
    archive::{ArchiveBrowser, ArchiveEvent, ArchiveView, cache_directory},
    archive_package::DownloadInspection,
    backend::{NATIVE_UPDATE_SUPPORTED, NATIVE_UPDATE_UNAVAILABLE},
    live::{Event, LiveApp, Work},
};
use slint::ComponentHandle;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender, TryRecvError},
    },
    time::Duration,
};

struct Driver {
    app: LiveApp,
    archive: ArchiveBrowser,
    requests: Sender<Work>,
    cancelled: Arc<AtomicBool>,
}

impl Driver {
    fn receive_events(&mut self, events: &Receiver<Event>) -> bool {
        let mut changed = false;
        loop {
            match events.try_recv() {
                Ok(event) => {
                    self.app.accept(event);
                    changed = true;
                }
                Err(TryRecvError::Empty) => return changed,
                Err(TryRecvError::Disconnected) => {
                    if self.app.is_busy() {
                        self.app.accept(Event::WorkerFailed(
                            "Updater worker ended. Inspect the operation record.".into(),
                        ));
                        changed = true;
                    }
                    return changed;
                }
            }
        }
    }

    fn receive_archive_events(&mut self, events: &Receiver<ArchiveEvent>) -> bool {
        let (changed, downloaded) = self.archive.receive(events);
        for event in downloaded {
            let ArchiveEvent::Downloaded {
                path,
                record,
                inspection,
            } = event
            else {
                continue;
            };
            if self.archive.selected_path() != Some(record.path()) {
                self.archive.set_status("Download completed for a release that is no longer selected; no updater package was changed.");
                continue;
            }
            match inspection {
                Ok(DownloadInspection::Supported(info)) => {
                    if self.app.view().component == info.component
                        && self.app.use_downloaded_package(path.clone(), info)
                    {
                        self.archive.set_status(format!(
                            "Downloaded and inspected {}. Cached at {}",
                            record.filename(),
                            path.display()
                        ));
                    } else {
                        self.archive.set_status(format!(
                            "Verified {} at {}. Choose it again when the updater is ready.",
                            record.filename(),
                            path.display()
                        ));
                    }
                }
                Ok(DownloadInspection::ArchivedOnly) => {
                    self.app.clear_selected_package();
                    self.archive.set_status(format!("Verified archive cached at {}. This historical version is not yet supported by the updater.", path.display()));
                }
                Err(error) => self
                    .archive
                    .set_status(format!("Archive download could not be inspected: {error}")),
            }
        }
        changed
    }
}

fn present(ui: &AppWindow, app: &LiveApp, archive: &ArchiveBrowser) {
    let v = app.view();
    ui.set_same_controller(v.same_controller);
    let can_update = v.can_update && (ui.get_demo_mode() || NATIVE_UPDATE_SUPPORTED);
    ui.set_primary_enabled(
        v.can_primary && !archive.is_busy() && (v.page != ModelPage::Ready || can_update),
    );
    let mut primary_label = ui.get_primary_label();
    update_text(&mut primary_label, &v.primary_label);
    ui.set_primary_label(primary_label);
    let component_name = if v.component == Component::Main {
        "Main firmware"
    } else {
        "Bluetooth firmware"
    };
    let status = if v.busy && v.page != ModelPage::Writing {
        "Reading / selecting…"
    } else {
        match v.page {
            ModelPage::Connect => "Waiting for controller",
            ModelPage::Ready if v.connected => "Controller inspected",
            ModelPage::Ready => "Package inspected · controller not inspected",
            ModelPage::Writing => "Writing firmware",
            ModelPage::Restart => "Verification pending",
            ModelPage::Verified => "Version verified",
            ModelPage::Failed => "Operation stopped",
        }
    };
    // Reuse Slint's shared string storage for unchanged fields during progress updates.
    let mut state = ui.get_state();
    state.page = match v.page {
        ModelPage::Connect => Page::Connect,
        ModelPage::Ready => Page::Ready,
        ModelPage::Writing => Page::Writing,
        ModelPage::Restart => Page::Restart,
        ModelPage::Verified => Page::Verified,
        ModelPage::Failed => Page::Failed,
    };
    state.bluetooth = v.component == Component::Bluetooth;
    update_text(&mut state.component_name, component_name);
    update_text(&mut state.main_version, v.main_version);
    update_text(&mut state.bt_version, v.bt_version);
    update_text(&mut state.installed, v.installed);
    update_text(&mut state.target, v.target);
    update_text(&mut state.filename, &v.filename);
    update_text(&mut state.payload, v.payload);
    update_text(&mut state.digest, v.digest);
    state.progress = progress_fraction(v.progress);
    state.transfer_label = slint::format!(
        "{} / {} bytes confirmed",
        v.progress.confirmed,
        v.progress.total
    );
    state.can_update = can_update;
    state.can_choose_package = v.can_choose_package && !archive.is_busy();
    state.can_open_attempt =
        v.can_open_attempt && (ui.get_demo_mode() || cfg!(target_os = "macos"));
    state.can_switch_component = v.can_switch_component && !archive.is_busy();
    state.can_troubleshoot = v.can_troubleshoot;
    state.busy = v.busy;
    state.connected = v.connected;
    state.identity_known = v.confirmed && v.connected;
    state.warning = !can_update && v.page != ModelPage::Verified;
    let notice = if v.can_update && !ui.get_demo_mode() && !NATIVE_UPDATE_SUPPORTED {
        NATIVE_UPDATE_UNAVAILABLE
    } else {
        v.notice
    };
    update_text(&mut state.notice, notice);
    state.error = state.notice.clone();
    update_text(&mut state.status, status);
    update_log(&mut state.log, v.log);
    present_archive(&mut state, &archive.view());
    ui.set_state(state);
}

fn present_archive(state: &mut super::ViewState, view: &ArchiveView) {
    update_text(&mut state.archive_status, &view.status);
    update_text(&mut state.archive_revision, &view.revision);
    state.archive_releases = slint::ModelRc::new(slint::VecModel::from(
        view.releases
            .iter()
            .map(|value| value.as_str().into())
            .collect::<Vec<slint::SharedString>>(),
    ));
    state.archive_selected = view.selected;
    update_text(&mut state.archive_version, &view.version);
    update_text(&mut state.archive_filename, &view.filename);
    update_text(&mut state.archive_details, &view.details);
    update_text(&mut state.archive_changelog, &view.changelog);
    state.archive_busy = view.busy;
    state.archive_refreshing = view.refreshing;
    state.archive_can_refresh = view.can_refresh;
    state.archive_can_download = view.can_download;
}

#[expect(
    clippy::cast_precision_loss,
    reason = "Slint renders an f32 fraction; the model and byte-count label retain exact usize counts."
)]
fn progress_fraction(progress: Progress) -> f32 {
    if progress.total == 0 {
        0.
    } else {
        progress.confirmed as f32 / progress.total as f32
    }
}

fn update_text(text: &mut slint::SharedString, value: &str) {
    if text.as_str() != value {
        *text = value.into();
    }
}

fn update_log(text: &mut slint::SharedString, entries: &[String]) {
    let remaining =
        entries
            .iter()
            .enumerate()
            .try_fold(text.as_str(), |remaining, (index, entry)| {
                let remaining = if index == 0 {
                    remaining
                } else {
                    remaining.strip_prefix("\n\n")?
                };
                remaining.strip_prefix(entry.as_str())
            });
    if remaining == Some("") {
        return;
    }
    let mut updated = slint::SharedString::new();
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            updated.push_str("\n\n");
        }
        updated.push_str(entry);
    }
    *text = updated;
}

fn act(
    ui: &slint::Weak<AppWindow>,
    driver: &Rc<RefCell<Driver>>,
    action: impl FnOnce(&mut LiveApp) -> Option<Work>,
) {
    if let Some(ui) = ui.upgrade() {
        let mut driver = driver.borrow_mut();
        if let Some(work) = action(&mut driver.app) {
            driver.cancelled.store(false, Ordering::Release);
            if driver.requests.send(work).is_err() {
                driver.app.accept(Event::Error(
                    "Updater worker ended. Restart the application.".into(),
                ));
            }
        }
        present(&ui, &driver.app, &driver.archive);
    }
}

fn bind_actions(ui: &AppWindow, driver: &Rc<RefCell<Driver>>, demo: bool) {
    bind_archive_actions(ui, driver);
    bind_demo_actions(ui, driver, demo);
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_confirm_same(move |confirmed| {
            act(&weak, &driver, |app| {
                app.confirm_same_controller(confirmed);
                None
            });
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_primary_action(move || {
            act(&weak, &driver, |app| {
                if !demo && !NATIVE_UPDATE_SUPPORTED && app.can_update() {
                    return None;
                }
                app.primary()
            });
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_inspect_controller(move || act(&weak, &driver, LiveApp::connect));
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_select_component(move |bluetooth| {
            act(&weak, &driver, |app| {
                let component = if bluetooth {
                    Component::Bluetooth
                } else {
                    Component::Main
                };
                app.select_component(component)
            });
            let mut driver = driver.borrow_mut();
            let selected_component = if bluetooth {
                Component::Bluetooth
            } else {
                Component::Main
            };
            if driver.app.view().component == selected_component {
                if driver.archive.set_component(selected_component) {
                    driver.app.clear_selected_package();
                }
                if let Some(ui) = weak.upgrade() {
                    present(&ui, &driver.app, &driver.archive);
                }
            }
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_choose_file(move || act(&weak, &driver, LiveApp::choose_package));
    }
    if demo || cfg!(target_os = "macos") {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_open_attempt(move || act(&weak, &driver, LiveApp::open_attempt));
    }
    {
        let driver = driver.clone();
        ui.on_cancel_operation(move || driver.borrow().cancelled.store(true, Ordering::Release));
    }
}

fn bind_archive_actions(ui: &AppWindow, driver: &Rc<RefCell<Driver>>) {
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_archive_refresh(move || {
            let mut driver = driver.borrow_mut();
            driver.archive.refresh();
            if let Some(ui) = weak.upgrade() {
                present(&ui, &driver.app, &driver.archive);
            }
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_archive_select(move |label| {
            let mut driver = driver.borrow_mut();
            if driver.app.view().can_choose_package && driver.archive.select_label(label.as_str()) {
                driver.app.clear_selected_package();
            }
            if let Some(ui) = weak.upgrade() {
                present(&ui, &driver.app, &driver.archive);
            }
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_archive_download(move || {
            let mut driver = driver.borrow_mut();
            driver.archive.download();
            if let Some(ui) = weak.upgrade() {
                present(&ui, &driver.app, &driver.archive);
            }
        });
    }
}

fn bind_demo_actions(ui: &AppWindow, driver: &Rc<RefCell<Driver>>, demo: bool) {
    if demo {
        use gulikit_ui::demo::{Profile, SamplePackage};
        let (weak, model) = (ui.as_weak(), driver.clone());
        ui.on_select_package(move |index| {
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            if let Some(sample) = [
                SamplePackage::Matching,
                SamplePackage::WrongModel,
                SamplePackage::WrongComponent,
                SamplePackage::LongFilename,
            ]
            .get(index)
            {
                act(&weak, &model, |app| app.choose_sample(*sample));
            }
        });
        let (weak, model) = (ui.as_weak(), driver.clone());
        ui.on_scenario_selected(move |index| {
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            if let Some(profile) = [
                Profile::Normal,
                Profile::Current,
                Profile::Newer,
                Profile::IdentityFailure,
                Profile::TransferFailure,
                Profile::VerificationFailure,
                Profile::UnknownVersion,
            ]
            .get(index)
            {
                act(&weak, &model, |app| app.configure_demo(*profile));
            }
        });
    }
}

pub fn create_mode(
    requests: Sender<Work>,
    events: Receiver<Event>,
    cancelled: Arc<AtomicBool>,
    demo: bool,
) -> Result<(AppWindow, slint::Timer), slint::PlatformError> {
    let (archive, archive_events) = ArchiveBrowser::spawn(cache_directory(), !demo && !cfg!(test));
    create_mode_with_archive(requests, events, cancelled, demo, archive, archive_events)
}

pub(super) fn create_mode_with_archive(
    requests: Sender<Work>,
    events: Receiver<Event>,
    cancelled: Arc<AtomicBool>,
    demo: bool,
    archive: ArchiveBrowser,
    archive_events: Receiver<ArchiveEvent>,
) -> Result<(AppWindow, slint::Timer), slint::PlatformError> {
    let ui = AppWindow::new()?;
    // Native widgets must use the same light palette as the fixed app surfaces.
    ui.global::<Palette>()
        .set_color_scheme(slint::language::ColorScheme::Light);
    ui.set_demo_mode(demo);
    let driver = Rc::new(RefCell::new(Driver {
        app: LiveApp::default(),
        archive,
        requests,
        cancelled,
    }));
    present(&ui, &driver.borrow().app, &driver.borrow().archive);
    bind_actions(&ui, &driver, demo);
    let closing = Rc::new(Cell::new(false));
    {
        let (driver, closing) = (driver.clone(), closing.clone());
        ui.window().on_close_requested(move || {
            if driver.borrow().app.is_busy() {
                closing.set(true);
                driver.borrow().cancelled.store(true, Ordering::Release);
                slint::CloseRequestResponse::KeepWindowShown
            } else {
                slint::CloseRequestResponse::HideWindow
            }
        });
    }
    let timer = slint::Timer::default();
    let weak = ui.as_weak();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(30),
        move || {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let mut driver = driver.borrow_mut();
            let op_changed = driver.receive_events(&events);
            let archive_changed = driver.receive_archive_events(&archive_events);
            if op_changed || archive_changed {
                present(&ui, &driver.app, &driver.archive);
            }
            if closing.get() && !driver.app.is_busy() {
                let _ = ui.hide();
            }
        },
    );
    Ok((ui, timer))
}

#[cfg(test)]
mod tests {
    use super::update_log;

    #[test]
    fn log_rendering_preserves_entries_and_reuses_unchanged_storage() {
        let mut rendered = slint::SharedString::default();
        for entries in [
            vec![String::new()],
            vec![String::new(), String::new()],
            vec!["é 🚲\n\n嵌入".into(), String::new(), "tail\n".into()],
            (0..200).map(|i| format!("entry {i}\nline 2")).collect(),
            vec!["replacement".into()],
            vec![],
        ] {
            update_log(&mut rendered, &entries);
            assert_eq!(rendered, entries.join("\n\n"));
            let retained = rendered.clone();
            update_log(&mut rendered, &entries);
            assert_eq!(rendered.as_str().as_ptr(), retained.as_str().as_ptr());
        }
    }
}
