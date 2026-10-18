use super::{AppWindow, Page, Palette};
use gulikit_core::{package::Component, update::Progress};
use gulikit_ui::{
    Page as ModelPage,
    backend::NATIVE_UPDATE_UNAVAILABLE,
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
}

fn present(ui: &AppWindow, app: &LiveApp) {
    let v = app.view();
    ui.set_model_confirmed(v.confirmed);
    ui.set_same_controller(v.same_controller);
    ui.set_rollback_allowed(v.allow_rollback);
    let can_update = v.can_update && ui.get_demo_mode();
    ui.set_primary_enabled(v.can_primary && (v.page != ModelPage::Ready || can_update));
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
    state.can_choose_package = v.can_choose_package;
    state.can_open_attempt =
        v.can_open_attempt && (ui.get_demo_mode() || cfg!(target_os = "macos"));
    state.can_switch_component = v.can_switch_component;
    state.can_troubleshoot = v.can_troubleshoot;
    state.busy = v.busy;
    state.connected = v.connected;
    state.identity_known = v.confirmed && v.connected;
    state.warning = !can_update && v.page != ModelPage::Verified;
    state.catalog_products = string_model(&v.catalog_products);
    state.catalog_product_index = v.catalog_product_index;
    state.catalog_components = string_model(&v.catalog_components);
    state.catalog_component_index = v.catalog_component_index;
    state.catalog_versions = string_model(&v.catalog_versions);
    state.catalog_version_index = v.catalog_version_index;
    update_text(&mut state.catalog_source_url, v.catalog_source_url);
    update_text(&mut state.catalog_changelog_url, v.catalog_changelog_url);
    update_text(&mut state.catalog_archive, v.catalog_archive);
    update_text(
        &mut state.catalog_software_support,
        v.catalog_software_support,
    );
    update_text(&mut state.catalog_parser_id, v.catalog_parser_id);
    update_text(
        &mut state.catalog_hardware_acceptance,
        v.catalog_hardware_acceptance,
    );
    update_text(&mut state.catalog_hardware_scope, v.catalog_hardware_scope);
    update_text(&mut state.catalog_availability, v.catalog_availability);
    state.catalog_can_import = v.catalog_can_import;
    state.catalog_can_open_source = v.catalog_can_open_source;
    state.catalog_can_open_changelog = v.catalog_can_open_changelog;
    state.catalog_can_download = v.catalog_can_download;
    state.can_allow_rollback = v.can_allow_rollback;
    let notice = if v.can_update && !ui.get_demo_mode() {
        NATIVE_UPDATE_UNAVAILABLE
    } else {
        v.notice
    };
    update_text(&mut state.notice, notice);
    state.error = state.notice.clone();
    update_text(&mut state.status, status);
    update_log(&mut state.log, v.log);
    ui.set_state(state);
    // Widget selection writes its in-out property. Reapply the model indices
    // through two-way bindings after publishing each new choices model.
    ui.set_catalog_product_index(v.catalog_product_index);
    ui.set_catalog_component_index(v.catalog_component_index);
    ui.set_catalog_version_index(v.catalog_version_index);
}

fn string_model(values: &[String]) -> slint::ModelRc<slint::SharedString> {
    slint::ModelRc::new(slint::VecModel::from(
        values
            .iter()
            .map(slint::SharedString::from)
            .collect::<Vec<_>>(),
    ))
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
        present(&ui, &driver.app);
    }
}

fn bind_catalog_actions(ui: &AppWindow, driver: &Rc<RefCell<Driver>>) {
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_select_catalog_product(move |index| {
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            act(&weak, &driver, |app| {
                app.select_catalog_product(index);
                None
            });
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_select_catalog_component(move |index| {
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            act(&weak, &driver, |app| {
                app.select_catalog_component(index);
                None
            });
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_select_catalog_version(move |index| {
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            act(&weak, &driver, |app| {
                app.select_catalog_version(index);
                None
            });
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_import_release(move || act(&weak, &driver, LiveApp::import_release));
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_open_source(move || act(&weak, &driver, LiveApp::open_source));
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_open_changelog(move || act(&weak, &driver, LiveApp::open_changelog));
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_download_release(move || act(&weak, &driver, LiveApp::download_release));
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_allow_rollback(move |enabled| {
            act(&weak, &driver, |app| {
                app.set_allow_rollback(enabled);
                None
            });
        });
    }
}

fn bind_actions(ui: &AppWindow, driver: &Rc<RefCell<Driver>>, demo: bool) {
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_confirm_model(move |confirmed| {
            act(&weak, &driver, |app| {
                app.confirm_model(confirmed);
                None
            });
        });
    }
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
                if !demo && app.can_update() {
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
                app.select_component(if bluetooth {
                    Component::Bluetooth
                } else {
                    Component::Main
                })
            });
        });
    }
    {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_choose_file(move || act(&weak, &driver, LiveApp::choose_package));
    }
    bind_catalog_actions(ui, driver);
    if demo || cfg!(target_os = "macos") {
        let (weak, driver) = (ui.as_weak(), driver.clone());
        ui.on_open_attempt(move || act(&weak, &driver, LiveApp::open_attempt));
    }
    {
        let driver = driver.clone();
        ui.on_cancel_operation(move || driver.borrow().cancelled.store(true, Ordering::Release));
    }
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

pub fn create_mode_with_catalog(
    requests: Sender<Work>,
    events: Receiver<Event>,
    cancelled: Arc<AtomicBool>,
    demo: bool,
    catalog: Option<gulikit_catalog::Catalog>,
) -> Result<(AppWindow, slint::Timer), slint::PlatformError> {
    let ui = AppWindow::new()?;
    // Application surfaces use a fixed light palette; native widgets must match
    // it even when the operating system requests dark appearance.
    ui.global::<Palette>()
        .set_color_scheme(slint::language::ColorScheme::Light);
    ui.set_demo_mode(demo);
    let mut app = LiveApp::default();
    if let Some(catalog) = catalog {
        app.set_catalog(catalog);
    }
    let driver = Rc::new(RefCell::new(Driver {
        app,
        requests,
        cancelled,
    }));
    present(&ui, &driver.borrow().app);
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
            if driver.receive_events(&events) {
                present(&ui, &driver.app);
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
