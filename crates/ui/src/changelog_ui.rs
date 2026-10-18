//! Manual, read-only release-note comparison, independent of the updater worker.
use super::AppWindow;
use gulikit_core::{
    changelog,
    package::{Component, Model},
};
use slint::ComponentHandle;

fn compare(ui: &AppWindow) {
    let component = if ui.get_changelog_bluetooth() {
        Component::Bluetooth
    } else {
        Component::Main
    };
    match changelog::compare(
        Model::Kk3Max,
        component,
        &ui.get_changelog_from(),
        &ui.get_changelog_to(),
    ) {
        Ok(comparison) => {
            ui.set_changelog_error(slint::SharedString::new());
            ui.set_changelog_result(comparison.render_text().into());
        }
        Err(error) => {
            ui.set_changelog_result(slint::SharedString::new());
            ui.set_changelog_error(error.to_string().into());
        }
    }
}

fn select_component(ui: &AppWindow, bluetooth: bool) {
    ui.set_changelog_bluetooth(bluetooth);
    let (from, to) = if bluetooth {
        ("3.23", "5.07")
    } else {
        ("5.8", "5.9")
    };
    ui.set_changelog_from(from.into());
    ui.set_changelog_to(to.into());
    compare(ui);
}

pub(super) fn bind(ui: &AppWindow) {
    let weak = ui.as_weak();
    ui.on_open_changelog(move || {
        if let Some(ui) = weak.upgrade() {
            select_component(&ui, ui.get_state().bluetooth);
        }
    });
    let weak = ui.as_weak();
    ui.on_select_changelog_component(move |bluetooth| {
        if let Some(ui) = weak.upgrade() {
            select_component(&ui, bluetooth);
        }
    });
    let weak = ui.as_weak();
    ui.on_compare_changelog(move || {
        if let Some(ui) = weak.upgrade() {
            compare(&ui);
        }
    });
}
