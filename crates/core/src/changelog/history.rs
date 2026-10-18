//! Paraphrased manufacturer notes. Historical capture coverage is partial.
//! Source URLs identify the official page or the exact archived official capture.
use super::ReleaseNotes;
use crate::package::{Component, Model};

const MAIN_SOURCE: &str = "https://www.gulikit.com/newsinfo/887152.html";
const BT_SOURCE: &str = "https://www.gulikit.com/newsinfo/915900.html";

const MAIN: &[ReleaseNotes] = &[
    ReleaseNotes {
        version: "3.2",
        release_date: None,
        changes: &[
            "Adds joystick-, vibration- and trigger-responsive ring lighting alongside steady lighting and off.",
        ],
        source_url: MAIN_SOURCE,
    },
    ReleaseNotes {
        version: "4.4",
        release_date: None,
        changes: &["Adds a third vibration intensity level."],
        source_url: MAIN_SOURCE,
    },
    ReleaseNotes {
        version: "5.8",
        release_date: None,
        changes: &[
            "Fixes an extra keystroke before the first playback after a slow APG double-press.",
        ],
        source_url: MAIN_SOURCE,
    },
    ReleaseNotes {
        version: "5.9",
        release_date: Some("2026-03-02"),
        changes: &[
            "Fixes incomplete analog trigger travel after switching back from Click mode on KK3 Max.",
        ],
        source_url: MAIN_SOURCE,
    },
];

const BLUETOOTH: &[ReleaseNotes] = &[
    ReleaseNotes {
        version: "3.23",
        release_date: Some("2024-04-30"),
        changes: &["Improves wireless transmission speed through data-processing changes."],
        source_url: "https://wayback.archive.org/web/20240520050308id_/https://gulikit.com/newsinfo/915900.html",
    },
    ReleaseNotes {
        version: "3.24",
        release_date: Some("2024-09-06"),
        changes: &["Fixes vibration continuing on a wired PC connection in Switch mode."],
        source_url: "https://web.archive.org/web/20240915054400id_/http://gulikit.com/newsinfo/915900.html",
    },
    ReleaseNotes {
        version: "3.26",
        release_date: Some("2024-10-30"),
        changes: &[
            "Improves Bluetooth speed, polling rate and latency in PC and Switch modes.",
            "Adjusts Switch-mode gyro sensitivity.",
        ],
        source_url: "https://wayback.archive.org/web/20241105115308id_/https://gulikit.com/newsinfo/915900.html",
    },
    ReleaseNotes {
        version: "3.27",
        release_date: Some("2025-01-14"),
        changes: &[
            "Improves PC Bluetooth operation and stability with multiple connected controllers.",
        ],
        source_url: "https://wayback.archive.org/web/20250126104944id_/https://gulikit.com/newsinfo/915900.html",
    },
    ReleaseNotes {
        version: "3.30",
        release_date: Some("2025-05-23"),
        changes: &["Improves PC Bluetooth compatibility and KK3 Max NFC compatibility."],
        source_url: "https://web.archive.org/web/20250611232309id_/https://gulikit.com/newsinfo/915900.html",
    },
    ReleaseNotes {
        version: "3.31",
        release_date: Some("2025-07-24"),
        changes: &["Automatically powers off the controller when Switch 2 sleeps."],
        source_url: "https://web.archive.org/web/20250915150016id_/https://www.gulikit.com/newsinfo/915900.html",
    },
    ReleaseNotes {
        version: "5.03",
        release_date: Some("2025-10-15"),
        changes: &[
            "Adds Switch 2 wake-up support, requiring the manufacturer's special pairing procedure; see the source instructions.",
        ],
        source_url: "https://note.com/gulikitjapan/n/n87f9e33d58b7",
    },
    ReleaseNotes {
        version: "5.07",
        release_date: Some("2025-12-10"),
        changes: &[
            "Prevents HOME power-on over PC USB from also waking the previously paired Switch.",
        ],
        source_url: BT_SOURCE,
    },
];

pub(super) fn releases(model: Model, component: Component) -> &'static [ReleaseNotes] {
    match (model, component) {
        (Model::Kk3Max, Component::Main) => MAIN,
        (Model::Kk3Max, Component::Bluetooth) => BLUETOOTH,
    }
}
