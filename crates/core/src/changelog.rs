//! Informational release history. Notes do not establish firmware support or authorize writes.
use crate::{
    package::{Component, Model},
    version::release_version,
};
use serde::Serialize;
use std::cmp::Ordering;

mod history;

pub const COVERAGE_NOTICE: &str =
    "Recorded vendor notes only; historical records may be incomplete.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upgrade,
    Downgrade,
    Unchanged,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Coverage {
    PartialHistoricalRecord,
}

#[derive(Debug, Serialize)]
pub struct ReleaseNotes {
    pub version: &'static str,
    pub release_date: Option<&'static str>,
    pub changes: &'static [&'static str],
    pub source_url: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    model: Model,
    component: Component,
    from: String,
    to: String,
    direction: Direction,
    coverage: Coverage,
    releases: Vec<&'static ReleaseNotes>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChangelogError {
    #[error(
        "Invalid {component} {bound} version '{value}'; use numeric major.minor notation (Bluetooth requires two minor digits)"
    )]
    InvalidVersion {
        component: Component,
        bound: &'static str,
        value: String,
    },
    #[error("Invalid recorded {component} release version '{version}'")]
    InvalidHistory {
        component: Component,
        version: &'static str,
    },
}

impl Comparison {
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    #[must_use]
    pub fn releases(&self) -> &[&'static ReleaseNotes] {
        &self.releases
    }

    /// Render the same comparison for CLI and desktop presentation.
    #[must_use]
    pub fn render_text(&self) -> String {
        let title = match self.direction {
            Direction::Upgrade => "Changes added",
            Direction::Downgrade => "Changes removed",
            Direction::Unchanged => "No version change",
        };
        let mut lines = vec![
            format!(
                "{} · {} · {} → {}",
                self.model, self.component, self.from, self.to
            ),
            COVERAGE_NOTICE.into(),
            String::new(),
            title.into(),
        ];
        if self.releases.is_empty() && self.direction != Direction::Unchanged {
            lines.push("No recorded release notes in this interval. This does not establish that the firmware is unchanged.".into());
        }
        for release in &self.releases {
            lines.push(String::new());
            lines.push(release.release_date.map_or_else(
                || format!("Version {}", release.version),
                |date| format!("Version {} · {date}", release.version),
            ));
            lines.extend(release.changes.iter().map(|change| format!("• {change}")));
            lines.push(format!("Source: {}", release.source_url));
        }
        lines.join("\n")
    }
}

/// Show every recorded release crossed by a version change, independently of package availability.
///
/// Upgrades include `(from, to]`; downgrades include `(to, from]` in reverse order,
/// describing changes removed. Versions need not themselves have recovered notes.
/// A future validated device read can supply `from` without changing this API.
///
/// # Errors
/// Rejects malformed component-specific version bounds or invalid recorded labels.
pub fn compare(
    model: Model,
    component: Component,
    from: &str,
    to: &str,
) -> Result<Comparison, ChangelogError> {
    let parse = |value: &str, bound| {
        release_version(component, value).map_err(|_| ChangelogError::InvalidVersion {
            component,
            bound,
            value: value.into(),
        })
    };
    let start = parse(from, "from")?;
    let end = parse(to, "to")?;
    let direction = match start.cmp(&end) {
        Ordering::Less => Direction::Upgrade,
        Ordering::Greater => Direction::Downgrade,
        Ordering::Equal => Direction::Unchanged,
    };
    let (low, high) = (start.min(end), start.max(end));
    let mut releases = history::releases(model, component)
        .iter()
        .map(|release| {
            release_version(component, release.version)
                .map(|version| (version, release))
                .map_err(|_| ChangelogError::InvalidHistory {
                    component,
                    version: release.version,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    releases.retain(|(version, _)| *version > low && *version <= high);
    releases.sort_by_key(|(version, _)| *version);
    if direction == Direction::Downgrade {
        releases.reverse();
    }
    Ok(Comparison {
        model,
        component,
        from: from.into(),
        to: to.into(),
        direction,
        coverage: Coverage::PartialHistoricalRecord,
        releases: releases.into_iter().map(|(_, release)| release).collect(),
    })
}
