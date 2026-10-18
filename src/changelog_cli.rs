use super::{Component, Model, write_json};
use std::{
    io::{self, Write},
    process::ExitCode,
};

pub(super) fn write_comparison(
    model: Model,
    component: Component,
    from: &str,
    to: &str,
    json: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<ExitCode> {
    match gulikit_core::changelog::compare(model, component, from, to) {
        Ok(comparison) => {
            if json {
                write_json(out, serde_json::json!({"changelog":comparison}))?;
            } else {
                writeln!(out, "{}", comparison.render_text())?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            if json {
                write_json(
                    err,
                    serde_json::json!({"error":{"kind":"invalid_version","message":error.to_string()}}),
                )?;
            } else {
                writeln!(err, "{error}")?;
            }
            Ok(ExitCode::from(2))
        }
    }
}
