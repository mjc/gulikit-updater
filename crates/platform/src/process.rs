//! Bounded OS helper execution; a helper timeout never authorizes a forced operation.

use std::{
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

/// Intended for OS helpers with small diagnostic output, such as diskutil.
/// Only the exact child owned by this handle is terminated on deadline.
pub fn run_with_deadline(command: &mut Command, deadline: Duration) -> Result<Output, String> {
    let started = Instant::now();
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().map_err(|e| e.to_string()),
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
        if started.elapsed() >= deadline {
            // The live, unreaped child handle prevents PID reuse; no unrelated process is signaled.
            let _ = child.kill();
            let output = child.wait_with_output().map_err(|e| e.to_string())?;
            return Err(format!(
                "OS helper exceeded its deadline; completion is uncertain: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{process::Command, time::Duration};
    #[test]
    fn helper_completion_and_timeout_are_distinct() {
        let result =
            run_with_deadline(&mut Command::new("/usr/bin/true"), Duration::from_secs(1)).unwrap();
        assert!(result.status.success());
        let mut command = Command::new("/bin/sleep");
        command.arg("2");
        assert!(
            run_with_deadline(&mut command, Duration::from_millis(20))
                .unwrap_err()
                .contains("deadline")
        );
    }
}
