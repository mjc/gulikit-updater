use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const OSASCRIPT: &str = "/usr/bin/osascript";
const CANCELLED_MARKER: &str = "GULIKIT_AUTHORIZATION_CANCELLED";
const EXITED_MARKER: &str = "GULIKIT_ELEVATED_APP_EXITED";
const INVOKING_UID_ARGUMENT: &str = "--authorized-invoking-uid";
const AUTHORIZATION_SCRIPT: &str = r#"
on run argv
    set toolPath to item 1 of argv
    set loginUID to item 2 of argv
    set commandText to "/bin/launchctl asuser " & (quoted form of loginUID) & " " & (quoted form of toolPath) & " " & (quoted form of "--authorized-invoking-uid") & " " & (quoted form of loginUID)
    try
        do shell script commandText with administrator privileges with prompt "GuliKit Updater needs administrator access to open its USB update interface. No controller command runs until you choose an action in the app."
    on error errorMessage number errorNumber
        if errorNumber is -128 then
            return "GULIKIT_AUTHORIZATION_CANCELLED"
        end if
        error errorMessage number errorNumber
    end try
    return "GULIKIT_ELEVATED_APP_EXITED"
end run
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupDisposition {
    Continue {
        receipt_owner: Option<gulikit_platform::journal::ReceiptOwner>,
    },
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizationOutcome {
    ChildExited,
    Cancelled,
}

pub fn ensure_administrator(
    receipt_owner: Option<gulikit_platform::journal::ReceiptOwner>,
) -> Result<StartupDisposition, String> {
    ensure_administrator_with(
        nix::unistd::geteuid().as_raw(),
        receipt_owner,
        || std::env::current_exe().map_err(|error| error.to_string()),
        || nix::unistd::getuid().as_raw(),
        request_authorized_launch,
    )
}

/// Remove the private UID argument added by the administrator-authenticated
/// desktop launcher. It is accepted only by a root process.
pub fn take_launcher_receipt_owner(
    arguments: &mut Vec<OsString>,
    effective_uid: u32,
) -> Result<Option<gulikit_platform::journal::ReceiptOwner>, String> {
    if arguments
        .first()
        .is_none_or(|argument| argument != INVOKING_UID_ARGUMENT)
    {
        return Ok(None);
    }
    if effective_uid != 0 {
        return Err("The administrator launch argument is valid only in the elevated app".into());
    }
    if arguments.len() != 2 {
        return Err("The administrator launch argument is malformed".into());
    }
    let uid_argument = arguments[1]
        .to_str()
        .ok_or("The administrator launch UID is not valid text")?;
    let uid = uid_argument
        .parse::<u32>()
        .map_err(|_| "The administrator launch UID is invalid")?;
    if uid_argument != uid.to_string() {
        return Err("The administrator launch UID is not canonical".into());
    }
    let receipt_owner =
        gulikit_platform::journal::ReceiptOwner::from_authenticated_launcher_uid(uid)?;
    arguments.clear();
    Ok(Some(receipt_owner))
}

fn ensure_administrator_with(
    effective_uid: u32,
    receipt_owner: Option<gulikit_platform::journal::ReceiptOwner>,
    executable: impl FnOnce() -> Result<PathBuf, String>,
    real_uid: impl FnOnce() -> u32,
    request_launch: impl FnOnce(&Path, u32) -> Result<AuthorizationOutcome, String>,
) -> Result<StartupDisposition, String> {
    if effective_uid == 0 {
        return Ok(StartupDisposition::Continue { receipt_owner });
    }
    if receipt_owner.is_some() {
        return Err("A receipt owner may be supplied only by the elevated desktop launch".into());
    }

    let executable = executable()?;
    match request_launch(&executable, real_uid())? {
        AuthorizationOutcome::ChildExited | AuthorizationOutcome::Cancelled => {
            Ok(StartupDisposition::Exit)
        }
    }
}

fn request_authorized_launch(
    executable: &Path,
    real_uid: u32,
) -> Result<AuthorizationOutcome, String> {
    let home = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(0))
        .map_err(|error| format!("Could not resolve administrator cache home: {error}"))?
        .ok_or("Administrator account has no home directory")?
        .dir;
    if !home.is_absolute() {
        return Err("Administrator home directory is not absolute".into());
    }
    let output = authorized_command(executable, real_uid, &home)
        .output()
        .map_err(|error| format!("Could not request administrator authorization: {error}"))?;

    authorization_outcome(&output)
}

fn authorized_command(executable: &Path, real_uid: u32, home: &Path) -> Command {
    let mut command = Command::new(OSASCRIPT);
    // launchctl adopts the user's UI session, not their environment. The root
    // GUI needs its account's home to locate the firmware cache.
    command
        .args(osascript_arguments(executable, real_uid))
        .env_clear()
        .env("HOME", home);
    command
}

fn osascript_arguments(executable: &Path, real_uid: u32) -> [OsString; 4] {
    [
        OsString::from("-e"),
        OsString::from(AUTHORIZATION_SCRIPT),
        executable.as_os_str().to_owned(),
        OsString::from(real_uid.to_string()),
    ]
}

fn authorization_outcome(output: &Output) -> Result<AuthorizationOutcome, String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success() {
        return match stdout.trim() {
            CANCELLED_MARKER => Ok(AuthorizationOutcome::Cancelled),
            EXITED_MARKER => Ok(AuthorizationOutcome::ChildExited),
            unexpected => Err(format!(
                "Administrator-authorized updater launch returned unexpected output: {unexpected}"
            )),
        };
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "Administrator-authorized updater launch failed ({}): {}",
        output.status,
        stderr.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHORIZATION_SCRIPT, AuthorizationOutcome, StartupDisposition, ensure_administrator_with,
        osascript_arguments, take_launcher_receipt_owner,
    };
    use std::{ffi::OsString, path::PathBuf};

    #[test]
    fn root_process_continues_without_resolving_or_relaunching() {
        let result = ensure_administrator_with(
            0,
            None,
            || panic!("root process must not resolve a relaunch target"),
            || panic!("root process must not request a user id"),
            |_, _| panic!("root process must not relaunch"),
        );

        assert_eq!(
            result.unwrap(),
            StartupDisposition::Continue {
                receipt_owner: None
            }
        );
    }

    #[test]
    fn authorization_relaunch_uses_the_current_executable_and_real_uid() {
        let executable =
            PathBuf::from("/Applications/Guli Kit/ütility.app/Contents/MacOS/gulikit-ui");
        let result = ensure_administrator_with(
            501,
            None,
            || Ok(executable.clone()),
            || 502,
            |actual_path, actual_uid| {
                assert_eq!(actual_path, executable.as_path());
                assert_eq!(actual_uid, 502);
                Ok(AuthorizationOutcome::ChildExited)
            },
        );

        assert_eq!(result.unwrap(), StartupDisposition::Exit);
    }

    #[test]
    fn authorization_cancellation_exits_without_startup() {
        let result = ensure_administrator_with(
            501,
            None,
            || {
                Ok(PathBuf::from(
                    "/Applications/GuliKit Updater.app/Contents/MacOS/gulikit-ui",
                ))
            },
            || 501,
            |_, _| Ok(AuthorizationOutcome::Cancelled),
        );

        assert_eq!(result.unwrap(), StartupDisposition::Exit);
    }

    #[test]
    fn relaunch_failure_returns_a_clear_error() {
        let result = ensure_administrator_with(
            501,
            None,
            || {
                Ok(PathBuf::from(
                    "/Applications/GuliKit Updater.app/Contents/MacOS/gulikit-ui",
                ))
            },
            || 501,
            |_, _| Err("osascript: launch denied".to_owned()),
        );

        assert_eq!(result.unwrap_err(), "osascript: launch denied");
    }

    #[test]
    fn script_is_static_and_path_and_uid_are_separate_arguments() {
        let executable =
            PathBuf::from("/tmp/Guli Kit/'quoted' $folder/é.app/Contents/MacOS/gulikit-ui");
        let args = osascript_arguments(&executable, 501);

        assert_eq!(args.len(), 4);
        assert_eq!(args[0], "-e");
        assert_eq!(args[1], AUTHORIZATION_SCRIPT);
        assert_eq!(args[2], executable.as_os_str());
        assert_eq!(args[3], "501");
        assert!(AUTHORIZATION_SCRIPT.contains("--authorized-invoking-uid"));
    }

    #[test]
    fn authorized_command_sets_the_resolved_administrator_home() {
        let executable =
            PathBuf::from("/Applications/GuliKit Updater.app/Contents/MacOS/gulikit-ui");
        let home = PathBuf::from("/var/root");
        let command = super::authorized_command(&executable, 501, &home);
        assert_eq!(command.get_program(), super::OSASCRIPT);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            osascript_arguments(&executable, 501)
        );
        let environment = command.get_envs().collect::<Vec<_>>();
        assert_eq!(
            environment,
            [(std::ffi::OsStr::new("HOME"), Some(home.as_os_str()))]
        );
    }

    #[test]
    fn executable_lookup_errors_prevent_authorization_request() {
        let result = ensure_administrator_with(
            501,
            None,
            || Err("executable unavailable".to_owned()),
            || 501,
            |_, _| panic!("must not request authorization without an executable"),
        );

        assert_eq!(result.unwrap_err(), "executable unavailable");
    }

    #[test]
    fn elevated_launcher_data_contains_only_the_executable_and_real_uid() {
        let executable =
            PathBuf::from("/Applications/GuliKit Updater.app/Contents/MacOS/gulikit-ui");
        let args = osascript_arguments(&executable, 501);

        assert_eq!(
            args,
            [
                OsString::from("-e"),
                OsString::from(AUTHORIZATION_SCRIPT),
                executable.into_os_string(),
                OsString::from("501"),
            ]
        );
    }

    #[test]
    fn authorization_result_markers_distinguish_cancel_from_launch_failure() {
        use std::{
            os::unix::process::ExitStatusExt,
            process::{ExitStatus, Output},
        };

        let cancelled = super::authorization_outcome(&Output {
            status: ExitStatus::from_raw(0),
            stdout: format!("{}\n", super::CANCELLED_MARKER).into_bytes(),
            stderr: Vec::new(),
        });
        assert_eq!(cancelled.unwrap(), AuthorizationOutcome::Cancelled);

        let failed = super::authorization_outcome(&Output {
            status: ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"launchctl: failed".to_vec(),
        });
        assert_eq!(
            failed.unwrap_err(),
            "Administrator-authorized updater launch failed (exit status: 1): launchctl: failed"
        );
    }

    #[test]
    fn launcher_uid_is_accepted_only_for_the_exact_root_launch_arguments() {
        let mut arguments = vec![
            OsString::from("--authorized-invoking-uid"),
            OsString::from("501"),
        ];

        let owner = take_launcher_receipt_owner(&mut arguments, 0).unwrap();

        assert_eq!(
            owner.map(gulikit_platform::journal::ReceiptOwner::uid),
            Some(501)
        );
        assert_eq!(arguments, [] as [OsString; 0]);
    }

    #[test]
    fn launcher_uid_rejects_nonroot_malformed_and_root_receipts() {
        let mut nonroot = vec![
            OsString::from("--authorized-invoking-uid"),
            OsString::from("501"),
        ];
        assert!(take_launcher_receipt_owner(&mut nonroot, 501).is_err());

        let mut malformed = vec![
            OsString::from("--authorized-invoking-uid"),
            OsString::from("5x"),
        ];
        assert!(take_launcher_receipt_owner(&mut malformed, 0).is_err());

        let mut noncanonical = vec![
            OsString::from("--authorized-invoking-uid"),
            OsString::from("0501"),
        ];
        assert!(take_launcher_receipt_owner(&mut noncanonical, 0).is_err());

        let mut root = vec![
            OsString::from("--authorized-invoking-uid"),
            OsString::from("0"),
        ];
        assert!(take_launcher_receipt_owner(&mut root, 0).is_err());

        let mut reserved = vec![
            OsString::from("--authorized-invoking-uid"),
            OsString::from(u32::MAX.to_string()),
        ];
        assert!(take_launcher_receipt_owner(&mut reserved, 0).is_err());
    }
}
