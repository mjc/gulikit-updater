//! Real native bundles and signatures; only Apple account services are faked.
use super::*;
use std::cell::RefCell;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;

struct Fixture {
    root: tempfile::TempDir,
    binaries: PathBuf,
    arch: Architecture,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let binaries = root.path().join("native binaries");
        fs::create_dir(&binaries).unwrap();
        let source = root.path().join("help.c");
        fs::write(
            &source,
            "#include <stdio.h>\nint main(void) { puts(\"Usage: gulikit-ui\"); }\n",
        )
        .unwrap();
        for name in ["gulikit-ui", "gulikit-updater"] {
            compile(&source, &binaries.join(name), &[]);
        }
        let arch = if cfg!(target_arch = "aarch64") {
            Architecture::Arm64
        } else {
            Architecture::X86_64
        };
        Self {
            root,
            binaries,
            arch,
        }
    }

    fn stage(&self) -> PathBuf {
        stage(
            &Native,
            &self.binaries,
            &self.root.path().join("bundle"),
            "0.1.0",
            self.arch,
        )
        .unwrap()
    }

    fn release(&self, apple: &Apple, auth: &NotaryAuth<'_>) -> Result<()> {
        release(
            apple,
            &self.stage(),
            self.root.path(),
            "release",
            "Developer ID Application: Example (TEAM)",
            None,
            auth,
        )
    }
}

fn compile(source: &Path, output: &Path, extra: &[OsString]) {
    let sdk = run(
        &Native,
        "/usr/bin/xcrun",
        &args(&["--sdk", "macosx", "--show-sdk-path"]),
    )
    .unwrap();
    let mut arguments = args(&["-isysroot", sdk.trim()]);
    arguments.extend(extra.iter().cloned());
    arguments.extend([source.into(), "-o".into(), output.into()]);
    run(&Native, "/usr/bin/clang", &arguments).unwrap();
}

fn profile() -> NotaryAuth<'static> {
    NotaryAuth::Profile {
        name: "profile",
        keychain: None,
    }
}

#[test]
fn signed_archive_extracts_and_executes_with_valid_metadata() {
    let fixture = Fixture::new();
    let app = fixture.stage();
    sign(&Native, &app, "-", None).unwrap();
    let zip = fixture.root.path().join("package.zip");
    archive(&Native, &app, &zip).unwrap();
    let extracted = fixture.root.path().join("consumer folder");
    run(
        &Native,
        "/usr/bin/ditto",
        &[
            "-x".into(),
            "-k".into(),
            zip.into(),
            extracted.clone().into(),
        ],
    )
    .unwrap();
    let consumer = extracted.join(APP_NAME);
    verify(&Native, &consumer).unwrap();
    smoke(&Native, &consumer).unwrap();
    let plist = consumer.join("Contents/Info.plist");
    let json = run(
        &Native,
        "/usr/bin/plutil",
        &[
            "-convert".into(),
            "json".into(),
            "-o".into(),
            "-".into(),
            plist.into(),
        ],
    )
    .unwrap();
    let info: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(info["CFBundleShortVersionString"], "0.1.0");
    assert_eq!(info["LSMinimumSystemVersion"], "13.0");
    assert_eq!(info["LSUIElement"], true);
    assert!(
        consumer
            .join("Contents/MacOS")
            .join(info["CFBundleExecutable"].as_str().unwrap())
            .is_file()
    );
    let daemon_plist = consumer
        .join("Contents/Library/LaunchDaemons")
        .join(PLIST_NAME);
    let json = run(
        &Native,
        "/usr/bin/plutil",
        &[
            "-convert".into(),
            "json".into(),
            "-o".into(),
            "-".into(),
            daemon_plist.into(),
        ],
    )
    .unwrap();
    let daemon: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(daemon["Label"], MACH_SERVICE);
    assert_eq!(daemon["BundleProgram"], "Contents/Helpers/gulikit-updater");
    assert_eq!(
        daemon["ProgramArguments"],
        serde_json::json!(["Contents/Helpers/gulikit-updater", HELPER_ARGUMENT])
    );
    assert_eq!(
        daemon["MachServices"],
        serde_json::json!({MACH_SERVICE: true})
    );
    assert_eq!(daemon["UserName"], "root");
    assert!(daemon.get("RunAtLoad").is_none());
    assert!(daemon.get("KeepAlive").is_none());
    assert!(
        consumer
            .join(daemon["BundleProgram"].as_str().unwrap())
            .is_file()
    );
    for (target, identifier) in [
        (
            consumer.join("Contents/Helpers/gulikit-updater"),
            HELPER_IDENTIFIER,
        ),
        (consumer.clone(), APP_IDENTIFIER),
    ] {
        let output = Native
            .execute(
                "/usr/bin/codesign",
                &["--display".into(), "--verbose=4".into(), target.into()],
            )
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .any(|line| line == format!("Identifier={identifier}"))
        );
    }
}

#[test]
fn modifying_nested_cli_invalidates_signature() {
    let fixture = Fixture::new();
    let app = fixture.stage();
    sign(&Native, &app, "-", None).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(app.join("Contents/Helpers/gulikit-updater"))
        .unwrap()
        .write_all(b"modified after signing")
        .unwrap();
    assert!(matches!(verify(&Native, &app), Err(Error::Tool { .. })));
}

#[test]
fn wrong_architecture_is_refused() {
    let fixture = Fixture::new();
    let arch = match fixture.arch {
        Architecture::Arm64 => Architecture::X86_64,
        Architecture::X86_64 => Architecture::Arm64,
    };
    let error = stage(
        &Native,
        &fixture.binaries,
        &fixture.root.path().join("bundle"),
        "0.1.0",
        arch,
    )
    .unwrap_err();
    assert!(error.to_string().contains("Wrong architecture"));
}

#[test]
fn builder_only_library_is_refused() {
    let fixture = Fixture::new();
    let source = fixture.root.path().join("library.c");
    let library = fixture.root.path().join("builder-only.dylib");
    fs::write(&source, "int builder_only(void) { return 0; }\n").unwrap();
    compile(&source, &library, &args(&["-dynamiclib"]));
    fs::write(
        &source,
        "int builder_only(void); int main(void) { return builder_only(); }\n",
    )
    .unwrap();
    compile(
        &source,
        &fixture.binaries.join("gulikit-ui"),
        &[library.into()],
    );
    let error = stage(
        &Native,
        &fixture.binaries,
        &fixture.root.path().join("bundle"),
        "0.1.0",
        fixture.arch,
    )
    .unwrap_err();
    assert!(error.to_string().contains("Non-system dependency"));
}

#[test]
fn development_identity_cannot_produce_a_release() {
    let fixture = Fixture::new();
    for identity in ["-", "Apple Development: Example (TEAM)"] {
        let error = release(
            &Native,
            fixture.root.path(),
            fixture.root.path(),
            "release",
            identity,
            None,
            &profile(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Developer ID Application"));
        assert!(!fixture.root.path().join("release.zip").exists());
    }
}

struct Apple {
    accepted: bool,
    nonzero: bool,
    gatekeeper_failure: bool,
    calls: RefCell<Vec<(String, Vec<OsString>)>>,
}

impl Apple {
    fn rejected(nonzero: bool) -> Self {
        Self {
            accepted: false,
            nonzero,
            gatekeeper_failure: false,
            calls: RefCell::default(),
        }
    }
}

fn output(text: &str, failed: bool) -> Output {
    Output {
        status: std::process::ExitStatus::from_raw(if failed { 65 << 8 } else { 0 }),
        stdout: text.as_bytes().to_vec(),
        stderr: vec![],
    }
}

impl Runner for Apple {
    fn execute(&self, program: &str, arguments: &[OsString]) -> std::io::Result<Output> {
        self.calls
            .borrow_mut()
            .push((program.into(), arguments.to_vec()));
        if program == "/usr/bin/security" {
            return Ok(output(
                "1) HASH \"Developer ID Application: Example (TEAM)\"\n",
                false,
            ));
        }
        if program == "/usr/bin/xcrun" && arguments.first() == Some(&"notarytool".into()) {
            return Ok(if arguments[1] == "submit" {
                output(
                    if self.accepted {
                        r#"{"id":"request-id","status":"Accepted"}"#
                    } else {
                        r#"{"id":"request-id","status":"Invalid"}"#
                    },
                    self.nonzero,
                )
            } else {
                output(r#"{"issues":["signature rejected"]}"#, false)
            });
        }
        if program == "/usr/bin/xcrun" && arguments.first() == Some(&"stapler".into()) {
            return Ok(output("", false));
        }
        if program == "/usr/sbin/spctl" {
            return Ok(output(
                "",
                self.gatekeeper_failure
                    && arguments
                        .last()
                        .is_some_and(|path| path.to_string_lossy().contains("extracted")),
            ));
        }
        // Use actual ad-hoc signatures for fixtures in place of account signing.
        let mut arguments = arguments.to_vec();
        if program == "/usr/bin/codesign"
            && let Some(index) = arguments.iter().position(|arg| arg == "--sign")
        {
            arguments[index + 1] = "-".into();
            for argument in &mut arguments {
                if argument == "--timestamp" {
                    *argument = "--timestamp=none".into();
                }
            }
        }
        Native.execute(program, &arguments)
    }
}

fn check_rejected(nonzero: bool, auth: &NotaryAuth<'_>) -> Apple {
    let fixture = Fixture::new();
    let apple = Apple::rejected(nonzero);
    let error = fixture.release(&apple, auth).unwrap_err();
    assert!(error.to_string().contains("not accepted"));
    assert!(!fixture.root.path().join("release.zip").exists());
    assert!(
        fs::read_to_string(fixture.root.path().join("release-notary-log.json"))
            .unwrap()
            .contains("signature rejected")
    );
    apple
}

#[test]
fn rejected_notarization_retains_log_without_publishing() {
    check_rejected(false, &profile());
}

#[test]
fn failing_notarytool_retains_submission_and_log() {
    check_rejected(true, &profile());
}

#[test]
fn api_key_authentication_reaches_submission_and_log() {
    let apple = check_rejected(
        false,
        &NotaryAuth::ApiKey {
            path: Path::new("/temporary/notary-key.p8"),
            id: "KEYID",
            issuer: Some("ISSUER"),
        },
    );
    let calls = apple.calls.borrow();
    let requests: Vec<_> = calls
        .iter()
        .filter(|(program, arguments)| {
            program == "/usr/bin/xcrun" && arguments.first() == Some(&"notarytool".into())
        })
        .collect();
    assert_eq!(requests.len(), 2);
    for (_, arguments) in requests {
        for value in ["/temporary/notary-key.p8", "KEYID", "ISSUER"] {
            assert!(arguments.contains(&value.into()));
        }
        assert!(!arguments.contains(&"--keychain-profile".into()));
    }
}

#[test]
fn accepted_service_response_requires_extracted_checks_before_publication() {
    let fixture = Fixture::new();
    let mut apple = Apple::rejected(false);
    apple.accepted = true;
    fixture.release(&apple, &profile()).unwrap();
    let zip = fixture.root.path().join("release.zip");
    let digest = run(
        &Native,
        "/usr/bin/shasum",
        &["-a".into(), "256".into(), zip.into()],
    )
    .unwrap();
    let digest = digest.split_whitespace().next().unwrap();
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("release.zip.sha256")).unwrap(),
        format!("{digest}  release.zip\n")
    );
    let calls = apple.calls.borrow();
    let staple = calls
        .iter()
        .position(|(_, a)| a.get(1) == Some(&"staple".into()))
        .unwrap();
    let final_archive = calls
        .iter()
        .rposition(|(p, a)| p == "/usr/bin/ditto" && a.first() == Some(&"-c".into()))
        .unwrap();
    assert!(staple < final_archive);
    assert!(calls.iter().any(|(p, a)| p == "/usr/sbin/spctl"
        && a.last().unwrap().to_string_lossy().contains("extracted")));
    assert!(
        calls
            .iter()
            .any(|(p, _)| p.contains("extracted") && p.ends_with("gulikit-ui"))
    );
}

#[test]
fn extracted_gatekeeper_refusal_prevents_publication() {
    let fixture = Fixture::new();
    let mut apple = Apple::rejected(false);
    apple.accepted = true;
    apple.gatekeeper_failure = true;
    assert!(fixture.release(&apple, &profile()).is_err());
    assert!(!fixture.root.path().join("release.zip").exists());
    assert!(!fixture.root.path().join("release.zip.sha256").exists());
}

#[test]
fn existing_artifact_is_not_overwritten() {
    let fixture = Fixture::new();
    fs::write(fixture.root.path().join("release.zip"), "previous release").unwrap();
    assert!(
        fixture
            .release(&Apple::rejected(false), &profile())
            .is_err()
    );
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("release.zip")).unwrap(),
        "previous release"
    );
}

#[test]
fn command_line_accepts_native_architecture_names() {
    for arch in ["arm64", "x86_64"] {
        let options =
            Options::try_parse_from(["gulikit-dist", "smoke", "--binaries", ".", "--arch", arch])
                .unwrap();
        assert_eq!(options.arch.name(), arch);
    }
}
