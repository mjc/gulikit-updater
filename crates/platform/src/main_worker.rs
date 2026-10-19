//! Main filesystem supervision. Never use this hard-stop policy for captured USB.
//!
//! The CLI can finish reporting while a guardian retains the global lease until
//! its exact I/O child has been reaped. A blocked filesystem call cannot release
//! ownership merely because the reporting deadline elapsed.

use crate::lock::ProcessLock;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const LIMIT: usize = 1_048_576;
const TICK: Duration = Duration::from_millis(10);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum Message {
    Request(serde_json::Value),
    PackageReady,
    Ready,
    Go,
    Cancel,
    Progress(gulikit_core::update::Progress),
    Result(serde_json::Value),
    Failed {
        kind: String,
        code: u8,
        message: String,
    },
    Unknown {
        reason: String,
        worker_stopped: bool,
    },
}

pub struct Channel {
    stream: UnixStream,
    pending: Vec<u8>,
    outgoing: Vec<u8>,
    written: usize,
}
impl Channel {
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be configured for nonblocking I/O.
    pub fn new(stream: UnixStream) -> Result<Self, String> {
        stream
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            stream,
            pending: Vec::new(),
            outgoing: Vec::new(),
            written: 0,
        })
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the inherited socket cannot be duplicated or configured for nonblocking I/O.
    pub fn from_stdin() -> Result<Self, String> {
        let fd = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| error.to_string())?;
        Self::new(UnixStream::from(fd))
    }
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized or unencodable message, socket write failure, closed peer, or exceeded write deadline.
    pub fn send(&mut self, message: &Message) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(1);
        self.flush_until(deadline)?;
        self.encode(message)?;
        self.flush_until(deadline)
    }

    /// Report progress without waiting for the reader. Retain a partial frame so
    /// later control messages cannot corrupt it; discard newer progress while busy.
    ///
    /// # Errors
    /// Returns socket or encoding errors. Progress failures do not cancel I/O.
    pub fn try_send_progress(
        &mut self,
        value: gulikit_core::update::Progress,
    ) -> Result<bool, String> {
        if !self.flush_pending()? {
            return Ok(false);
        }
        self.encode(&Message::Progress(value))?;
        self.flush_pending()
    }

    fn encode(&mut self, message: &Message) -> Result<(), String> {
        self.outgoing.extend_from_slice(&[0; 4]);
        if let Err(error) = serde_json::to_writer(&mut self.outgoing, message) {
            self.outgoing.clear();
            return Err(error.to_string());
        }
        let length = self.outgoing.len() - 4;
        if length > LIMIT {
            self.outgoing.clear();
            return Err("Main worker message exceeds bound".into());
        }
        let length = u32::try_from(length).map_err(|_| "Main worker message exceeds bound")?;
        self.outgoing[..4].copy_from_slice(&length.to_le_bytes());
        Ok(())
    }

    fn flush_until(&mut self, deadline: Instant) -> Result<(), String> {
        while !self.flush_pending()? {
            if Instant::now() >= deadline {
                return Err("Main worker channel write deadline".into());
            }
            std::thread::sleep(TICK);
        }
        Ok(())
    }

    fn flush_pending(&mut self) -> Result<bool, String> {
        while self.written < self.outgoing.len() {
            match self.stream.write(&self.outgoing[self.written..]) {
                Ok(0) => return Err("Main worker channel closed".into()),
                Ok(count) => self.written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(false);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        self.outgoing.clear();
        self.written = 0;
        Ok(true)
    }
    ///
    /// # Errors
    ///
    /// Returns an error for oversized or invalid frames, a closed peer, or a socket read failure.
    pub fn poll(&mut self) -> Result<Option<Message>, String> {
        loop {
            if let [a, b, c, d, ..] = self.pending.as_slice() {
                let length = usize::try_from(u32::from_le_bytes([*a, *b, *c, *d]))
                    .map_err(|_| "Main worker message exceeds bound")?;
                if length > LIMIT {
                    return Err("Main worker message exceeds bound".into());
                }
                if self.pending.len() >= length + 4 {
                    let result = serde_json::from_slice(&self.pending[4..length + 4])
                        .map_err(|error| error.to_string())?;
                    self.pending.drain(..length + 4);
                    return Ok(Some(result));
                }
            }
            let mut buffer = [0; 4096];
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err("Main worker channel closed".into()),
                Ok(count) => {
                    self.pending.extend_from_slice(&buffer[..count]);
                    if self.pending.len() > LIMIT + 4 {
                        return Err("Main worker message exceeds bound".into());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    }
    ///
    /// # Errors
    ///
    /// Returns a framing or socket error from polling, or an error when the read deadline expires.
    pub fn wait(&mut self, timeout: Duration) -> Result<Message, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(message) = self.poll()? {
                return Ok(message);
            }
            if Instant::now() >= deadline {
                return Err("Main worker channel read deadline".into());
            }
            std::thread::sleep(TICK);
        }
    }
}

/// The lease outlives the child, including during panic/EOF/error unwinding.
struct LeasedChild {
    child: Child,
    lease: Option<ProcessLock>,
}
impl LeasedChild {
    fn grant_lease(&mut self, socket: &UnixStream) -> Result<(), String> {
        if self.lease.is_none() {
            self.lease = Some(ProcessLock::acquire()?);
        }
        let descriptor = self
            .lease
            .as_ref()
            .ok_or("Main guardian has no lease")?
            .worker_descriptor()?;
        send_lease(socket, &descriptor)
    }

    fn interrupt(&self) -> Result<(), String> {
        // The owned, unreaped Child prevents PID reuse; never signal a wrapped PID.
        let pid = i32::try_from(self.child.id())
            .map_err(|_| "Main worker PID exceeds the platform range")?;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGINT,
        )
        .map_err(|error| error.to_string())
    }
}

impl Drop for LeasedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Delivery of SIGKILL is not proof that blocked kernel I/O has stopped.
        // Retain ownership on every wait error; this headless guardian may linger.
        loop {
            if self.child.wait().is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

///
/// # Errors
///
/// Returns an error for invalid parent or worker protocol, failed process or channel operations, or lease acquisition and transfer failures. Cleanup retains the lease until the exact child is reaped.
pub fn guardian(parent: Channel, worker_command: Command, budget: Duration) -> Result<(), String> {
    guardian_with_lease(parent, worker_command, budget, None)
}
fn guardian_with_lease(
    parent: Channel,
    worker_command: Command,
    budget: Duration,
    lease: Option<ProcessLock>,
) -> Result<(), String> {
    guardian_with_clock(parent, worker_command, budget, lease, Instant::now)
}
fn guardian_with_clock(
    mut parent: Channel,
    mut worker_command: Command,
    budget: Duration,
    lease: Option<ProcessLock>,
    now: impl Fn() -> Instant,
) -> Result<(), String> {
    let Message::Request(request) = parent.wait(Duration::from_secs(10))? else {
        return Err("Main guardian expected a request".into());
    };
    let (local, remote) = UnixStream::pair().map_err(|error| error.to_string())?;
    let (lease_sender, lease_receiver) = UnixStream::pair().map_err(|error| error.to_string())?;
    lease_sender
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|error| error.to_string())?;
    let child = worker_command
        .stdin(Stdio::from(OwnedFd::from(remote)))
        .stdout(Stdio::null())
        .stderr(Stdio::from(OwnedFd::from(lease_receiver)))
        .spawn()
        .map_err(|error| error.to_string())?;
    // Command retains configured Stdio handles for reuse. Close its peer copy
    // so worker EOF is observable when the actual child exits.
    drop(worker_command);
    let mut owned = LeasedChild { child, lease };
    let mut worker = Channel::new(local)?;
    worker.send(&Message::Request(request))?;
    let deadline = now() + budget;
    let mut lease_sent = false;
    let mut ready = false;
    let mut started = false;
    let mut result = None;
    let mut cancellation_deadline = None;
    loop {
        match parent.poll()? {
            Some(Message::Go) if ready && !started => {
                worker.send(&Message::Go)?;
                started = true;
            }
            Some(Message::Cancel) => {
                if !started {
                    return Err("Cancelled before Main worker authorization".into());
                }
                if cancellation_deadline.is_none() {
                    owned.interrupt()?;
                    cancellation_deadline = Some(now() + Duration::from_secs(5));
                }
            }
            None => {}
            Some(_) => return Err("Unexpected Main guardian parent message".into()),
        }
        if result.is_none() {
            match poll_worker(&mut worker, &mut parent, started) {
                Ok(Some(Message::PackageReady)) if !lease_sent && !ready && !started => {
                    owned.grant_lease(&lease_sender)?;
                    lease_sent = true;
                }
                Ok(Some(Message::Ready)) if lease_sent && !ready && !started => {
                    ready = true;
                    parent.send(&Message::Ready)?;
                }
                Ok(Some(message @ Message::Result(_))) if started => result = Some(message),
                Ok(Some(message @ Message::Failed { .. })) => result = Some(message),
                Ok(None) => {}
                Ok(Some(_)) => return Err("Unexpected Main I/O worker message".into()),
                Err(error) => {
                    // A final frame may be absent because the worker failed or was killed.
                    if owned.child.try_wait().map_err(|e| e.to_string())?.is_some() {
                        parent.send(&Message::Unknown {
                            reason: error,
                            worker_stopped: true,
                        })?;
                        return Ok(());
                    }
                }
            }
        }
        if owned
            .child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            if result.is_none() {
                result = drain_final_response(&mut worker, &mut parent, started)?;
            }
            parent.send(&result.unwrap_or_else(|| Message::Unknown {
                reason: "Main worker exited without a final result".into(),
                worker_stopped: true,
            }))?;
            return Ok(());
        }
        if now() >= deadline || cancellation_deadline.is_some_and(|limit| now() >= limit) {
            parent.send(&Message::Unknown { reason: "Main I/O deadline or cancellation grace expired; guardian retains ownership until the worker is reaped".into(), worker_stopped: false })?;
            return Ok(()); // Drop kills and reaps before unlocking, without delaying the CLI report.
        }
        std::thread::sleep(TICK);
    }
}

fn drain_final_response(
    worker: &mut Channel,
    parent: &mut Channel,
    started: bool,
) -> Result<Option<Message>, String> {
    match poll_worker(worker, parent, started) {
        Ok(Some(message @ Message::Result(_))) if started => Ok(Some(message)),
        Ok(Some(message @ Message::Failed { .. })) => Ok(Some(message)),
        Ok(None) | Err(_) => Ok(None),
        Ok(Some(_)) => Err("Main worker exited in an unexpected protocol phase".into()),
    }
}

fn poll_worker(
    worker: &mut Channel,
    parent: &mut Channel,
    started: bool,
) -> Result<Option<Message>, String> {
    loop {
        match worker.poll()? {
            Some(Message::Progress(value)) if started => {
                let _ = parent.try_send_progress(value);
            }
            message => return Ok(message),
        }
    }
}

///
/// # Errors
///
/// Returns an error if the guardian cannot be started or its reporting channel fails before a final response. Unknown results retain their explicit worker-stopped evidence.
pub fn run(
    guardian_command: Command,
    request: serde_json::Value,
    budget: Duration,
    cancelled: impl FnMut() -> bool,
) -> Result<Message, String> {
    run_with_progress(guardian_command, request, budget, cancelled, |_| {})
}

/// Run a supervised filesystem operation and forward observed progress.
///
/// # Errors
/// Reports guardian startup or channel failures. Reporting failures after GO
/// retain an unknown outcome and the guardian's ownership of its worker.
pub fn run_with_progress(
    mut guardian_command: Command,
    request: serde_json::Value,
    budget: Duration,
    mut cancelled: impl FnMut() -> bool,
    mut progress: impl FnMut(gulikit_core::update::Progress),
) -> Result<Message, String> {
    // Terminal signals reach the reporting process. It forwards cancellation to
    // the owned I/O child; the guardian must survive to retain its lease.
    guardian_command.process_group(0);
    let (local, remote) = UnixStream::pair().map_err(|error| error.to_string())?;
    let mut child = guardian_command
        .stdin(Stdio::from(OwnedFd::from(remote)))
        .stdout(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    // Otherwise this process would retain the guardian's socket endpoint and
    // hide guardian EOF until the outer deadline.
    drop(guardian_command);
    std::thread::Builder::new()
        .name("main-guardian-reaper".into())
        .spawn(move || {
            let _ = child.wait();
        })
        .map_err(|error| error.to_string())?;
    let mut channel = Channel::new(local)?;
    channel.send(&Message::Request(request))?;
    let deadline = Instant::now() + budget;
    let mut started = false;
    let mut cancel_sent = false;
    loop {
        if cancelled() && !cancel_sent {
            if let Err(error) = channel.send(&Message::Cancel) {
                return Ok(reporting_failure(started, error));
            }
            cancel_sent = true;
        }
        match channel.poll() {
            Ok(Some(Message::Ready)) if !started && !cancel_sent => {
                if let Err(error) = channel.send(&Message::Go) {
                    return Ok(reporting_failure(false, error));
                }
                started = true;
            }
            Ok(Some(Message::Progress(value))) if started => progress(value),
            Ok(Some(Message::Unknown { reason, .. })) if !started => {
                return Ok(reporting_failure(false, reason));
            }
            Ok(Some(Message::Result(_))) if !started => {
                return Ok(reporting_failure(
                    false,
                    "Main worker returned a result before GO".into(),
                ));
            }
            Ok(Some(
                message @ (Message::Result(_) | Message::Failed { .. } | Message::Unknown { .. }),
            )) => return Ok(message),
            Ok(None) => {}
            Ok(Some(_)) => {
                return Ok(reporting_failure(
                    started,
                    "Unexpected Main guardian response".into(),
                ));
            }
            Err(error) => return Ok(reporting_failure(started, error)),
        }
        if Instant::now() >= deadline {
            return Ok(if started {
                Message::Unknown { reason: "Main reporting deadline; guardian owns worker shutdown and retains the lease".into(), worker_stopped: false }
            } else {
                Message::Failed { kind: "main_worker_startup".into(), code: 5, message: "Main worker did not start before its deadline; no GO authorization was sent".into() }
            });
        }
        std::thread::sleep(TICK);
    }
}

fn send_lease(socket: &UnixStream, file: &std::fs::File) -> Result<(), String> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::{io::IoSlice, mem::MaybeUninit};
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let descriptors = [file.as_fd()];
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err("Main lease message exceeds its bound".into());
    }
    let count = sendmsg(
        socket,
        &[IoSlice::new(b"L")],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(|error| error.to_string())?;
    if count != 1 {
        return Err("Incomplete Main lease descriptor handoff".into());
    }
    Ok(())
}

fn reporting_failure(started: bool, reason: String) -> Message {
    if started {
        Message::Unknown {
            reason,
            worker_stopped: false,
        }
    } else {
        Message::Failed {
            kind: "main_worker_startup".into(),
            code: 5,
            message: format!("{reason}; no GO authorization was sent"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_progress_does_not_wait_or_corrupt_the_final_result() {
        let (mut local, mut remote) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        let padding = [0_u8; 8192];
        let mut buffered_bytes = 0;
        loop {
            match local.write(&padding) {
                Ok(count) => buffered_bytes += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                result => panic!("{result:?}"),
            }
        }
        let mut writer = Channel::new(local).unwrap();
        let started = Instant::now();
        for confirmed in 0..1000 {
            assert!(
                !writer
                    .try_send_progress(gulikit_core::update::Progress {
                        submitted: confirmed,
                        confirmed,
                        total: 1000
                    })
                    .unwrap()
            );
        }
        assert!(started.elapsed() < Duration::from_millis(500));
        let mut drained = vec![0; buffered_bytes];
        remote.read_exact(&mut drained).unwrap();
        writer
            .send(&Message::Result(serde_json::json!({"complete":true})))
            .unwrap();
        let mut reader = Channel::new(remote).unwrap();
        assert!(
            matches!(reader.poll().unwrap(), Some(Message::Progress(value)) if value.confirmed == 0)
        );
        assert!(
            matches!(reader.poll().unwrap(), Some(Message::Result(value)) if value["complete"] == true)
        );
    }
    #[test]
    #[ignore = "subprocess fixture; invoked by the guardian tests"]
    fn worker_fixture() {
        let mut channel = Channel::from_stdin().unwrap();
        let Message::Request(request) = channel.wait(Duration::from_secs(2)).unwrap() else {
            panic!("request");
        };
        channel.send(&Message::PackageReady).unwrap();
        let lock = ProcessLock::adopt_worker_descriptor_at(std::path::PathBuf::from(
            request["lock"].as_str().unwrap(),
        ))
        .unwrap();
        if request["early_result"] == true {
            channel
                .send(&Message::Result(serde_json::json!({"completed":true})))
                .unwrap();
            return;
        }
        channel.send(&Message::Ready).unwrap();
        assert!(matches!(
            channel.wait(Duration::from_secs(2)).unwrap(),
            Message::Go
        ));
        drop(lock); // Worker closes its duplicate; the guardian still owns the lease.
        if request["progress"] == true {
            for confirmed in [0, 512, 1024] {
                channel
                    .send(&Message::Progress(gulikit_core::update::Progress {
                        submitted: confirmed,
                        confirmed,
                        total: 1024,
                    }))
                    .unwrap();
            }
        }
        channel
            .send(&Message::Result(serde_json::json!({"completed":true,"process_group":nix::unistd::getpgrp().as_raw()})))
            .unwrap();
        if request["linger"] == true {
            if let Some(marker) = request["result_marker"].as_str() {
                std::fs::write(marker, b"result sent").unwrap();
            }
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    #[test]
    #[ignore = "subprocess guardian fixture; invoked by reporter tests"]
    fn guardian_fixture() {
        let path = std::path::PathBuf::from(std::env::var_os("GULIKIT_TEST_LEASE").unwrap());
        let lease = ProcessLock::at(&path).unwrap();
        guardian_with_lease(
            Channel::from_stdin().unwrap(),
            fixture_command(),
            Duration::from_secs(2),
            Some(lease),
        )
        .unwrap();
    }
    #[test]
    fn a_result_before_go_cannot_claim_a_completed_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lease");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "main_worker::tests::guardian_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("GULIKIT_TEST_LEASE", &path);
        let response = run(
            command,
            serde_json::json!({"lock":path,"early_result":true}),
            Duration::from_secs(3),
            || false,
        )
        .unwrap();
        let Message::Failed { code, message, .. } = response else {
            panic!("{response:?}");
        };
        assert_eq!(code, 5);
        assert!(
            !message.contains("deadline"),
            "A closed guardian must be observed immediately: {message}"
        );
    }
    #[test]
    fn progress_is_forwarded_before_the_reaped_workers_final_result() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lease");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "main_worker::tests::guardian_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("GULIKIT_TEST_LEASE", &path);
        let mut observed = Vec::new();
        let response = run_with_progress(
            command,
            serde_json::json!({"lock":path,"progress":true}),
            Duration::from_secs(3),
            || false,
            |value| observed.push(value),
        )
        .unwrap();
        assert!(matches!(response, Message::Result(_)), "{response:?}");
        assert_eq!(
            observed
                .iter()
                .map(|value| value.confirmed)
                .collect::<Vec<_>>(),
            [0, 512, 1024]
        );
        assert!(
            observed
                .iter()
                .all(|value| value.total == 1024 && value.confirmed == value.submitted)
        );
    }

    #[test]
    fn terminal_interruption_is_forwarded_by_the_reporter_instead_of_killing_the_guardian() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lease");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "main_worker::tests::guardian_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("GULIKIT_TEST_LEASE", &path);
        let response = run(
            command,
            serde_json::json!({"lock":path,"linger":false}),
            Duration::from_secs(3),
            || false,
        )
        .unwrap();
        let Message::Result(result) = response else {
            panic!("{response:?}");
        };
        assert_ne!(
            result["process_group"].as_i64().unwrap(),
            i64::from(nix::unistd::getpgrp().as_raw())
        );
        assert_eq!(result["completed"], true);
    }
    fn fixture_command() -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "main_worker::tests::worker_fixture",
            "--ignored",
            "--nocapture",
        ]);
        command
    }
    #[test]
    fn guardian_requires_child_exit_before_success_and_bounds_a_lingering_worker() {
        for linger in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("lease");
            let lease = ProcessLock::at(&path).unwrap();
            let (local, remote) = UnixStream::pair().unwrap();
            let marker = directory.path().join("result-sent");
            let observed_marker = marker.clone();
            let start = Instant::now();
            let guardian = std::thread::spawn(move || {
                guardian_with_clock(
                    Channel::new(remote).unwrap(),
                    fixture_command(),
                    Duration::from_secs(1),
                    Some(lease),
                    move || {
                        if observed_marker.is_file() {
                            start + Duration::from_secs(2)
                        } else {
                            start
                        }
                    },
                )
            });
            let mut parent = Channel::new(local).unwrap();
            parent
                .send(&Message::Request(
                    serde_json::json!({"lock":path,"linger":linger,"result_marker":marker}),
                ))
                .unwrap();
            assert!(matches!(
                parent.wait(Duration::from_secs(2)).unwrap(),
                Message::Ready
            ));
            parent.send(&Message::Go).unwrap();
            let message = parent.wait(Duration::from_secs(2)).unwrap();
            if linger {
                assert!(matches!(
                    message,
                    Message::Unknown {
                        worker_stopped: false,
                        ..
                    }
                ));
            } else {
                assert!(matches!(message, Message::Result(_)));
            }
            guardian.join().unwrap().unwrap();
            ProcessLock::at(&path).unwrap();
        }
    }
    #[test]
    fn parent_disconnect_stops_worker_before_releasing_the_lease() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lease");
        let lease = ProcessLock::at(&path).unwrap();
        let (local, remote) = UnixStream::pair().unwrap();
        let guardian = std::thread::spawn(move || {
            guardian_with_lease(
                Channel::new(remote).unwrap(),
                fixture_command(),
                Duration::from_secs(2),
                Some(lease),
            )
        });
        let mut parent = Channel::new(local).unwrap();
        parent
            .send(&Message::Request(
                serde_json::json!({"lock":path,"linger":true}),
            ))
            .unwrap();
        assert!(matches!(
            parent.wait(Duration::from_secs(2)).unwrap(),
            Message::Ready
        ));
        assert!(ProcessLock::at(&path).is_err());
        drop(parent); // No GO, so the worker cannot begin device operations.
        assert!(guardian.join().unwrap().is_err());
        ProcessLock::at(&path).unwrap();
    }
    #[test]
    fn reporting_failures_preserve_uncertainty_only_after_go() {
        for reason in ["cancel send failed", "protocol failure", "channel closed"] {
            assert!(matches!(
                reporting_failure(true, reason.into()),
                Message::Unknown {
                    worker_stopped: false,
                    ..
                }
            ));
            assert!(matches!(
                reporting_failure(false, reason.into()),
                Message::Failed { code: 5, .. }
            ));
        }
    }
    #[test]
    fn channel_sends_exact_length_prefixed_json_for_consecutive_messages() {
        let (local, mut remote) = UnixStream::pair().unwrap();
        let mut channel = Channel::new(local).unwrap();
        for message in [
            Message::Request(serde_json::json!({"payload":"µ\n\"".repeat(1024)})),
            Message::Go,
        ] {
            let expected = serde_json::to_vec(&message).unwrap();
            channel.send(&message).unwrap();
            let mut prefix = [0; 4];
            remote.read_exact(&mut prefix).unwrap();
            assert_eq!(u32::from_le_bytes(prefix) as usize, expected.len());
            let mut body = vec![0; expected.len()];
            remote.read_exact(&mut body).unwrap();
            assert_eq!(body, expected);
        }
    }

    #[test]
    fn channel_rejects_oversized_frames_and_incomplete_eof() {
        for bytes in [
            u32::try_from(LIMIT + 1).unwrap().to_le_bytes().to_vec(),
            vec![1, 0],
        ] {
            let (local, mut remote) = UnixStream::pair().unwrap();
            let mut channel = Channel::new(local).unwrap();
            remote.write_all(&bytes).unwrap();
            drop(remote);
            assert!(channel.poll().is_err());
        }
    }
}
