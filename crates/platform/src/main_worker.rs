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
        unix::net::UnixStream,
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
    Ready,
    Go,
    Cancel,
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
}
impl Channel {
    pub fn new(stream: UnixStream) -> Result<Self, String> {
        stream
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            stream,
            pending: Vec::new(),
        })
    }
    pub fn from_stdin() -> Result<Self, String> {
        let fd = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| error.to_string())?;
        Self::new(UnixStream::from(fd))
    }
    pub fn send(&mut self, message: &Message) -> Result<(), String> {
        let body = serde_json::to_vec(message).map_err(|error| error.to_string())?;
        if body.len() > LIMIT {
            return Err("Main worker message exceeds bound".into());
        }
        let frame = [(body.len() as u32).to_le_bytes().as_slice(), &body].concat();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut remaining = frame.as_slice();
        while !remaining.is_empty() {
            if Instant::now() >= deadline {
                return Err("Main worker channel write deadline".into());
            }
            match self.stream.write(remaining) {
                Ok(0) => return Err("Main worker channel closed".into()),
                Ok(count) => remaining = &remaining[count..],
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(TICK)
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Option<Message>, String> {
        loop {
            if self.pending.len() >= 4 {
                let length =
                    u32::from_le_bytes(self.pending[..4].try_into().expect("four bytes")) as usize;
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
    _lease: ProcessLock,
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

pub fn guardian(parent: Channel, worker_command: Command, budget: Duration) -> Result<(), String> {
    let lease = ProcessLock::acquire()?;
    guardian_with_lease(parent, worker_command, budget, lease)
}
fn guardian_with_lease(
    mut parent: Channel,
    mut worker_command: Command,
    budget: Duration,
    lease: ProcessLock,
) -> Result<(), String> {
    let request = match parent.wait(Duration::from_secs(10))? {
        Message::Request(request) => request,
        _ => return Err("Main guardian expected a request".into()),
    };
    let (local, remote) = UnixStream::pair().map_err(|error| error.to_string())?;
    let child = worker_command
        .stdin(Stdio::from(OwnedFd::from(remote)))
        .stdout(Stdio::null())
        .stderr(Stdio::from(lease.worker_descriptor()?))
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut owned = LeasedChild {
        child,
        _lease: lease,
    };
    let mut worker = Channel::new(local)?;
    worker.send(&Message::Request(request))?;
    let deadline = Instant::now() + budget;
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
                    // Owned, unreaped Child prevents PID reuse. Only this child is signaled.
                    nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(owned.child.id() as i32),
                        nix::sys::signal::Signal::SIGINT,
                    )
                    .map_err(|error| error.to_string())?;
                    cancellation_deadline = Some(Instant::now() + Duration::from_secs(5));
                }
            }
            None => {}
            Some(_) => return Err("Unexpected Main guardian parent message".into()),
        }
        if result.is_none() {
            match worker.poll() {
                Ok(Some(Message::Ready)) if !ready && !started => {
                    ready = true;
                    parent.send(&Message::Ready)?;
                }
                Ok(Some(message @ (Message::Result(_) | Message::Failed { .. }))) => {
                    result = Some(message)
                }
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
            if result.is_none()
                && let Ok(Some(message @ (Message::Result(_) | Message::Failed { .. }))) =
                    worker.poll()
            {
                result = Some(message);
            }
            parent.send(&result.unwrap_or(Message::Unknown {
                reason: "Main worker exited without a final result".into(),
                worker_stopped: true,
            }))?;
            return Ok(());
        }
        if Instant::now() >= deadline
            || cancellation_deadline.is_some_and(|limit| Instant::now() >= limit)
        {
            parent.send(&Message::Unknown { reason: "Main I/O deadline or cancellation grace expired; guardian retains ownership until the worker is reaped".into(), worker_stopped: false })?;
            return Ok(()); // Drop kills and reaps before unlocking, without delaying the CLI report.
        }
        std::thread::sleep(TICK);
    }
}

pub fn run(
    mut guardian_command: Command,
    request: serde_json::Value,
    budget: Duration,
    mut cancelled: impl FnMut() -> bool,
) -> Result<Message, String> {
    let (local, remote) = UnixStream::pair().map_err(|error| error.to_string())?;
    let mut child = guardian_command
        .stdin(Stdio::from(OwnedFd::from(remote)))
        .stdout(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut channel = Channel::new(local)?;
    channel.send(&Message::Request(request))?;
    let deadline = Instant::now() + budget;
    let mut started = false;
    let mut cancel_sent = false;
    loop {
        if cancelled() && !cancel_sent {
            channel.send(&Message::Cancel)?;
            cancel_sent = true;
        }
        match channel.poll() {
            Ok(Some(Message::Ready)) if !started && !cancel_sent => {
                channel.send(&Message::Go)?;
                started = true;
            }
            Ok(Some(
                message @ (Message::Result(_) | Message::Failed { .. } | Message::Unknown { .. }),
            )) => return Ok(message),
            Ok(None) => {}
            Ok(Some(_)) => return Err("Unexpected Main guardian response".into()),
            Err(error) if started => {
                return Ok(Message::Unknown {
                    reason: error,
                    worker_stopped: false,
                });
            }
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Ok(if started {
                Message::Unknown { reason: "Main reporting deadline; guardian owns worker shutdown and retains the lease".into(), worker_stopped: false }
            } else {
                Message::Failed { kind: "main_worker_startup".into(), code: 5, message: "Main worker did not start before its deadline; no GO authorization was sent".into() }
            });
        }
        let _ = child.try_wait();
        std::thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "subprocess fixture; invoked by the guardian tests"]
    fn worker_fixture() {
        let mut channel = Channel::from_stdin().unwrap();
        let Message::Request(request) = channel.wait(Duration::from_secs(2)).unwrap() else {
            panic!("request");
        };
        let lock = ProcessLock::adopt_worker_descriptor_at(std::path::PathBuf::from(
            request["lock"].as_str().unwrap(),
        ))
        .unwrap();
        channel.send(&Message::Ready).unwrap();
        assert!(matches!(
            channel.wait(Duration::from_secs(2)).unwrap(),
            Message::Go
        ));
        drop(lock); // Worker closes its duplicate; the guardian still owns the lease.
        channel
            .send(&Message::Result(serde_json::json!({"completed":true})))
            .unwrap();
        if request["linger"] == true {
            std::thread::sleep(Duration::from_secs(60));
        }
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
            let guardian = std::thread::spawn(move || {
                guardian_with_lease(
                    Channel::new(remote).unwrap(),
                    fixture_command(),
                    Duration::from_millis(250),
                    lease,
                )
            });
            let mut parent = Channel::new(local).unwrap();
            parent
                .send(&Message::Request(
                    serde_json::json!({"lock":path,"linger":linger}),
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
                lease,
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
    fn channel_rejects_oversized_frames_and_incomplete_eof() {
        for bytes in [((LIMIT + 1) as u32).to_le_bytes().to_vec(), vec![1, 0]] {
            let (local, mut remote) = UnixStream::pair().unwrap();
            let mut channel = Channel::new(local).unwrap();
            remote.write_all(&bytes).unwrap();
            drop(remote);
            assert!(channel.poll().is_err());
        }
    }
}
