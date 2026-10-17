//! macOS ownership boundary. The small Objective-C bridge uses the shipped SDK;
//! all firmware, version, BOT and transaction decisions remain in the shared core.
#![allow(unsafe_code)]

use crate::volume::Volume;
use gulikit_core::{
    bot::{self, BulkIo, Direction, validate_status},
    device::{Candidate, Discovery},
    update::{BluetoothPort, CompletionDecision, CompletionObservation, MainPort},
    version::MainVersion,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, c_char, c_void},
    fs::File,
    path::PathBuf,
    process::Command,
    ptr::NonNull,
    time::{Duration, Instant},
};

unsafe extern "C" {
    fn gu_snapshot() -> *mut c_char;
    fn gu_free(value: *mut c_void);
    fn gu_watch_open() -> *mut c_void;
    fn gu_watch_epoch(value: *mut c_void) -> u64;
    fn gu_watch_state(value: *mut c_void, epoch: *mut u64, arrivals: *mut u64);
    fn gu_watch_close(value: *mut c_void);
    fn gu_usb_open(id: u64, error: *mut c_char, capacity: usize) -> *mut c_void;
    fn gu_usb_transfer(
        value: *mut c_void,
        input: i32,
        bytes: *mut u8,
        length: usize,
        timeout: f64,
        actual: *mut usize,
        timed_out: *mut i32,
        error: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn gu_usb_close(value: *mut c_void, surrender: i32);
    fn gu_usb_max_lun(value: *mut c_void, lun: *mut u8, error: *mut c_char, capacity: usize)
    -> i32;
    fn gu_entry_hold(id: u64) -> u32;
    fn gu_entry_release(entry: u32);
    fn gu_usb_endpoint_status(
        value: *mut c_void,
        input: i32,
        address: *mut u8,
        status: *mut u16,
        error: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn gu_usb_description(value: *mut c_void) -> *mut c_char;
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Disk {
    pub bsd: String,
    pub mount: PathBuf,
    pub writable: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NativeCandidate {
    pub ancestor: u64,
    pub generation: u64,
    pub main_access: bool,
    /// A correlated command path; successful F1 is separate protocol evidence.
    pub bluetooth_transport_candidate: bool,
    pub observed_profile: bool,
    pub conflicting_model: bool,
    pub disks: Vec<Disk>,
    pub mount: Option<PathBuf>,
}
impl NativeCandidate {
    fn core(&self) -> Candidate {
        Candidate {
            ancestor: self.ancestor,
            generation: self.generation,
            main_access: self.main_access,
            bluetooth_access: self.bluetooth_transport_candidate,
            observed_profile: self.observed_profile,
            conflicting_model: self.conflicting_model,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub candidates: Vec<NativeCandidate>,
    pub incomplete: Vec<String>,
}
impl Snapshot {
    pub fn select(&self, confirmed: bool) -> Result<NativeCandidate, String> {
        let selected = Discovery {
            candidates: self.candidates.iter().map(NativeCandidate::core).collect(),
            incomplete: self.incomplete.clone(),
        }
        .select(confirmed)
        .map_err(|e| e.to_string())?;
        self.candidates
            .iter()
            .find(|c| c.ancestor == selected.ancestor)
            .cloned()
            .ok_or_else(|| "Selected attachment vanished".into())
    }
}
pub fn discover() -> Result<Snapshot, String> {
    // SAFETY: gu_snapshot returns an owned, NUL-terminated allocation or null;
    // gu_free is its matching allocator. No borrowed bridge storage escapes.
    unsafe {
        let ptr = NonNull::new(gu_snapshot()).ok_or("Native enumeration allocation failed")?;
        let bytes = CStr::from_ptr(ptr.as_ptr()).to_bytes();
        let result = serde_json::from_slice(bytes)
            .map_err(|e| format!("{e}; native snapshot={}", String::from_utf8_lossy(bytes)));
        gu_free(ptr.as_ptr().cast());
        result
    }
}

struct Watch {
    ptr: NonNull<c_void>,
    epoch: u64,
    arrivals: u64,
}
impl Watch {
    fn new() -> Result<Self, String> {
        // SAFETY: unique opaque owner, released once in Drop. Bridge synchronizes callbacks.
        let ptr =
            NonNull::new(unsafe { gu_watch_open() }).ok_or("USB topology watcher unavailable")?;
        let mut epoch = 0;
        let mut arrivals = 0;
        unsafe {
            gu_watch_state(ptr.as_ptr(), &mut epoch, &mut arrivals);
        }
        Ok(Self {
            ptr,
            epoch,
            arrivals,
        })
    }
    fn unchanged(&self) -> bool {
        unsafe { gu_watch_epoch(self.ptr.as_ptr()) == self.epoch }
    }
    fn changes(&self) -> (u64, u64) {
        let mut epoch = 0;
        let mut arrivals = 0;
        unsafe {
            gu_watch_state(self.ptr.as_ptr(), &mut epoch, &mut arrivals);
        }
        (
            epoch.saturating_sub(self.epoch),
            arrivals.saturating_sub(self.arrivals),
        )
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        unsafe {
            gu_watch_close(self.ptr.as_ptr());
        }
    }
}

/// Owns one updater-wide process lock and the physical USB attachment watcher.
/// Unknown future bootloader identities are outside this build's discovery coverage.
pub struct Session {
    pub target: NativeCandidate,
    watch: Watch,
    lock: crate::lock::ProcessLock,
    service: u32,
}
impl Session {
    /// Create the host audit log relative to an open directory, excluding device volumes.
    pub fn create_record(&mut self, path: &std::path::Path) -> Result<File, String> {
        use nix::{
            fcntl::{OFlag, open, openat},
            sys::stat::Mode,
        };
        use std::os::unix::fs::MetadataExt;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let name = path
            .file_name()
            .ok_or("Attempt record requires a filename")?;
        let dir = File::from(
            open(
                parent,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        let device = dir.metadata().map_err(|e| e.to_string())?.dev();
        for disk in &self.target.disks {
            if !disk.mount.as_os_str().is_empty()
                && std::fs::metadata(&disk.mount)
                    .map_err(|e| e.to_string())?
                    .dev()
                    == device
            {
                return Err(
                    "Attempt records must be stored on the host, outside the controller volume"
                        .into(),
                );
            }
        }
        Ok(File::from(
            openat(
                &dir,
                name,
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|e| e.to_string())?,
        ))
    }
    pub fn open(confirmed: bool) -> Result<Self, String> {
        let lock = crate::lock::ProcessLock::acquire()?;
        let watch = Watch::new()?;
        let target = discover()?.select(confirmed)?;
        let service = unsafe { gu_entry_hold(target.ancestor) };
        if service == 0 {
            return Err("Selected physical attachment disappeared".into());
        }
        let session = Self {
            target,
            watch,
            lock,
            service,
        };
        session.check()?;
        Ok(session)
    }
    pub fn check(&self) -> Result<(), String> {
        self.lock.check()?;
        if !self.watch.unchanged() {
            return Err("USB topology changed; this session is invalidated. Rediscover and confirm the controller again.".into());
        }
        let current = discover()?.select(true)?;
        if current != self.target {
            return Err("Selected attachment changed".into());
        }
        if !self.watch.unchanged() {
            return Err("USB topology changed during discovery".into());
        }
        Ok(())
    }
    pub fn main(self) -> Result<MainSession, String> {
        use std::os::unix::fs::MetadataExt;
        self.check()?;
        let mount = self
            .target
            .mount
            .as_ref()
            .ok_or("Main volume is not mounted")?;
        let disk = self
            .target
            .disks
            .iter()
            .find(|disk| disk.mount == *mount && disk.writable)
            .ok_or("Selected mount is not a writable device volume")?;
        let device = std::fs::metadata(PathBuf::from("/dev").join(&disk.bsd))
            .map_err(|e| e.to_string())?
            .rdev();
        let volume = Volume::open_on_device(mount, device)?;
        self.check()?;
        Ok(MainSession {
            session: self,
            volume,
        })
    }
    pub fn bluetooth(self) -> Result<BluetoothSession, String> {
        self.check()?;
        let mut port = BluetoothSession {
            session: self,
            usb: None,
            unmounted: Vec::new(),
            finished: false,
            last_opcode: 0,
            continuation_used: false,
        };
        let result = (|| {
            for disk in port.session.target.disks.clone() {
                if !disk.mount.as_os_str().is_empty() {
                    port.session.check()?;
                    port.unmounted.push(disk.bsd.clone());
                    diskutil("unmount", &disk.bsd)?;
                }
            }
            port.session.check_transport()?;
            let mut error = [0i8; 1024];
            // SAFETY: bridge consumes only this ID and writes at most error.len() bytes.
            port.usb = NonNull::new(unsafe {
                gu_usb_open(
                    port.session.target.ancestor,
                    error.as_mut_ptr(),
                    error.len(),
                )
            })
            .map(|ptr| {
                bot::Session::new(NativeUsb {
                    ptr: Some(ptr),
                    diagnostic: false,
                    tag: 0,
                    zero_input_timeout: false,
                })
            });
            if port.usb.is_none() {
                return Err(error_string(&error));
            }
            port.session.check_transport()?;
            port.usb
                .as_mut()
                .ok_or("No USB claim")?
                .qualify_addressing()?;
            port.session.check_transport()?;
            Ok(())
        })();
        if let Err(error) = result {
            let cleanup = port.finish();
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; cleanup requires attention: {cleanup}"),
            });
        }
        Ok(port)
    }
    // Quiescing storage can remove its logical mount. Still require all physical
    // candidates, the selected ancestor and live watcher, never a cached mount path.
    fn check_transport(&self) -> Result<(), String> {
        self.lock.check()?;
        if !self.watch.unchanged() {
            return Err("USB topology changed during transport ownership".into());
        }
        let snapshot = discover()?;
        let selected = Discovery {
            candidates: snapshot
                .candidates
                .iter()
                .map(|c| {
                    let mut c = c.core();
                    c.main_access = c.ancestor == self.target.ancestor;
                    c
                })
                .collect(),
            incomplete: snapshot.incomplete,
        }
        .select(true)
        .map_err(|e| e.to_string())?;
        if selected.ancestor != self.target.ancestor
            || selected.generation != self.target.generation
            || !self.watch.unchanged()
        {
            return Err("Transport attachment changed".into());
        }
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            gu_entry_release(self.service);
        }
    }
}
fn error_string(bytes: &[i8]) -> String {
    let bytes: Vec<u8> = bytes
        .iter()
        .map(|b| *b as u8)
        .take_while(|b| *b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
fn diskutil(action: &str, bsd: &str) -> Result<(), String> {
    if !bsd.starts_with("disk") || !bsd.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("Invalid OS disk identifier".into());
    }
    let output = crate::process::run_with_deadline(
        Command::new("/usr/sbin/diskutil").args([action, bsd]),
        Duration::from_secs(30),
    )?;
    if !output.status.success() {
        return Err(format!(
            "diskutil {action} refused: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub struct MainSession {
    session: Session,
    volume: Volume,
}
impl MainSession {
    pub fn target(&self) -> &NativeCandidate {
        &self.session.target
    }
}
impl MainPort for MainSession {
    fn prepare_write(&mut self) -> Result<(), String> {
        Err("Native Main writes remain gated until filesystem durability and completion qualification succeed".into())
    }
    fn read_version(&mut self) -> Result<Vec<u8>, String> {
        self.session.check()?;
        let raw = self.volume.read_version()?;
        self.check_session()?;
        Ok(raw)
    }
    fn check_session(&mut self) -> Result<(), String> {
        self.session.check()?;
        self.volume.check_root()
    }
    fn create_destination(&mut self) -> Result<(), String> {
        self.prepare_write()?;
        self.check_session()?;
        self.volume.create()
    }
    fn write(&mut self, bytes: &[u8]) -> Result<usize, String> {
        self.check_session()?;
        self.volume.write(bytes)
    }
    fn flush(&mut self) -> Result<(), String> {
        self.volume.flush()
    }
    fn close(&mut self) -> Result<(), String> {
        self.volume.close()
    }
    // No separate qualified volume-flush API is claimed. File sync_all precedes checked close.
    fn volume_flush(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn wait_for_completion(&mut self, cancelled: &mut dyn FnMut() -> bool) -> Result<bool, String> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(120) {
            if cancelled() {
                return Err(
                    "Cancelled while awaiting Main completion after firmware submission".into(),
                );
            }
            let snapshot = discover()?;
            let (events, arrivals) = self.session.watch.changes();
            match (CompletionObservation {selected_present:snapshot.candidates.iter().any(|c|c.ancestor==self.session.target.ancestor),other_candidate_present:snapshot.candidates.iter().any(|c|c.ancestor!=self.session.target.ancestor),discovery_complete:snapshot.incomplete.is_empty(),usb_events:events,usb_arrivals:arrivals}).decision(){
                CompletionDecision::ExpectedDetach=>return Ok(true),
                CompletionDecision::Invalidated=>return Err("Unexpected topology change or incomplete discovery while awaiting Main completion".into()),
                CompletionDecision::Pending=>{}
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(false)
    }
    fn finish(&mut self) -> Result<(), String> {
        self.volume.close()
    }
}

struct NativeUsb {
    ptr: Option<NonNull<c_void>>,
    diagnostic: bool,
    tag: u32,
    zero_input_timeout: bool,
}
impl NativeUsb {
    fn pointer(&self) -> Result<NonNull<c_void>, String> {
        self.ptr.ok_or_else(|| "USB claim is closed".into())
    }
    fn close(mut self, surrender: bool) {
        if let Some(ptr) = self.ptr.take() {
            // SAFETY: unique bridge ownership, consumed exactly once. Explicit
            // destruction precedes ARC release; later destruction is idempotent.
            unsafe {
                gu_usb_close(ptr.as_ptr(), i32::from(surrender));
            }
        }
    }
}
impl Drop for NativeUsb {
    fn drop(&mut self) {
        // Panic/early-drop must never choose reset after an unknown F0. Normal
        // read-only reset/restoration is an explicit successful finish phase.
        if let Some(ptr) = self.ptr.take() {
            unsafe {
                gu_usb_close(ptr.as_ptr(), 1);
            }
        }
    }
}
fn transfer_result(result: i32, actual: usize, bytes: &[u8], error: &str) -> Result<usize, String> {
    if result != 0 || actual > bytes.len() {
        return Err(format!(
            "USB status={result} actual={actual} requested={} error={error}; raw={:02x?}",
            bytes.len(),
            &bytes[..actual.min(bytes.len())]
        ));
    }
    Ok(actual)
}
impl BulkIo for NativeUsb {
    fn max_lun(&mut self) -> Result<u8, String> {
        let usb = self.pointer()?;
        let mut value = 0;
        let mut error = [0i8; 1024];
        let result =
            unsafe { gu_usb_max_lun(usb.as_ptr(), &mut value, error.as_mut_ptr(), error.len()) };
        if result != 0 {
            return Err(error_string(&error));
        }
        Ok(value)
    }

    fn transfer(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, String> {
        let usb = self.pointer()?;
        let input = direction == Direction::In;
        let mut actual = 0;
        let mut timed_out = 0;
        let mut error = [0i8; 1024];
        if !input && bytes.len() == 31 && bytes.starts_with(b"USBC") {
            self.tag = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        }
        let started = Instant::now();
        // SAFETY: owned live bridge object and bounded buffers remain valid
        // until the synchronous operation returns; actual is separately retained.
        let result = unsafe {
            gu_usb_transfer(
                usb.as_ptr(),
                i32::from(input),
                bytes.as_mut_ptr(),
                bytes.len(),
                timeout.as_secs_f64(),
                &mut actual,
                &mut timed_out,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        self.zero_input_timeout =
            result != 0 && timed_out != 0 && input && actual == 0 && bytes.len() == 20;
        if self.diagnostic {
            eprintln!(
                "USB tag={} direction={} requested={} actual={} elapsed_ms={} os_result={} raw={:02x?} error={}",
                self.tag,
                if input { "in" } else { "out" },
                bytes.len(),
                actual,
                started.elapsed().as_millis(),
                result,
                bytes,
                error_string(&error)
            );
        }
        transfer_result(result, actual, bytes, &error_string(&error))
    }
}

pub struct BluetoothSession {
    session: Session,
    usb: Option<bot::Session<NativeUsb>>,
    unmounted: Vec<String>,
    finished: bool,
    last_opcode: u8,
    continuation_used: bool,
}
impl BluetoothSession {
    fn native(&mut self) -> Result<&mut NativeUsb, String> {
        self.usb
            .as_mut()
            .map(bot::Session::io_mut)
            .ok_or_else(|| "No exclusive USB claim".into())
    }
    pub fn enable_diagnostics(&mut self) -> Result<String, String> {
        let io = self.native()?;
        io.diagnostic = true;
        let usb = io.pointer()?;
        unsafe {
            let p = NonNull::new(gu_usb_description(usb.as_ptr()))
                .ok_or("Description allocation failed")?;
            let value = CStr::from_ptr(p.as_ptr()).to_string_lossy().into_owned();
            gu_free(p.as_ptr().cast());
            Ok(value)
        }
    }
    /// Standard read-only EP0 diagnostics; no recovery or firmware opcode.
    pub fn endpoint_status(&mut self, input: bool) -> Result<(u8, u16), String> {
        let usb = self.native()?.pointer()?;
        let mut address = 0;
        let mut status = 0;
        let mut error = [0i8; 1024];
        let result = unsafe {
            gu_usb_endpoint_status(
                usb.as_ptr(),
                i32::from(input),
                &mut address,
                &mut status,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if result != 0 {
            return Err(format!(
                "Endpoint 0x{address:02x} GET_STATUS: {}",
                error_string(&error)
            ));
        }
        Ok((address, status))
    }
    pub fn max_lun(&mut self) -> Result<u8, String> {
        self.check_session()?;
        self.usb
            .as_mut()
            .ok_or("No USB claim")?
            .qualify_addressing()
    }
    pub fn target(&self) -> &NativeCandidate {
        &self.session.target
    }
    pub fn read_info(&mut self) -> Result<Vec<u8>, String> {
        self.check_session()?;
        self.command(0xf1, &[])
    }
    pub fn inquiry(&mut self) -> Result<Vec<u8>, String> {
        self.check_session()?;
        self.bot(&[0x12, 0, 0, 0, 36, 0], Direction::In, &[], 36)
    }
    fn bot(
        &mut self,
        cdb: &[u8],
        direction: Direction,
        data: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, String> {
        self.last_opcode = cdb.first().copied().unwrap_or(0);
        self.usb
            .as_mut()
            .ok_or("No exclusive USB claim")?
            .command(cdb, direction, data, length)
    }
    /// At most one diagnostic continuation of the original timed-out F1 IN
    /// phase. Never clears the failure latch or authorizes a firmware command.
    pub fn diagnostic_continuation(&mut self) -> Result<String, String> {
        if self.continuation_used || self.last_opcode != 0xf1 {
            return Err("No eligible F1 continuation".into());
        }
        let channel = self.usb.as_mut().ok_or("No USB claim")?;
        if !channel.failed()
            || channel.firmware_may_have_been_submitted()
            || !channel.io_mut().diagnostic
            || !channel.io_mut().zero_input_timeout
        {
            return Err("Continuation requires a read-only zero-byte F1 timeout".into());
        }
        self.continuation_used = true;
        for input in [true, false] {
            let (address, status) = self.endpoint_status(input)?;
            if status & 1 != 0 {
                return Err(format!(
                    "Endpoint 0x{address:02x} is halted; no continuation issued"
                ));
            }
        }
        let channel = self.usb.as_mut().ok_or("No USB claim")?;
        let tag = channel.tag();
        let mut bytes = vec![0; 20];
        let actual =
            channel
                .io_mut()
                .transfer(Direction::In, &mut bytes, Duration::from_secs(5))?;
        bytes.truncate(actual);
        if actual == 13 && bytes.starts_with(b"USBS") {
            return Ok(format!(
                "Original transaction early CSW raw={bytes:02x?}; validation={:?}",
                validate_status(&bytes, tag, 20, 0)
            ));
        }
        if actual == 20 {
            let mut status = [0; 13];
            let count =
                channel
                    .io_mut()
                    .transfer(Direction::In, &mut status, Duration::from_secs(5))?;
            return Ok(format!(
                "Late F1 data raw={bytes:02x?}; CSW={:02x?}; validation={:?}; original deadline still failed",
                &status[..count],
                validate_status(&status[..count], tag, 20, 20)
            ));
        }
        Ok(format!(
            "Original transaction continuation actual={actual} raw={bytes:02x?}; remains failed"
        ))
    }
}
impl BluetoothPort for BluetoothSession {
    fn qualified_lun(&self) -> Option<u8> {
        self.usb.as_ref().and_then(bot::Session::qualified_lun)
    }
    fn prepare_write(&mut self) -> Result<(), String> {
        Err("Native Bluetooth writes remain gated until address, zero-tail F1 and ownership qualification succeed".into())
    }
    fn check_session(&mut self) -> Result<(), String> {
        if self.finished {
            return Err("USB session has ended".into());
        }
        self.session.check_transport()
    }
    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, String> {
        if !matches!(opcode, 0xf0..=0xf2) {
            return Err("Unreviewed vendor opcode".into());
        }
        // F1 must qualify this native adapter before the hardware write gate can be enabled.
        if opcode != 0xf1 {
            return Err("Native Bluetooth writes remain gated until zero-tail F1 and ownership qualification succeed".into());
        }
        let mut cdb = [0; 10];
        cdb[0] = opcode;
        self.bot(
            &cdb,
            if opcode == 0xf0 {
                Direction::Out
            } else {
                Direction::In
            },
            data,
            if opcode == 0xf0 { 512 } else { 20 },
        )
    }
    fn finish(&mut self) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if let Some(mut usb) = self.usb.take() {
            let preserve = usb.firmware_may_have_been_submitted();
            if usb.io_mut().diagnostic {
                eprintln!(
                    "Cleanup disposition: {}",
                    if preserve {
                        "no-reset DeviceSurrender; driver restoration pending"
                    } else {
                        "read-only ordinary destroy; documented USB reset and driver rematch"
                    }
                );
            }
            usb.into_inner().close(preserve);
            if preserve {
                return Err("Host claim surrendered without reset after possible F0; storage driver restoration remains pending. Restart normally before fresh discovery/verification.".into());
            }
        }
        let mut errors = Vec::new();
        for disk in std::mem::take(&mut self.unmounted) {
            // No cached disk number is acted upon after replacement/reconnect.
            if let Err(error) = self.session.check_transport() {
                errors.push(format!("Remount requires rediscovery: {error}"));
                break;
            }
            let current = match discover() {
                Ok(value) => value,
                Err(error) => {
                    errors.push(error);
                    break;
                }
            };
            if current.candidates.iter().any(|c| {
                c.ancestor == self.session.target.ancestor
                    && c.disks
                        .iter()
                        .any(|d| d.bsd == disk && !d.mount.as_os_str().is_empty())
            }) {
                continue;
            }
            if let Err(error) = diskutil("mount", &disk) {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}
impl Drop for BluetoothSession {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub fn read_main(confirmed: bool) -> Result<(NativeCandidate, Vec<u8>, MainVersion), String> {
    let mut port = Session::open(confirmed)?.main()?;
    let raw = port.read_version()?;
    let version = MainVersion::parse(&raw).map_err(|e| e.to_string())?;
    Ok((port.session.target.clone(), raw, version))
}

#[cfg(test)]
mod tests {
    use super::transfer_result;
    #[test]
    fn native_error_and_actual_length_are_independent() {
        let data = [0xa1; 20];
        for count in [0, 7, 20] {
            let error = transfer_result(-1, count, &data, "NSError timeout").unwrap_err();
            assert!(error.contains("status=-1"));
            assert!(error.contains(&format!("actual={count}")));
            assert!(error.contains("raw="));
        }
        assert!(transfer_result(0, 21, &data, "").is_err());
        assert_eq!(transfer_result(0, 7, &data, "").unwrap(), 7);
    }
}
