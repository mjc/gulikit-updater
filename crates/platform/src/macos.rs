//! macOS ownership boundary. The small Objective-C bridge uses the shipped SDK;
//! all firmware, version, BOT and transaction decisions remain in the shared core.
#![allow(unsafe_code)]

pub use crate::discovery::{Disk, NativeCandidate, Snapshot, StorageIdentity};
use crate::{acquisition::AcquisitionError, volume::Volume};
use gulikit_core::{
    bot::{self, BulkIo, Direction, MaxLun, validate_status},
    package::Component,
    update::{BluetoothPort, CompletionDecision, CompletionObservation, MainPort},
    version::MainVersion,
};
use std::{
    ffi::{CStr, c_char, c_void},
    fs::File,
    path::PathBuf,
    process::Command,
    ptr::NonNull,
    time::{Duration, Instant},
};

unsafe extern "C" {
    fn gu_snapshot(bound_id: u64) -> *mut c_char;
    #[cfg(test)]
    fn gu_collect_profile_fixture(root: u64, json: *const c_char) -> *mut c_char;
    #[cfg(test)]
    fn gu_cached_storage_profile(
        vendor: *const c_char,
        product: *const c_char,
        revision: *const c_char,
    ) -> i32;
    #[cfg(test)]
    fn gu_bluetooth_candidate(vendor: u16, product: u16, bot: i32) -> i32;
    #[cfg(test)]
    fn gu_profile_candidate(
        vendor: u16,
        product: u16,
        bot: i32,
        name: *const c_char,
        cached: i32,
        id: u64,
        bound: u64,
    ) -> i32;
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
    #[cfg(test)]
    fn gu_max_lun_result(succeeded: i32, actual: usize, code: i32) -> i32;
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

pub fn discover() -> Result<Snapshot, String> {
    discover_bound(0)
}
// Only an already selected, held USB entry and unchanged topology may preserve
// recognition after our own capture removes its cached storage identity node.
fn discover_bound(bound_id: u64) -> Result<Snapshot, String> {
    // SAFETY: gu_snapshot returns an owned, NUL-terminated allocation or null;
    // gu_free is its matching allocator. No borrowed bridge storage escapes.
    unsafe {
        let ptr =
            NonNull::new(gu_snapshot(bound_id)).ok_or("Native enumeration allocation failed")?;
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
    component: Component,
    watch: Watch,
    lock: crate::lock::ProcessLock,
    service: u32,
}
impl Session {
    /// Create the host audit log relative to an open directory, excluding device volumes.
    pub fn create_record(&mut self, path: &std::path::Path) -> Result<File, String> {
        use std::os::unix::fs::MetadataExt;
        let devices = self
            .target
            .disks
            .iter()
            .filter(|disk| !disk.mount.as_os_str().is_empty())
            .map(|disk| {
                std::fs::metadata(&disk.mount)
                    .map(|metadata| metadata.dev())
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        crate::journal::create_host_record(path, &devices)
    }
    pub fn open(confirmed: bool, component: Component) -> Result<Self, String> {
        Self::open_locked(confirmed, component, crate::lock::ProcessLock::acquire()?)
    }
    pub fn open_main_worker(
        confirmed: bool,
        lease: crate::lock::ProcessLock,
    ) -> Result<Self, String> {
        if !lease.is_worker_lease() {
            return Err("Main worker requires a guardian-owned lease".into());
        }
        Self::open_locked(confirmed, Component::Main, lease)
    }
    fn open_locked(
        confirmed: bool,
        component: Component,
        lock: crate::lock::ProcessLock,
    ) -> Result<Self, String> {
        let watch = Watch::new()?;
        let target = discover()?.select(confirmed, component)?;
        let service = unsafe { gu_entry_hold(target.ancestor) };
        if service == 0 {
            return Err("Selected physical attachment disappeared".into());
        }
        let session = Self {
            target,
            component,
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
        let current = discover()?.select(true, self.component)?;
        if current != self.target {
            return Err("Selected attachment changed".into());
        }
        if !self.watch.unchanged() {
            return Err("USB topology changed during discovery".into());
        }
        Ok(())
    }
    pub fn main(self) -> Result<MainSession, String> {
        if self.component != Component::Main {
            return Err("Session selected a different component".into());
        }
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
            .find(|disk| disk.mount == *mount)
            .ok_or("Selected mount is not a correlated device volume")?;
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
    pub fn bluetooth(self) -> Result<BluetoothSession, AcquisitionError> {
        if self.component != Component::Bluetooth {
            return Err("Session selected a different component".into());
        }
        self.check()?;
        if !self.target.storage_identities.iter().any(|identity| {
            identity.vendor.as_deref() == Some("Gamepad")
                && identity.product.as_deref() == Some("Updater")
                && identity.revision.as_deref() == Some("1.00")
        }) {
            return Err("Bluetooth requires the observed Gamepad/Updater/1.00 update profile. Exit the current mode normally, then enter Gear/Set+A Bluetooth mode and rediscover.".into());
        }
        let mut port = BluetoothSession {
            session: self,
            usb: None,
            unmounted: Vec::new(),
            finished: false,
            last_opcode: 0,
            continuation_used: false,
            sense_used: false,
            write_gate: BluetoothWriteGate::default(),
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
            return Err(AcquisitionError::after_cleanup(error, cleanup));
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
        let snapshot = discover_bound(self.target.ancestor)?;
        snapshot.validate_transport(&self.target, self.component)?;
        if !self.watch.unchanged() {
            return Err("USB topology changed during transport discovery".into());
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
fn main_write_capability(supervised: bool, writable: bool) -> Result<(), String> {
    if !supervised {
        return Err("Main writes require supervised filesystem I/O with retained ownership".into());
    }
    if !writable {
        return Err("Selected Main update volume is not writable".into());
    }
    Ok(())
}
impl MainPort for MainSession {
    fn prepare_write(&mut self) -> Result<(), String> {
        self.check_session()?;
        let writable =
            self.session.target.disks.iter().any(|disk| {
                Some(&disk.mount) == self.session.target.mount.as_ref() && disk.writable
            });
        main_write_capability(self.session.lock.is_worker_lease(), writable)?;
        self.check_session()
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
    fn create_destination(&mut self) -> Result<(), gulikit_core::update::DestinationCreationError> {
        self.prepare_write()?;
        self.check_session()?;
        self.volume.create().map_err(Into::into)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<usize, gulikit_core::update::SubmissionError> {
        self.check_session()
            .map_err(gulikit_core::update::SubmissionError::before)?;
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
    fn max_lun(&mut self) -> Result<MaxLun, String> {
        let usb = self.pointer()?;
        let mut value = 0;
        let mut error = [0i8; 1024];
        let result =
            unsafe { gu_usb_max_lun(usb.as_ptr(), &mut value, error.as_mut_ptr(), error.len()) };
        match result {
            0 => Ok(MaxLun::Reported(value)),
            1 => Ok(MaxLun::SingleLunStall),
            _ => Err(error_string(&error)),
        }
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

#[derive(Default)]
struct BluetoothWriteGate {
    fresh_f1: bool,
    prepared: bool,
}
impl BluetoothWriteGate {
    fn observe_f1(&mut self, raw: &[u8]) -> Result<(), String> {
        self.fresh_f1 = false;
        self.prepared = false;
        gulikit_core::version::bluetooth_info(raw)
            .map_err(|error| format!("{error}; raw={raw:02x?}"))?;
        self.fresh_f1 = true;
        Ok(())
    }
    fn begin_f1(&mut self) {
        *self = Self::default();
    }
    fn prepare(&mut self, lun: Option<u8>, failed: bool) -> Result<(), String> {
        self.prepared = false;
        if !self.fresh_f1 || lun != Some(0) || failed {
            return Err(
                "Bluetooth writing requires a fresh valid F1 in this qualified LUN0 session".into(),
            );
        }
        self.prepared = true;
        Ok(())
    }
}

pub struct BluetoothSession {
    session: Session,
    usb: Option<bot::Session<NativeUsb>>,
    unmounted: Vec<String>,
    finished: bool,
    last_opcode: u8,
    continuation_used: bool,
    sense_used: bool,
    write_gate: BluetoothWriteGate,
}
impl BluetoothSession {
    fn native(&mut self) -> Result<&mut NativeUsb, String> {
        self.usb
            .as_mut()
            .map(bot::Session::io_mut)
            .ok_or_else(|| "No exclusive USB claim".into())
    }
    pub fn enable_diagnostics(&mut self) -> Result<String, String> {
        self.check_session()?;
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
        self.check_session()?;
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
        // command invalidates the previous F1 proof before its first fallible check.
        self.command(0xf1, &[]).map_err(|error| error.message)
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
    pub fn failed_f1_status(&self) -> Option<[u8; 13]> {
        self.usb.as_ref().and_then(bot::Session::failed_f1_status)
    }
    pub fn diagnostic_sense_eligible(&mut self) -> bool {
        if self.sense_used || self.last_opcode != 0xf1 {
            return false;
        }
        let Some(channel) = self.usb.as_mut() else {
            return false;
        };
        channel.io_mut().diagnostic && channel.request_sense_eligible()
    }
    /// One standard error read, without clearing the failed session or write gate.
    pub fn diagnostic_request_sense(&mut self) -> Result<Vec<u8>, String> {
        if !self.diagnostic_sense_eligible() {
            return Err("No eligible diagnostic REQUEST SENSE".into());
        }
        self.sense_used = true;
        self.check_session()?;
        for input in [true, false] {
            let (address, status) = self.endpoint_status(input)?;
            if status != 0 {
                return Err(format!(
                    "Endpoint 0x{address:02x} status=0x{status:04x}; no REQUEST SENSE issued"
                ));
            }
        }
        self.check_session()?;
        self.last_opcode = 3;
        let raw = self
            .usb
            .as_mut()
            .ok_or("No exclusive USB claim")?
            .diagnostic_request_sense()?;
        self.check_session()?;
        Ok(raw)
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
impl BluetoothSession {
    fn vendor_command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, String> {
        if opcode == 0xf1 {
            self.write_gate.begin_f1();
        }
        self.check_session()?;
        let channel = self.usb.as_ref().ok_or("No exclusive USB claim")?;
        if channel.failed() {
            return Err("BOT session already failed".into());
        }
        match opcode {
            0xf1 if !channel.firmware_may_have_been_submitted() && data.is_empty() => {}
            0xf0 if self.write_gate.prepared
                && channel.qualified_lun() == Some(0)
                && data.len() == 512 => {}
            0xf2 if self.write_gate.prepared
                && channel.qualified_lun() == Some(0)
                && channel.firmware_may_have_been_submitted()
                && data.is_empty() => {}
            _ => {
                return Err(
                    "Vendor command is not authorized in the current Bluetooth transaction state"
                        .into(),
                );
            }
        }
        let mut cdb = [0; 10];
        cdb[0] = opcode;
        let raw = self.bot(
            &cdb,
            if opcode == 0xf0 {
                Direction::Out
            } else {
                Direction::In
            },
            data,
            if opcode == 0xf0 { 512 } else { 20 },
        )?;
        self.check_session()?;
        if opcode == 0xf1 {
            self.write_gate.observe_f1(&raw)?;
        }
        Ok(raw)
    }
}
impl BluetoothPort for BluetoothSession {
    fn lun_evidence(&self) -> Option<MaxLun> {
        self.usb.as_ref().and_then(bot::Session::lun_evidence)
    }
    fn qualified_lun(&self) -> Option<u8> {
        self.usb.as_ref().and_then(bot::Session::qualified_lun)
    }
    fn prepare_write(&mut self) -> Result<(), String> {
        self.write_gate.prepared = false;
        self.check_session()?;
        let channel = self.usb.as_ref().ok_or("No exclusive USB claim")?;
        self.write_gate
            .prepare(channel.qualified_lun(), channel.failed())?;
        if let Err(error) = self.check_session() {
            self.write_gate.prepared = false;
            return Err(error);
        }
        Ok(())
    }
    fn check_session(&mut self) -> Result<(), String> {
        if self.finished {
            return Err("USB session has ended".into());
        }
        self.session.check_transport()
    }
    fn command(
        &mut self,
        opcode: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, gulikit_core::update::SubmissionError> {
        let before = self.usb.as_ref().map(bot::Session::tag);
        let result = self.vendor_command(opcode, data);
        let attempted = self.usb.as_ref().map(bot::Session::tag) != before;
        result.map_err(|message| {
            if attempted {
                message.into()
            } else {
                gulikit_core::update::SubmissionError::before(message)
            }
        })
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
    let mut port = Session::open(confirmed, Component::Main)?.main()?;
    let raw = port.read_version()?;
    let version = MainVersion::parse(&raw).map_err(|e| e.to_string())?;
    Ok((port.session.target.clone(), raw, version))
}

#[cfg(test)]
mod tests {
    use super::{
        NativeCandidate, Snapshot, gu_cached_storage_profile, gu_profile_candidate, transfer_result,
    };
    #[test]
    fn main_writes_require_both_a_supervised_lease_and_writable_media() {
        for (supervised, writable) in [(false, false), (false, true), (true, false)] {
            assert!(super::main_write_capability(supervised, writable).is_err());
        }
        super::main_write_capability(true, true).unwrap();
    }
    #[test]
    fn bluetooth_write_gate_requires_fresh_valid_f1_and_qualified_live_bot() {
        let mut gate = super::BluetoothWriteGate::default();
        assert!(gate.prepare(Some(0), false).is_err());
        let mut raw = gulikit_core::version::BT_SIGNATURE.to_vec();
        raw.extend_from_slice(&[0x43, 1, 0, 0]);
        gate.observe_f1(&raw).unwrap();
        assert!(gate.prepare(Some(1), false).is_err());
        assert!(gate.prepare(None, false).is_err());
        assert!(gate.prepare(Some(0), true).is_err());
        gate.prepare(Some(0), false).unwrap();
        assert!(gate.prepared);
        gate.begin_f1();
        assert!(!gate.prepared);
        assert!(gate.prepare(Some(0), false).is_err());
        gate.observe_f1(&raw).unwrap();
        gate.prepare(Some(0), false).unwrap();
        raw[0] = 0;
        assert!(gate.observe_f1(&raw).is_err());
        assert!(!gate.prepared);
        assert!(gate.prepare(Some(0), false).is_err());
    }
    #[test]
    fn max_lun_accepts_only_a_zero_byte_stall_as_the_single_lun_fallback() {
        const STALL: i32 = 0xe000404f_u32 as i32;
        // SAFETY: pure bridge decoder takes values only and performs no I/O.
        unsafe {
            assert_eq!(super::gu_max_lun_result(0, 0, STALL), 1);
            assert_eq!(super::gu_max_lun_result(1, 1, 0), 0);
            for (success, actual, code) in [
                (0, 1, STALL),
                (0, 0, 0xe00002d6_u32 as i32),
                (0, 0, 0),
                (1, 0, 0),
                (1, 2, 0),
            ] {
                assert_eq!(super::gu_max_lun_result(success, actual, code), -1);
            }
        }
    }
    #[test]
    fn main_usb_storage_is_not_a_bluetooth_update_path() {
        // SAFETY: synchronous pure bridge predicate, no IOKit or USB operations.
        unsafe {
            assert_eq!(super::gu_bluetooth_candidate(0x34d3, 0x1100, 1), 0);
            assert_eq!(super::gu_bluetooth_candidate(0x8087, 0x1024, 1), 1);
            assert_eq!(super::gu_bluetooth_candidate(0x8087, 0x1024, 0), 0);
        }
    }
    #[test]
    fn cached_storage_and_bound_capture_recognition_do_not_include_ordinary_bot_disks() {
        use std::ffi::CString;
        let text = |value: &str| CString::new(value).unwrap();
        let vendor = text("Gamepad");
        let product = text("Updater");
        let revision = text("1.00");
        let ordinary = text("Generic");
        // SAFETY: these stable CString buffers are NUL-terminated for synchronous pure predicates.
        let cached = unsafe {
            gu_cached_storage_profile(vendor.as_ptr(), product.as_ptr(), revision.as_ptr())
        };
        assert_eq!(cached, 1);
        assert_eq!(
            unsafe { gu_profile_candidate(0x1234, 0x5678, 1, ordinary.as_ptr(), cached, 20, 0) },
            1
        );
        assert_eq!(
            unsafe { gu_profile_candidate(0x1234, 0x5678, 1, ordinary.as_ptr(), 0, 20, 0) },
            0
        );
        assert_eq!(
            unsafe { gu_profile_candidate(0x34d3, 0x1100, 0, ordinary.as_ptr(), 0, 20, 0) },
            1
        );
        assert_eq!(
            unsafe { gu_profile_candidate(0x1234, 0x5678, 1, ordinary.as_ptr(), 0, 20, 20) },
            1
        );
        assert_eq!(
            unsafe { gu_profile_candidate(0x1234, 0x5678, 1, ordinary.as_ptr(), 0, 21, 20) },
            0
        );
        for wrong in ["G", "Gamepad ", "gamepad", " Gamepad"] {
            let wrong = text(wrong);
            assert_eq!(
                unsafe {
                    gu_cached_storage_profile(wrong.as_ptr(), product.as_ptr(), revision.as_ptr())
                },
                0
            );
        }
    }
    #[test]
    fn hub_and_sibling_devices_never_inherit_the_controllers_cached_storage_identity() {
        let nodes = serde_json::json!([
            {"ancestor":1,"entry":10,"interface":true,"lun":false,"properties":{"bInterfaceClass":9}},
            {"ancestor":2,"entry":20,"interface":true,"lun":false,"properties":{"bInterfaceClass":8,"bInterfaceSubClass":6,"bInterfaceProtocol":80}},
            {"ancestor":2,"entry":21,"interface":false,"lun":true,"properties":{"Vendor Identification":"Gamepad","Product Identification":"Updater","Product Revision Level":"1.00"}},
            {"ancestor":3,"entry":30,"interface":true,"lun":false,"properties":{"bInterfaceClass":8,"bInterfaceSubClass":6,"bInterfaceProtocol":80}},
            {"ancestor":3,"entry":31,"interface":false,"lun":true,"properties":{"Vendor Identification":"Generic","Product Identification":"USB Disk","Product Revision Level":"1.00"}}
        ]);
        let input = std::ffi::CString::new(nodes.to_string()).unwrap();
        let collect = |root| {
            // SAFETY: fixture adapter takes one valid CString, returns allocated NUL text.
            unsafe {
                let raw = super::gu_collect_profile_fixture(root, input.as_ptr());
                assert!(!raw.is_null());
                let value: serde_json::Value =
                    serde_json::from_slice(std::ffi::CStr::from_ptr(raw).to_bytes()).unwrap();
                super::gu_free(raw.cast());
                value
            }
        };
        let hub = collect(1);
        assert_eq!(hub["bot"], false);
        assert_eq!(hub["cached"], false);
        assert!(hub["storage_identities"].as_array().unwrap().is_empty());
        let controller = collect(2);
        assert_eq!(controller["bot"], true);
        assert_eq!(controller["cached"], true);
        assert_eq!(
            controller["storage_identities"].as_array().unwrap().len(),
            1
        );
        assert_eq!(controller["storage_identities"][0]["entry"], 21);
        let sibling = collect(3);
        assert_eq!(sibling["bot"], true);
        assert_eq!(sibling["cached"], false);
        assert_eq!(sibling["storage_identities"][0]["entry"], 31);
    }
    #[test]
    fn capture_view_loss_preserves_only_the_previously_bound_physical_attachment() {
        let target: NativeCandidate=serde_json::from_value(serde_json::json!({"ancestor":20,"generation":20,"main_volume_candidate":true,"bluetooth_transport_candidate":true,"observed_profile":true,"conflicting_model":false,"disks":[],"mount":null,"storage_identities":[{"entry":30,"vendor":"Gamepad","product":"Updater","revision":"1.00"}]})).unwrap();
        let mut captured = target.clone();
        captured.main_volume_candidate = false;
        captured.observed_profile = false;
        captured.storage_identities.clear();
        let mut snapshot = Snapshot {
            candidates: vec![captured],
            incomplete: vec![],
        };
        snapshot
            .validate_transport(&target, gulikit_core::package::Component::Bluetooth)
            .unwrap();
        snapshot.candidates[0].generation = 21;
        assert!(
            snapshot
                .validate_transport(&target, gulikit_core::package::Component::Bluetooth)
                .is_err()
        );
        snapshot.candidates[0].generation = 20;
        snapshot.candidates[0].ancestor = 21;
        assert!(
            snapshot
                .validate_transport(&target, gulikit_core::package::Component::Bluetooth)
                .is_err()
        );
        snapshot.candidates[0].ancestor = 20;
        let mut other = target.clone();
        other.ancestor = 22;
        other.bluetooth_transport_candidate = false;
        snapshot.candidates.push(other);
        assert!(
            snapshot
                .validate_transport(&target, gulikit_core::package::Component::Bluetooth)
                .unwrap_err()
                .starts_with("More than one device")
        );
        snapshot.candidates.pop();
        snapshot
            .incomplete
            .push("uncorrelated update volume".into());
        assert!(
            snapshot
                .validate_transport(&target, gulikit_core::package::Component::Bluetooth)
                .is_err()
        );
    }
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
