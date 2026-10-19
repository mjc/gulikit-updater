//! macOS ownership boundary. The small Objective-C bridge uses the shipped SDK;
//! all firmware, version, BOT and transaction decisions remain in the shared core.
#![allow(unsafe_code)]

pub use crate::discovery::{Disk, NativeCandidate, Snapshot, StorageIdentity};
use crate::{acquisition::AcquisitionError, volume::Volume};
use gulikit_core::{
    bot::{self, BulkIo, Direction, MaxLun, TransferError, TransferFailureKind, validate_status},
    package::Component,
    update::{BluetoothPort, CompletionDecision, CompletionObservation, MainPort},
    version::MainVersion,
};
use std::{
    ffi::{CStr, c_char, c_void},
    fs::File,
    path::PathBuf,
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
        failure_kind: *mut i32,
        error: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn gu_usb_clear_stall(value: *mut c_void, error: *mut c_char, capacity: usize) -> i32;
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

///
/// # Errors
///
/// Returns an error if native enumeration fails or its snapshot cannot be decoded.
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
            gu_watch_state(ptr.as_ptr(), &raw mut epoch, &raw mut arrivals);
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
            gu_watch_state(self.ptr.as_ptr(), &raw mut epoch, &raw mut arrivals);
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
    ///
    /// # Errors
    ///
    /// Returns an error if attachment or lock identity changes, disk correlation is invalid, or the host record cannot be created durably outside device storage.
    pub fn create_record(&mut self, path: &std::path::Path) -> Result<File, String> {
        self.check_record_session()?;
        let devices = record_exclusions(&self.target.disks, |bsd| {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            if !bsd.starts_with("disk") || !bsd.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return Err("Invalid correlated disk identifier".into());
            }
            let metadata = std::fs::metadata(PathBuf::from("/dev").join(bsd))
                .map_err(|error| error.to_string())?;
            if !metadata.file_type().is_block_device() {
                return Err("Correlated disk is not a block device".into());
            }
            Ok(metadata.rdev())
        })?;
        self.check_record_session()?;
        crate::journal::create_host_record(path, &devices)
    }

    fn check_record_session(&self) -> Result<(), String> {
        match self.component {
            Component::Main => self.check(),
            Component::Bluetooth => self.check_transport(),
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the process lock or watcher cannot be acquired, discovery refuses the requested attachment, or its identity changes.
    pub fn open(confirmed: bool, component: Component) -> Result<Self, String> {
        Self::open_locked(confirmed, component, crate::lock::ProcessLock::acquire()?)
    }
    ///
    /// # Errors
    ///
    /// Returns an error for a nonworker lease, failed watcher or discovery, or a changed Main attachment.
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
    ///
    /// # Errors
    ///
    /// Returns an error if lock identity, USB topology, discovery completeness, or the selected attachment changes.
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
    ///
    /// # Errors
    ///
    /// Returns an error for a different component, changed session, missing or uncorrelated mount, or failure to open the selected filesystem.
    pub fn main(self) -> Result<MainSession, String> {
        use std::os::unix::fs::MetadataExt;
        if self.component != Component::Main {
            return Err("Session selected a different component".into());
        }
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
    ///
    /// # Errors
    ///
    /// Returns an acquisition error for a different component, changed session, unqualified profile, disk media, or failed USB capture. Cleanup failures remain separate evidence.
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
        bluetooth_media_capability(&self.target.disks)?;
        let mut port = BluetoothSession {
            session: self,
            usb: None,
            finished: false,
            last_opcode: 0,
            continuation_used: false,
            sense_used: false,
            write_gate: BluetoothWriteGate::default(),
        };
        let result = (|| {
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
    fn completion_observation(&self) -> Result<CompletionObservation, String> {
        self.lock.check()?;
        let snapshot = discover_bound(self.target.ancestor)?;
        let (events, arrivals) = self.watch.changes();
        Ok(CompletionObservation {
            selected_present: snapshot
                .candidates
                .iter()
                .any(|candidate| candidate.ancestor == self.target.ancestor),
            other_candidate_present: snapshot
                .candidates
                .iter()
                .any(|candidate| candidate.ancestor != self.target.ancestor),
            discovery_complete: snapshot.incomplete.is_empty(),
            usb_events: events,
            usb_arrivals: arrivals,
        })
    }
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
        .map(|b| b.to_ne_bytes()[0])
        .take_while(|b| *b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
// Include unmounted media: Disk Arbitration can mount it before record creation.
fn record_exclusions(
    disks: &[Disk],
    device: impl FnMut(&str) -> Result<u64, String>,
) -> Result<Vec<u64>, String> {
    let mut device = device;
    disks.iter().map(|disk| device(&disk.bsd)).collect()
}

fn bluetooth_media_capability(disks: &[Disk]) -> Result<(), String> {
    if disks.is_empty() {
        Ok(())
    } else {
        Err("Bluetooth capture requires the qualified update profile without disk media. No volume will be unmounted; enter Gear/Set+A mode and rediscover.".into())
    }
}

pub struct MainSession {
    session: Session,
    volume: Volume,
}
impl MainSession {
    #[must_use]
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
            match self.session.completion_observation()?.decision() {
                CompletionDecision::ExpectedDetach => return Ok(true),
                CompletionDecision::Invalidated => return Err("Unexpected topology change or incomplete discovery while awaiting Main completion".into()),
                CompletionDecision::Pending => {}
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        self.session
            .completion_observation()?
            .at_deadline()
            .map_err(str::to_owned)
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
fn transfer_result(
    result: i32,
    actual: usize,
    bytes: &[u8],
    error: &str,
) -> Result<usize, TransferError> {
    if result != 0 || actual > bytes.len() {
        return Err(TransferError {
            kind: TransferFailureKind::Other,
            actual,
            raw: bytes[..actual.min(bytes.len())].to_vec(),
            message: format!(
                "USB status={result} requested={} error={error}",
                bytes.len()
            ),
        });
    }
    Ok(actual)
}
impl BulkIo for NativeUsb {
    fn max_lun(&mut self) -> Result<MaxLun, String> {
        let usb = self.pointer()?;
        let mut value = 0;
        let mut error = [0i8; 1024];
        let result = unsafe {
            gu_usb_max_lun(
                usb.as_ptr(),
                &raw mut value,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        match result {
            0 => Ok(MaxLun::Reported(value)),
            1 => Ok(MaxLun::SingleLunStall),
            _ => Err(error_string(&error)),
        }
    }

    fn clear_stall(&mut self, budget: Duration) -> Result<(), TransferError> {
        if budget.is_zero() {
            return Err(TransferError {
                kind: TransferFailureKind::Timeout,
                actual: 0,
                raw: Vec::new(),
                message: "No remaining CSW-clearance budget".into(),
            });
        }
        let usb = self.pointer()?;
        let mut error = [0i8; 1024];
        // The synchronous API has no timeout parameter. Ownership and the global
        // lease stay held until it returns; the BOT layer rejects any overrun
        // before scheduling another transfer. Never kill a captured USB worker.
        let result = unsafe { gu_usb_clear_stall(usb.as_ptr(), error.as_mut_ptr(), error.len()) };
        if result != 0 {
            return Err(format!("Bulk-IN halt clearance failed: {}", error_string(&error)).into());
        }
        Ok(())
    }
    fn transfer(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransferError> {
        let usb = self.pointer()?;
        let input = direction == Direction::In;
        let mut actual = 0;
        let mut failure_kind = 0;
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
                &raw mut actual,
                &raw mut failure_kind,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        self.zero_input_timeout =
            result != 0 && failure_kind == 2 && input && actual == 0 && bytes.len() == 20;
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
        transfer_result(result, actual, bytes, &error_string(&error)).map_err(|mut error| {
            error.kind = match failure_kind {
                1 => TransferFailureKind::Stall,
                2 => TransferFailureKind::Timeout,
                _ => TransferFailureKind::Other,
            };
            error
        })
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum BluetoothWriteGate {
    #[default]
    Unqualified,
    FreshInfo,
    Prepared,
}
impl BluetoothWriteGate {
    fn observe_f1(&mut self, raw: &[u8]) -> Result<(), String> {
        self.begin_f1();
        gulikit_core::version::bluetooth_info(raw)
            .map_err(|error| format!("{error}; raw={raw:02x?}"))?;
        *self = Self::FreshInfo;
        Ok(())
    }
    fn begin_f1(&mut self) {
        *self = Self::Unqualified;
    }
    fn unprepare(&mut self) {
        match self {
            Self::Unqualified | Self::FreshInfo => {}
            Self::Prepared => *self = Self::FreshInfo,
        }
    }
    fn is_prepared(self) -> bool {
        self == Self::Prepared
    }
    fn prepare(&mut self, lun: Option<u8>, failed: bool) -> Result<(), String> {
        self.unprepare();
        if *self != Self::FreshInfo || lun != Some(0) || failed {
            return Err(
                "Bluetooth writing requires a fresh valid F1 in this qualified LUN0 session".into(),
            );
        }
        *self = Self::Prepared;
        Ok(())
    }
}

pub struct BluetoothSession {
    session: Session,
    usb: Option<bot::Session<NativeUsb>>,
    finished: bool,
    last_opcode: u8,
    continuation_used: bool,
    sense_used: bool,
    write_gate: BluetoothWriteGate,
}
impl BluetoothSession {
    /// Release ownership without resetting the device or restoring its drivers.
    /// An imported recovery hold must survive closing an idle desktop window.
    pub fn surrender(mut self) {
        self.finished = true;
        if let Some(usb) = self.usb.take() {
            usb.into_inner().close(true);
        }
    }

    /// Create an audit record while retaining the inspected transport claim.
    ///
    /// # Errors
    /// Rejects invalidated ownership or a path on controller storage.
    pub fn create_record(&mut self, path: &std::path::Path) -> Result<File, String> {
        self.check_session()?;
        self.session.create_record(path)
    }

    fn native(&mut self) -> Result<&mut NativeUsb, String> {
        self.usb
            .as_mut()
            .map(bot::Session::io_mut)
            .ok_or_else(|| "No exclusive USB claim".into())
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the session or USB claim is invalid or the native description cannot be allocated.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the session or claim is invalid or the endpoint status request fails.
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
                &raw mut address,
                &raw mut status,
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
    ///
    /// # Errors
    ///
    /// Returns an error if the session or claim is invalid or the observed maximum LUN does not qualify for this adapter.
    pub fn max_lun(&mut self) -> Result<u8, String> {
        self.check_session()?;
        self.usb
            .as_mut()
            .ok_or("No USB claim")?
            .qualify_addressing()
    }
    #[must_use]
    pub fn target(&self) -> &NativeCandidate {
        &self.session.target
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the F1 request, session checks, or vendor response validation fails.
    pub fn read_info(&mut self) -> Result<Vec<u8>, String> {
        // command invalidates the previous F1 proof before its first fallible check.
        self.command(0xf1, &[]).map_err(|error| error.message)
    }
    ///
    /// # Errors
    ///
    /// Returns an error if the session check or bounded standard inquiry fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error without the exact diagnostic allowance, for nonzero endpoint status, or if session checks or the one permitted sense read fail.
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
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the one permitted read-only F1 timeout continuation, endpoint checks pass, and its bounded reads and status validation succeed.
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
            0xf0 if self.write_gate.is_prepared()
                && channel.qualified_lun() == Some(0)
                && data.len() == 512 => {}
            0xf2 if self.write_gate.is_prepared()
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
        if opcode == 0xf1 {
            // Identity must remain attachment-bound before it can authorize a
            // write. Completed F0/F2 evidence survives a subsequent detach;
            // their next operation still checks the live session before I/O.
            self.check_session()?;
            self.write_gate.observe_f1(&raw)?;
        }
        Ok(raw)
    }
}
impl BluetoothPort for BluetoothSession {
    fn take_transport_evidence(&mut self) -> Option<bot::CommandEvidence> {
        self.usb.as_mut().and_then(bot::Session::take_evidence)
    }

    fn lun_evidence(&self) -> Option<MaxLun> {
        self.usb.as_ref().and_then(bot::Session::lun_evidence)
    }
    fn qualified_lun(&self) -> Option<u8> {
        self.usb.as_ref().and_then(bot::Session::qualified_lun)
    }
    fn prepare_write(&mut self) -> Result<(), String> {
        self.write_gate.unprepare();
        self.check_session()?;
        let channel = self.usb.as_ref().ok_or("No exclusive USB claim")?;
        self.write_gate
            .prepare(channel.qualified_lun(), channel.failed())?;
        if let Err(error) = self.check_session() {
            self.write_gate.unprepare();
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
        if let Some(channel) = self.usb.as_mut() {
            channel.clear_evidence();
        }
        let before = self.usb.as_ref().map(bot::Session::tag);
        let result = self.vendor_command(opcode, data);
        let attempted = self.usb.as_ref().map(bot::Session::tag) != before;
        result.map_err(|message| {
            if attempted {
                let mut error = gulikit_core::update::SubmissionError::from(message);
                if self
                    .usb
                    .as_ref()
                    .is_some_and(bot::Session::data_sent_status_missing)
                {
                    error.completion =
                        gulikit_core::update::SubmissionCompletion::DataSentStatusMissing;
                }
                error
            } else {
                gulikit_core::update::SubmissionError::before(message)
            }
        })
    }
    fn completion_detached(&mut self) -> Result<bool, String> {
        // The KK3 normally reboots after accepting the last DATA block, before
        // its CSW. OS removal notifications can lag that reboot. Wait only on
        // host observations; never send F2, F1, a retry, or a reset here.
        let started = Instant::now();
        crate::completion::wait_for_expected_reboot(
            || self.session.completion_observation(),
            || {
                let remaining = Duration::from_secs(5).saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return false;
                }
                std::thread::sleep(remaining.min(Duration::from_millis(50)));
                true
            },
        )
    }
    fn finish(&mut self) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if let Some(mut usb) = self.usb.take() {
            let preserve = usb.firmware_may_have_been_submitted();
            let detached = preserve
                && self
                    .session
                    .completion_observation()
                    .is_ok_and(|observation| {
                        observation.decision() == CompletionDecision::ExpectedDetach
                    });
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
            if preserve && !detached {
                return Err(crate::acquisition::SURRENDER_PENDING_NOTICE.into());
            }
        }
        Ok(())
    }
}
impl Drop for BluetoothSession {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

///
/// # Errors
///
/// Returns an error if the Main session cannot be acquired, the version file cannot be read, or its contents do not identify a known version.
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
    fn bluetooth_capture_refuses_media_including_unmounted_disks() {
        super::bluetooth_media_capability(&[]).unwrap();
        for mount in ["", "/Volumes/GuliKit"] {
            let disks = [super::Disk {
                bsd: "disk9".into(),
                mount: mount.into(),
                writable: true,
            }];
            assert!(super::bluetooth_media_capability(&disks).is_err());
            let exclusions = super::record_exclusions(&disks, |bsd| {
                assert_eq!(bsd, "disk9");
                Ok(99)
            })
            .unwrap();
            assert_eq!(exclusions, [99]);
        }
    }
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
        assert!(gate.is_prepared());
        gate.begin_f1();
        assert!(!gate.is_prepared());
        assert!(gate.prepare(Some(0), false).is_err());
        gate.observe_f1(&raw).unwrap();
        gate.prepare(Some(0), false).unwrap();
        raw[0] = 0;
        assert!(gate.observe_f1(&raw).is_err());
        assert!(!gate.is_prepared());
        assert!(gate.prepare(Some(0), false).is_err());
    }
    #[test]
    fn max_lun_accepts_only_a_zero_byte_stall_as_the_single_lun_fallback() {
        const STALL: i32 = i32::from_ne_bytes(0xe000_404f_u32.to_ne_bytes());
        assert_eq!(
            unsafe {
                super::gu_max_lun_result(0, 0, i32::from_ne_bytes(0xe000_5000_u32.to_ne_bytes()))
            },
            1
        );
        // SAFETY: pure bridge decoder takes values only and performs no I/O.
        unsafe {
            assert_eq!(super::gu_max_lun_result(0, 0, STALL), 1);
            assert_eq!(super::gu_max_lun_result(1, 1, 0), 0);
            for (success, actual, code) in [
                (0, 1, STALL),
                (0, 0, i32::from_ne_bytes(0xe000_02d6_u32.to_ne_bytes())),
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
        assert_eq!(
            hub["storage_identities"].as_array().unwrap().as_slice(),
            [] as [serde_json::Value; 0]
        );
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
            let error = transfer_result(-1, count, &data, "NSError timeout")
                .unwrap_err()
                .to_string();
            assert!(error.contains("status=-1"));
            assert!(error.contains(&format!("actual={count}")));
            assert!(error.contains("raw="));
        }
        assert!(transfer_result(0, 21, &data, "").is_err());
        assert_eq!(transfer_result(0, 7, &data, "").unwrap(), 7);
    }
}
