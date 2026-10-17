//! macOS ownership boundary. The small Objective-C bridge uses the shipped SDK;
//! all firmware, version, BOT and transaction decisions remain in the shared core.
#![allow(unsafe_code)]

use crate::volume::Volume;
use gulikit_core::{
    bot::{DataStage, Direction, command_block, data_stage, validate_status},
    device::{Candidate, Discovery},
    update::{BluetoothPort, MainPort},
    version::MainVersion,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, c_char, c_void},
    fs::{File, OpenOptions},
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
    fn gu_watch_close(value: *mut c_void);
    fn gu_usb_open(id: u64, error: *mut c_char, capacity: usize) -> *mut c_void;
    fn gu_usb_transfer(
        value: *mut c_void,
        input: i32,
        bytes: *mut u8,
        length: usize,
        actual: *mut usize,
        error: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn gu_usb_close(value: *mut c_void);
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Disk {
    pub bsd: String,
    pub mount: PathBuf,
    pub writable: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NativeCandidate {
    pub ancestor: u64,
    pub generation: u64,
    pub main_access: bool,
    pub bluetooth_access: bool,
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
            bluetooth_access: self.bluetooth_access,
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
}
impl Watch {
    fn new() -> Result<Self, String> {
        // SAFETY: unique opaque owner, released once in Drop. Bridge synchronizes callbacks.
        let ptr =
            NonNull::new(unsafe { gu_watch_open() }).ok_or("USB topology watcher unavailable")?;
        let epoch = unsafe { gu_watch_epoch(ptr.as_ptr()) };
        Ok(Self { ptr, epoch })
    }
    fn unchanged(&self) -> bool {
        unsafe { gu_watch_epoch(self.ptr.as_ptr()) == self.epoch }
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
    _lock: File,
}
impl Session {
    pub fn open(confirmed: bool) -> Result<Self, String> {
        let home = std::env::var_os("HOME").ok_or("HOME unavailable for updater lock")?;
        let state = PathBuf::from(home).join("Library/Application Support/gulikit-updater");
        std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("update.lock"))
            .map_err(|e| e.to_string())?;
        lock.try_lock()
            .map_err(|e| format!("Another updater owns the process lock: {e}"))?;
        let watch = Watch::new()?;
        let target = discover()?.select(confirmed)?;
        let session = Self {
            target,
            watch,
            _lock: lock,
        };
        session.check()?;
        Ok(session)
    }
    pub fn check(&self) -> Result<(), String> {
        if !self.watch.unchanged() {
            return Err("USB topology changed; this session is invalidated. Rediscover and confirm the controller again.".into());
        }
        let current = discover()?.select(true)?;
        if current.ancestor != self.target.ancestor || current.generation != self.target.generation
        {
            return Err("Selected attachment changed".into());
        }
        if !self.watch.unchanged() {
            return Err("USB topology changed during discovery".into());
        }
        Ok(())
    }
    pub fn main(self) -> Result<MainSession, String> {
        self.check()?;
        let mount = self
            .target
            .mount
            .as_ref()
            .ok_or("Main volume is not mounted")?;
        let volume = Volume::open(mount)?;
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
            tag: 0,
            finished: false,
        };
        let result = (|| {
            for disk in port.session.target.disks.clone() {
                if !disk.mount.as_os_str().is_empty() {
                    port.session.check()?;
                    diskutil("unmount", &disk.bsd)?;
                    port.unmounted.push(disk.bsd);
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
            });
            if port.usb.is_none() {
                return Err(error_string(&error));
            }
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
    let output = Command::new("/usr/sbin/diskutil")
        .args([action, bsd])
        .output()
        .map_err(|e| e.to_string())?;
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
    fn read_version(&mut self) -> Result<Vec<u8>, String> {
        self.session.check()?;
        self.volume.read_version()
    }
    fn check_session(&mut self) -> Result<(), String> {
        self.session.check()?;
        self.volume.check_root()
    }
    fn create_destination(&mut self) -> Result<(), String> {
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
    fn wait_for_completion(&mut self) -> Result<bool, String> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(120) {
            let snapshot = discover()?;
            if !snapshot.incomplete.is_empty() {
                return Err("Discovery incomplete while awaiting Main completion".into());
            }
            if snapshot
                .candidates
                .iter()
                .any(|c| c.ancestor != self.session.target.ancestor)
            {
                return Err("Another update device appeared while awaiting completion".into());
            }
            if !snapshot
                .candidates
                .iter()
                .any(|c| c.ancestor == self.session.target.ancestor)
            {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(false)
    }
    fn finish(&mut self) -> Result<(), String> {
        self.volume.close()
    }
}

pub struct BluetoothSession {
    session: Session,
    usb: Option<NonNull<c_void>>,
    unmounted: Vec<String>,
    tag: u32,
    finished: bool,
}
impl BluetoothSession {
    pub fn target(&self) -> &NativeCandidate {
        &self.session.target
    }
    fn transfer(&mut self, input: bool, bytes: &mut [u8]) -> Result<usize, String> {
        let usb = self.usb.ok_or("No exclusive USB claim")?;
        let mut actual = 0;
        let mut error = [0i8; 1024];
        // SAFETY: uniquely owned live bridge object and bounded mutable buffers;
        // synchronous transfer returns before any buffer can be dropped.
        let result = unsafe {
            gu_usb_transfer(
                usb.as_ptr(),
                i32::from(input),
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut actual,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if result != 0 {
            return Err(format!(
                "USB transfer failed after {actual}/{} bytes: {}; raw={:02x?}",
                bytes.len(),
                error_string(&error),
                &bytes[..actual.min(bytes.len())]
            ));
        }
        if actual > bytes.len() {
            return Err("USB adapter returned an invalid transfer length".into());
        }
        Ok(actual)
    }
    /// Read-only qualification: zero-tail F1 with strict BOT checks.
    pub fn read_info(&mut self) -> Result<Vec<u8>, String> {
        self.check_session()?;
        self.command(0xf1, &[])
    }
    /// Read-only diagnostic in the same exclusive session, with no reset/reclaim.
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
        self.tag = self.tag.checked_add(1).ok_or("BOT tag exhausted")?;
        let mut cbw =
            command_block(self.tag, direction, length as u32, cdb).map_err(|e| e.to_string())?;
        if self.transfer(false, &mut cbw)? != 31 {
            return Err("Short CBW; command is uncertain".into());
        }
        let mut bytes = if direction == Direction::In {
            vec![0; length]
        } else {
            data.to_vec()
        };
        let actual = self.transfer(direction == Direction::In, &mut bytes)?;
        bytes.truncate(actual);
        if direction == Direction::In
            && data_stage(&bytes, self.tag, length as u32).map_err(|e| e.to_string())?
                == DataStage::EarlyStatus
        {
            return Err(format!("Early CSW instead of vendor data: {bytes:02x?}"));
        }
        let mut status = [0; 13];
        let status_actual = self.transfer(true, &mut status)?;
        validate_status(
            &status[..status_actual],
            self.tag,
            length as u32,
            actual as u32,
        )
        .map_err(|e| format!("{e}; CSW={status:02x?}, data={bytes:02x?}"))?;
        if actual != length {
            return Err(format!("Short vendor data {actual}/{length}: {bytes:02x?}"));
        }
        Ok(if direction == Direction::In {
            bytes
        } else {
            Vec::new()
        })
    }
}
impl BluetoothPort for BluetoothSession {
    fn check_session(&mut self) -> Result<(), String> {
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
        if let Some(usb) = self.usb.take() {
            unsafe {
                gu_usb_close(usb.as_ptr());
            }
        }
        let mut errors = Vec::new();
        for disk in std::mem::take(&mut self.unmounted) {
            // No cached disk number is acted upon after replacement/reconnect.
            if let Err(error) = self.session.check_transport() {
                errors.push(format!("Remount requires rediscovery: {error}"));
                break;
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
    Ok((port.session.target, raw, version))
}
