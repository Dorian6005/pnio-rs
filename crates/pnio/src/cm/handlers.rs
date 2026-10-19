//! Application-defined record handlers: the device-side counterpart of the
//! controller's `RDREC` / `WRREC` function blocks.
//!
//! A controller reads and writes *records* — opaque byte blocks addressed by
//! `(api, slot, subslot, index)` — over the acyclic DCE-RPC `Read` and `Write`
//! services. The crate already served the standard I&M records; this module lets the
//! application register its own handlers for **manufacturer-specific indices**
//! (`0x0000..=`[`USER_INDEX_MAX`]) and exchange blocks far larger than one cyclic frame.
//!
//! # Execution mode
//!
//! Each handler is registered with a [`RecordExec`]:
//!
//! - [`RecordExec::Inline`] runs the closure on the acyclic loop, right where the
//!   request is parsed. Cheapest and lowest latency, but the loop also serves DCP, alarms
//!   and RPC retransmissions, so the closure must be short and must not block.
//! - [`RecordExec::Worker`] hands the request to a dedicated worker thread. The loop
//!   keeps running meanwhile and the response is sent when the closure returns.
//!
//! Neither mode touches the real-time cyclic thread.
//!
//! # Panics
//!
//! A panicking handler never takes the device down: it is caught and answered as
//! [`RecordError::ModuleFailure`].

use super::PnioStatus;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

/// Highest index an application may register. `0x8000..` is reserved by the standard
/// and by this crate (I&M `0xAFF0..=0xAFF3`, diagnosis, `MultipleWrite` `0xE040`, ...).
pub const USER_INDEX_MAX: u16 = 0x7fff;

/// Largest record payload (bytes) served or accepted through a handler.
pub const MAX_RECORD_DATA: usize = 64 * 1024;

/// Which direction a [`RecordError`] is being reported for (selects the PNIORW
/// `ErrorCode`: `0xDE` read, `0xDF` write).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A record read (`RDREC`).
    Read,
    /// A record write (`WRREC`).
    Write,
}

/// Why a handler refused a record. Mapped to a PNIORW status (IEC 61158-6-10,
/// `ErrorDecode = 0x80`) by [`RecordError::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// `Code1 = 0xB0`: no such index.
    InvalidIndex,
    /// `Code1 = 0xB1`: the written data has the wrong length.
    WriteLength,
    /// `Code1 = 0xB2`: no such slot/subslot.
    InvalidSlotSubslot,
    /// `Code1 = 0xB5`: not possible in the current state.
    StateConflict,
    /// `Code1 = 0xB6`: access denied.
    AccessDenied,
    /// `Code1 = 0xB7`: range invalid — e.g. the record does not fit the controller's
    /// receive buffer.
    InvalidRange,
    /// `Code1 = 0xB8`: invalid parameter.
    InvalidParameter,
    /// `Code1 = 0xA7`: busy, try again.
    Busy,
    /// `Code1 = 0xA9`: feature not supported.
    FeatureNotSupported,
    /// `Code1 = 0xA2`: module failure (also what a panicking handler is reported as).
    ModuleFailure,
    /// `Code1 = 0xA0` (read) / `0xA1` (write) with an application-chosen `Code2`.
    Application(u8),
}

impl RecordError {
    /// The PNIO status this error is answered with.
    pub fn status(self, dir: Direction) -> PnioStatus {
        let code = match dir {
            Direction::Read => 0xde,
            Direction::Write => 0xdf,
        };
        let (code1, code2) = match self {
            RecordError::InvalidIndex => (0xb0, 0),
            RecordError::WriteLength => (0xb1, 0),
            RecordError::InvalidSlotSubslot => (0xb2, 0),
            RecordError::StateConflict => (0xb5, 0),
            RecordError::AccessDenied => (0xb6, 0),
            RecordError::InvalidRange => (0xb7, 0),
            RecordError::InvalidParameter => (0xb8, 0),
            RecordError::Busy => (0xa7, 0),
            RecordError::FeatureNotSupported => (0xa9, 0),
            RecordError::ModuleFailure => (0xa2, 0),
            RecordError::Application(c2) => (
                match dir {
                    Direction::Read => 0xa0,
                    Direction::Write => 0xa1,
                },
                c2,
            ),
        };
        PnioStatus::new(code, 0x80, code1, code2)
    }
}

/// What a handler is told about the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRequest {
    /// Application Process Identifier.
    pub api: u32,
    /// Target slot.
    pub slot: u16,
    /// Target subslot.
    pub subslot: u16,
    /// The record index.
    pub index: u16,
    /// Read: the buffer size the controller offers (`RecordDataLength`); the response
    /// must fit. Write: the length of the data being written.
    pub len: u32,
}

/// Where a handler runs. See the [module docs](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordExec {
    /// On the acyclic loop. Keep it short; never block.
    #[default]
    Inline,
    /// On the dedicated worker thread; the loop keeps serving meanwhile.
    Worker,
}

/// A read handler: produce the record for `req`.
pub type ReadFn = dyn Fn(&RecordRequest) -> Result<Vec<u8>, RecordError> + Send + Sync;
/// A write handler: consume the record `data` for `req`.
pub type WriteFn = dyn Fn(&RecordRequest, &[u8]) -> Result<(), RecordError> + Send + Sync;

#[derive(Clone)]
pub(crate) struct ReadEntry {
    pub f: Arc<ReadFn>,
    pub exec: RecordExec,
}

#[derive(Clone)]
pub(crate) struct WriteEntry {
    pub f: Arc<WriteFn>,
    pub exec: RecordExec,
}

/// Refused registrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The index is above [`USER_INDEX_MAX`]: reserved for the standard and the crate.
    #[error("record index {0:#06x} is reserved (user indices are 0x0000..=0x7fff)")]
    ReservedIndex(u16),
}

#[derive(Default)]
struct Inner {
    read: BTreeMap<u16, ReadEntry>,
    write: BTreeMap<u16, WriteEntry>,
}

/// The shared table of record handlers. Cloning is cheap and every clone sees the same
/// table, so the application can register or remove handlers while the device runs.
#[derive(Clone, Default)]
pub struct RecordRegistry {
    inner: Arc<RwLock<Inner>>,
}

impl RecordRegistry {
    /// An empty registry.
    pub fn new() -> RecordRegistry {
        RecordRegistry::default()
    }

    /// Registers (or replaces) the read handler for `index`.
    pub fn on_read(
        &self,
        index: u16,
        exec: RecordExec,
        f: impl Fn(&RecordRequest) -> Result<Vec<u8>, RecordError> + Send + Sync + 'static,
    ) -> Result<(), RegisterError> {
        check_index(index)?;
        self.write_lock().read.insert(
            index,
            ReadEntry {
                f: Arc::new(f),
                exec,
            },
        );
        Ok(())
    }

    /// Registers (or replaces) the write handler for `index`.
    pub fn on_write(
        &self,
        index: u16,
        exec: RecordExec,
        f: impl Fn(&RecordRequest, &[u8]) -> Result<(), RecordError> + Send + Sync + 'static,
    ) -> Result<(), RegisterError> {
        check_index(index)?;
        self.write_lock().write.insert(
            index,
            WriteEntry {
                f: Arc::new(f),
                exec,
            },
        );
        Ok(())
    }

    /// Removes both handlers of `index`; the index is answered "invalid index" again.
    pub fn remove(&self, index: u16) {
        let mut g = self.write_lock();
        g.read.remove(&index);
        g.write.remove(&index);
    }

    pub(crate) fn read_entry(&self, index: u16) -> Option<ReadEntry> {
        self.read_lock().read.get(&index).cloned()
    }

    pub(crate) fn write_entry(&self, index: u16) -> Option<WriteEntry> {
        self.read_lock().write.get(&index).cloned()
    }

    fn read_lock(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_lock(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }
}

fn check_index(index: u16) -> Result<(), RegisterError> {
    if index > USER_INDEX_MAX {
        Err(RegisterError::ReservedIndex(index))
    } else {
        Ok(())
    }
}

/// Runs a read handler, converting a panic into [`RecordError::ModuleFailure`] and
/// enforcing the size limits (the controller's buffer and [`MAX_RECORD_DATA`]).
pub(crate) fn call_read(f: &ReadFn, req: &RecordRequest) -> Result<Vec<u8>, RecordError> {
    let data =
        catch_unwind(AssertUnwindSafe(|| f(req))).unwrap_or(Err(RecordError::ModuleFailure))?;
    if data.len() > MAX_RECORD_DATA || data.len() as u64 > u64::from(req.len) {
        return Err(RecordError::InvalidRange);
    }
    Ok(data)
}

/// Runs a write handler, converting a panic into [`RecordError::ModuleFailure`].
pub(crate) fn call_write(f: &WriteFn, req: &RecordRequest, data: &[u8]) -> Result<(), RecordError> {
    catch_unwind(AssertUnwindSafe(|| f(req, data))).unwrap_or(Err(RecordError::ModuleFailure))
}

/// One unit of work for the worker thread: a deferred read or the app-handled records
/// of one write request. Run it with [`RecordJob::run`].
pub struct RecordJob {
    pub(crate) id: u64,
    work: Work,
}

enum Work {
    Read { req: RecordRequest, f: Arc<ReadFn> },
    Write { items: Vec<WriteItem> },
}

pub(crate) struct WriteItem {
    /// Position of the record inside the originating write request.
    pub rec_idx: usize,
    pub req: RecordRequest,
    pub data: Vec<u8>,
    pub f: Arc<WriteFn>,
}

/// The result of a [`RecordJob`], to be handed back to `Cm::complete_job`.
pub struct JobDone {
    pub(crate) id: u64,
    pub(crate) out: JobOutput,
}

pub(crate) enum JobOutput {
    Read(Result<Vec<u8>, RecordError>),
    Write(Vec<(usize, Result<(), RecordError>)>),
}

impl RecordJob {
    pub(crate) fn read(id: u64, req: RecordRequest, f: Arc<ReadFn>) -> RecordJob {
        RecordJob {
            id,
            work: Work::Read { req, f },
        }
    }

    pub(crate) fn write(id: u64, items: Vec<WriteItem>) -> RecordJob {
        RecordJob {
            id,
            work: Work::Write { items },
        }
    }

    /// Executes the handler(s). Safe to call from any thread.
    pub fn run(self) -> JobDone {
        let out = match self.work {
            Work::Read { req, f } => JobOutput::Read(call_read(&*f, &req)),
            Work::Write { items } => JobOutput::Write(
                items
                    .into_iter()
                    .map(|it| (it.rec_idx, call_write(&*it.f, &it.req, &it.data)))
                    .collect(),
            ),
        };
        JobDone { id: self.id, out }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(len: u32) -> RecordRequest {
        RecordRequest {
            api: 0,
            slot: 1,
            subslot: 1,
            index: 0x10,
            len,
        }
    }

    #[test]
    fn reserved_indices_are_refused() {
        let r = RecordRegistry::new();
        assert_eq!(
            r.on_read(0x8000, RecordExec::Inline, |_| Ok(vec![])),
            Err(RegisterError::ReservedIndex(0x8000))
        );
        assert_eq!(
            r.on_write(0xaff1, RecordExec::Inline, |_, _| Ok(())),
            Err(RegisterError::ReservedIndex(0xaff1))
        );
        assert!(r
            .on_read(0x7fff, RecordExec::Inline, |_| Ok(vec![]))
            .is_ok());
        assert!(r.read_entry(0x7fff).is_some());
        r.remove(0x7fff);
        assert!(r.read_entry(0x7fff).is_none());
    }

    #[test]
    fn clones_share_one_table() {
        let a = RecordRegistry::new();
        let b = a.clone();
        a.on_write(5, RecordExec::Worker, |_, _| Ok(())).unwrap();
        assert_eq!(b.write_entry(5).unwrap().exec, RecordExec::Worker);
    }

    #[test]
    fn panicking_handler_becomes_module_failure() {
        let f: Arc<ReadFn> = Arc::new(|_| panic!("boom"));
        assert_eq!(call_read(&*f, &req(100)), Err(RecordError::ModuleFailure));
        let g: Arc<WriteFn> = Arc::new(|_, _| panic!("boom"));
        assert_eq!(
            call_write(&*g, &req(1), &[1]),
            Err(RecordError::ModuleFailure)
        );
    }

    #[test]
    fn oversized_read_is_an_invalid_range() {
        let f: Arc<ReadFn> = Arc::new(|_| Ok(vec![0; 10]));
        assert_eq!(call_read(&*f, &req(9)), Err(RecordError::InvalidRange));
        assert_eq!(call_read(&*f, &req(10)).unwrap().len(), 10);
    }

    #[test]
    fn statuses_use_the_pniorw_family() {
        let s = RecordError::InvalidIndex.status(Direction::Read);
        assert_eq!(
            (s.code(), s.decode(), s.code1(), s.code2()),
            (0xde, 0x80, 0xb0, 0)
        );
        let s = RecordError::Application(7).status(Direction::Write);
        assert_eq!(
            (s.code(), s.decode(), s.code1(), s.code2()),
            (0xdf, 0x80, 0xa1, 7)
        );
    }

    #[test]
    fn job_runs_every_write_item_in_order() {
        let f: Arc<WriteFn> = Arc::new(|r, d| {
            if d.is_empty() {
                Err(RecordError::WriteLength)
            } else {
                assert_eq!(r.index, 0x10);
                Ok(())
            }
        });
        let items = vec![
            WriteItem {
                rec_idx: 1,
                req: req(1),
                data: vec![1],
                f: f.clone(),
            },
            WriteItem {
                rec_idx: 3,
                req: req(0),
                data: vec![],
                f,
            },
        ];
        let done = RecordJob::write(9, items).run();
        assert_eq!(done.id, 9);
        match done.out {
            JobOutput::Write(v) => {
                assert_eq!(v, vec![(1, Ok(())), (3, Err(RecordError::WriteLength))])
            }
            _ => panic!("wrong output"),
        }
    }
}
