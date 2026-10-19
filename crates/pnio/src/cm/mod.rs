//! PROFINET Context Manager (CM): PNIO status, PNIO block header, and the
//! Connect-request block parsers (ARBlockReq, IOCRBlockReq, ExpectedSubmoduleBlockReq,
//! AlarmCRBlockReq) needed to establish an Application Relationship (AR).

pub mod ar;
pub mod block;
pub mod connect;
pub mod control;
pub mod handlers;
pub mod model;
pub mod records;
pub mod status;
pub mod write;

pub use ar::{
    AbortReason, Action, Ar, ArContext, ArState, Event, ACTIVITY_TIMEOUT_UNIT,
    APP_READY_MAX_ATTEMPTS, APP_READY_TIMEOUT,
};
pub use block::{
    ty, AlarmCrBlockReq, ArBlockReq, BlockHeader, Cursor, DataDescription, ExpectedApi,
    ExpectedSubmodule, ExpectedSubmoduleBlockReq, IocrApi, IocrBlockReq, IocrObject,
};
pub use connect::{build_connect_res, validate, ArParams, ConnectReq, IocrParams};
pub use control::{app_ready_req, cmd, prm_end_done, release_done, ControlBlock};
pub use handlers::{
    Direction, JobDone, RecordError, RecordExec, RecordJob, RecordRegistry, RecordRequest,
    RegisterError, MAX_RECORD_DATA, USER_INDEX_MAX,
};
pub use model::{DeviceModel, SlotModel, SubmoduleModel};
pub use records::{build_read_res, read_record, write_im_record, ReadReq, RecordCtx};
pub use status::{ConnectBlock, PnioStatus};
pub use write::{build_write_res, build_write_res_with, Record, WriteReq, INDEX_MULTIPLE_WRITE};

use crate::im::{Im0, ImStore, INDEX_IM1, INDEX_IM3};
use crate::rpc::frag::{self, FRAG_BODY_MAX, MAX_FRAGMENTS, MAX_STUB};
use crate::rpc::{
    Drep, NdrRequest, NdrResponse, Opnum, PacketType, RpcError, RpcHeader, Uuid, FLAG1_FRAG,
    FLAG1_IDEMPOTENT, FLAG1_LAST_FRAG, FLAG1_NO_FACK, PNIO_CONTROLLER_INTERFACE,
    PNIO_DEVICE_INTERFACE, PNIO_UDP_PORT,
};
use handlers::{call_read, call_write, JobOutput, WriteItem};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors from parsing/serializing PNIO blocks (the 6-byte header and the per-type bodies).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlockError {
    /// Fewer bytes available than the block shape being parsed needs.
    #[error("block buffer too short: need {need}, have {have}")]
    TooShort {
        /// Bytes the parse needs.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },
    /// The block header's `BlockType` is not the one the caller asked to parse.
    #[error("unexpected block type: expected {expected:#06x}, got {got:#06x}")]
    UnexpectedType {
        /// `BlockType` the caller expected.
        expected: u16,
        /// `BlockType` actually found.
        got: u16,
    },
    /// The block header's version is not `1.0`.
    #[error("bad block version {0}.{1} (expected 1.0)")]
    BadVersion(u8, u8),
    /// The block header's `BlockLength` declares more bytes than are available.
    #[error("bad block length: declared {declared}, available {available}")]
    BadLength {
        /// `BlockLength` as declared in the block header.
        declared: u16,
        /// Bytes actually available after the header.
        available: usize,
    },
    /// The block parsed to the right length and type but its content violates a
    /// structural rule (e.g. a count field disagreeing with the actual data).
    #[error("malformed block: {0}")]
    Malformed(&'static str),
}

/// Errors from the Context Manager's AR establishment / lifecycle handling.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CmError {
    /// A PNIO block failed to parse; see [`BlockError`].
    #[error("block error: {0}")]
    Block(#[from] BlockError),
    /// The request is well-formed but the AR/CM logic rejects it with this status.
    #[error("connect rejected: {0:?}")]
    Reject(PnioStatus),
}

// ---------------------------------------------------------------------------------
// Cm: RPC datagram <-> AR glue.
// ---------------------------------------------------------------------------------

/// Our advertised max NDR args length (`args_max`/`max_count`) for outgoing calls —
/// p-net's value, required byte-for-byte by the golden ApplicationReady request.
pub const RPC_ARGS_MAX: u32 = 1340;

/// Maximum number of cached full response PDUs kept for retransmission, FIFO eviction.
const CACHE_CAPACITY: usize = 4;

/// Fragments of one response we send before waiting for a `fack`.
const FRAG_WINDOW: usize = 8;
/// How long a fragmented response waits for a `fack` before resending the first
/// unacknowledged fragment.
const FRAG_STALL: Duration = Duration::from_millis(250);
/// Resends of the first unacknowledged fragment before the transfer is abandoned.
const FRAG_MAX_RETRIES: u8 = 6;
/// An incomplete fragmented request is forgotten after this much silence.
const RX_TIMEOUT: Duration = Duration::from_secs(5);
/// Record jobs that may be outstanding on the worker at once; more are answered "busy".
const MAX_PENDING_JOBS: usize = 8;

/// One outgoing RPC datagram: the raw bytes to send and the address to send them to.
#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing {
    /// The complete UDP payload (RPC header + NDR body) to send.
    pub bytes: Vec<u8>,
    /// Destination address.
    pub to: SocketAddr,
}

/// The effects of one `Cm::handle_datagram`/`Cm::tick` call: datagrams to send, and AR
/// state-change notifications to report (state plus the abort reason, when any).
#[derive(Debug, Default, PartialEq)]
pub struct CmOutput {
    /// Datagrams the caller must send on the wire, in order.
    pub send: Vec<Outgoing>,
    /// AR state transitions to report to the application, each with the reason when
    /// the transition is a fall back to [`ArState::Idle`] due to an abort.
    pub notify: Vec<(ArState, Option<AbortReason>)>,
}

/// The request-specific fields needed to build and cache a Response PDU, gathered
/// from the incoming request's RPC header plus its NDR `args_max`.
#[derive(Clone)]
struct RespondCtx {
    object: Uuid,
    interface: Uuid,
    activity: Uuid,
    seq_num: u32,
    opnum: u16,
    args_max: u32,
    from: SocketAddr,
}

/// Maps a block-parsing failure to the PNIO status to answer with: `Reject(status)`
/// carries its own status through unchanged; a `Block` error logs and falls back to
/// `default` (the caller's per-opnum convention).
fn error_status(e: &CmError, default: PnioStatus) -> PnioStatus {
    match e {
        CmError::Reject(status) => *status,
        CmError::Block(be) => {
            log::warn!("PNIO block parse error: {be}");
            default
        }
    }
}

fn respond(status: PnioStatus) -> Vec<Action> {
    vec![Action::Respond {
        status,
        blocks: Vec::new(),
    }]
}

fn respond_ok(blocks: Vec<u8>) -> Vec<Action> {
    vec![Action::Respond {
        status: PnioStatus::OK,
        blocks,
    }]
}

/// RPC datagram <-> AR glue: parses the DCE-RPC/NDR/PNIO envelope of an incoming UDP
/// datagram, feeds the pure [`Ar`] state machine the resulting [`Event`], and wraps its
/// [`Action`]s back into complete RPC PDUs — byte-exact against the golden p-net <-> CPU
/// capture. Also owns the small response cache (a retransmitted request is answered with
/// the identical cached bytes instead of re-running the AR machine) and the call sequence
/// number / controller address used for our outgoing ApplicationReady calls.
pub struct Cm {
    ar: Ar,
    /// Own copy of the device model (`Ar` holds one too, for Connect validation):
    /// needed here to serve I&M reads/writes without a model accessor on `Ar`.
    model: DeviceModel,
    /// Device identity answered by I&M0 reads; `Im0::default()` until [`Cm::set_im`]
    /// is called.
    im0: Im0,
    /// The writable I&M1-3 records; blank, unpersisted, until [`Cm::set_im`] is
    /// called.
    im: ImStore,
    /// Activity UUID used for calls we place to the controller (ApplicationReady).
    activity_seed: Uuid,
    /// Seq num to assign to the *next new* outgoing call to the controller.
    call_seq: u32,
    /// Seq num of the current outstanding call, reused unchanged by `tick`'s retries.
    current_call_seq: Option<u32>,
    /// Controller address for outgoing calls, learned from the Connect request's
    /// source address (its IP, PNIO's well-known UDP port).
    controller_addr: Option<SocketAddr>,
    /// Cached responses, keyed by `(activity, seq_num)`, FIFO eviction at
    /// [`CACHE_CAPACITY`] entries.
    cache: VecDeque<((Uuid, u32), Cached)>,
    /// The application's record handlers (shared with the application).
    registry: RecordRegistry,
    /// The fragmented request being reassembled, if any.
    rx: Option<Reasm>,
    /// The fragmented response being sent, if any.
    tx: Option<TxFrag>,
    /// Record jobs handed to the worker, awaiting [`Cm::complete_job`].
    pending: Vec<Pending>,
    /// Jobs queued for the worker, drained by [`Cm::take_jobs`].
    jobs_out: Vec<RecordJob>,
    /// Id of the next job.
    next_job: u64,
}

/// A response kept for retransmission: one PDU, or the fragments of a large one.
#[derive(Clone)]
enum Cached {
    One(Vec<u8>),
    Frags(Vec<Vec<u8>>),
}

/// A fragmented request being reassembled.
struct Reasm {
    key: (Uuid, u32),
    /// The call exceeded the limits: its remaining fragments are ignored until the
    /// reassembly times out.
    dead: bool,
    first: Option<RpcHeader>,
    parts: BTreeMap<u16, Vec<u8>>,
    bytes: usize,
    last: Option<u16>,
    touched: Instant,
}

/// A fragmented response being sent.
struct TxFrag {
    key: (Uuid, u32),
    to: SocketAddr,
    frags: Vec<Vec<u8>>,
    /// Next fragment to send.
    next: usize,
    /// Fragments `0..acked` are acknowledged.
    acked: usize,
    sent_at: Instant,
    retries: u8,
}

/// A record request whose handler runs on the worker.
struct Pending {
    id: u64,
    key: (Uuid, u32),
    ctx: RespondCtx,
    /// The AR the request arrived on; a result for any other AR is dropped.
    ar_uuid: Option<Uuid>,
    kind: PendingKind,
}

enum PendingKind {
    Read(ReadReq),
    Write {
        req: WriteReq,
        statuses: Vec<PnioStatus>,
    },
}

impl Cm {
    /// A fresh Context Manager for `model`, idle (no AR). `activity_seed` is the
    /// activity UUID used for calls this device places to the controller
    /// (ApplicationReady); it should be stable across the device's lifetime.
    pub fn new(model: DeviceModel, activity_seed: Uuid) -> Cm {
        Cm {
            model: model.clone(),
            ar: Ar::new(model),
            im0: Im0::default(),
            im: ImStore::new(),
            activity_seed,
            call_seq: 0,
            current_call_seq: None,
            controller_addr: None,
            cache: VecDeque::new(),
            registry: RecordRegistry::new(),
            rx: None,
            tx: None,
            pending: Vec::new(),
            jobs_out: Vec::new(),
            next_job: 0,
        }
    }

    /// The table of application record handlers. Clones share the same table, so
    /// handlers may be registered or removed while the device runs.
    pub fn registry(&self) -> RecordRegistry {
        self.registry.clone()
    }

    /// Replaces the handler table (e.g. with one the application already shares).
    pub fn set_registry(&mut self, registry: RecordRegistry) {
        self.registry = registry;
    }

    /// Takes the record jobs queued for the worker thread (handlers registered with
    /// [`RecordExec::Worker`]). Run each with [`RecordJob::run`] on any thread and hand
    /// the result back to [`Cm::complete_job`].
    pub fn take_jobs(&mut self) -> Vec<RecordJob> {
        std::mem::take(&mut self.jobs_out)
    }

    /// Number of record requests currently waiting for the worker's result.
    pub fn pending_jobs(&self) -> usize {
        self.pending.len()
    }

    /// Delivers a worker result: builds and sends (and caches) the response of the
    /// request that was deferred. A result for an AR that is gone, or an unknown job,
    /// is dropped.
    pub fn complete_job(&mut self, done: JobDone, now: Instant) -> CmOutput {
        let mut output = CmOutput::default();
        let Some(pos) = self.pending.iter().position(|p| p.id == done.id) else {
            log::debug!("record job {} has no pending request; dropping", done.id);
            return output;
        };
        let p = self.pending.remove(pos);
        if p.ar_uuid != self.ar.context().map(|c| c.params.ar_uuid) {
            log::warn!(
                "record job {} finished after its AR ended; dropping",
                done.id
            );
            return output;
        }
        let actions = match (p.kind, done.out) {
            (PendingKind::Read(req), JobOutput::Read(Ok(data))) => {
                finish_read(&req, &data, p.ctx.args_max)
            }
            (PendingKind::Read(_), JobOutput::Read(Err(e))) => respond(e.status(Direction::Read)),
            (PendingKind::Write { req, mut statuses }, JobOutput::Write(results)) => {
                for (i, r) in results {
                    statuses[i] =
                        r.map_or_else(|e| e.status(Direction::Write), |()| PnioStatus::OK);
                }
                finish_write(&req, &statuses)
            }
            _ => {
                log::error!("record job {} returned the wrong kind of result", p.id);
                respond(PnioStatus::service_unsupported())
            }
        };
        self.apply(actions, Some((p.ctx, p.key)), true, &mut output, now);
        output
    }

    /// The AR's current lifecycle state.
    pub fn state(&self) -> ArState {
        self.ar.state()
    }

    /// The current AR's negotiated context (parameters, layout, ...), if one is established.
    pub fn context(&self) -> Option<&ArContext> {
        self.ar.context()
    }

    /// The next time the caller must call [`Cm::tick`] (a pending timeout), or `None`
    /// if nothing is outstanding.
    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.ar.next_deadline(),
            self.tx.as_ref().map(|t| t.sent_at + FRAG_STALL),
            self.rx.as_ref().map(|r| r.touched + RX_TIMEOUT),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Replace the device identity answered by I&M0 reads and the writable I&M1-3
    /// store (e.g. once loaded from config/a backing file at startup). Until called,
    /// `Cm` answers with `Im0::default()` and blank I&M1-3 records.
    pub fn set_im(&mut self, im0: Im0, store: ImStore) {
        self.im0 = im0;
        self.im = store;
    }

    /// The current I&M1-3 store (e.g. so the application can read back tag
    /// function/location after a controller Write).
    pub fn im_store(&self) -> &ImStore {
        &self.im
    }

    /// Parse one incoming UDP datagram and drive the AR machine, returning the PDUs to
    /// send and the AR notifications to report. RPC envelope errors ([`RpcHeader::parse`],
    /// [`NdrRequest::parse`]/[`NdrResponse::parse`], a foreign interface UUID) propagate to
    /// the caller to log and drop; PNIO-block-level parse failures are answered in-band
    /// with the appropriate PNIO status instead.
    pub fn handle_datagram(
        &mut self,
        buf: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<CmOutput, RpcError> {
        let h = RpcHeader::parse_any(buf)?;
        let body = &buf[RpcHeader::LEN..];
        match h.ptype {
            PacketType::Fack => return Ok(self.on_fack(&h, from, now)),
            PacketType::Request if h.is_fragment() => {
                return self.on_request_fragment(h, body, from, now)
            }
            _ if h.is_fragment() => {
                return Err(RpcError::Fragmented {
                    frag_num: h.frag_num,
                    flags1: h.flags1,
                })
            }
            _ => {}
        }
        self.handle_pdu(h, body, from, now)
    }

    /// Handles one complete (reassembled, if it was fragmented) call PDU.
    fn handle_pdu(
        &mut self,
        h: RpcHeader,
        body: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<CmOutput, RpcError> {
        let mut output = CmOutput::default();

        if h.ptype == PacketType::Response {
            // The controller answering our ApplicationReady call.
            let (n, _blocks) = NdrResponse::parse(body, h.drep)?;
            let actions = self.ar.on(
                Event::AppReadyRsp {
                    status: PnioStatus(n.status),
                },
                now,
            );
            self.apply(actions, None, false, &mut output, now);
            return Ok(output);
        }
        if h.ptype != PacketType::Request {
            log::warn!(
                "dropping DCE-RPC packet type {:?}, only Request/Response handled",
                h.ptype
            );
            return Ok(output);
        }

        if h.interface != PNIO_DEVICE_INTERFACE {
            return Err(RpcError::BadInterface(h.interface));
        }

        let cache_key = (h.activity, h.seq_num);
        if self.resend_cached(&cache_key, from, now, &mut output) {
            return Ok(output);
        }
        if self.pending.iter().any(|p| p.key == cache_key) {
            log::debug!(
                "request {cache_key:?} is still being handled by the worker; ignoring retry"
            );
            return Ok(output);
        }

        let (req, blocks) = NdrRequest::parse(body, h.drep)?;
        let rctx = RespondCtx {
            object: h.object,
            interface: h.interface,
            activity: h.activity,
            seq_num: h.seq_num,
            opnum: h.opnum,
            args_max: req.args_max,
            from,
        };

        let actions = match Opnum::from_u16(h.opnum) {
            Some(Opnum::Connect) => {
                let actions = match ConnectReq::parse(blocks) {
                    Ok(req) => self.ar.on(Event::ConnectReq(req), now),
                    Err(e) => respond(error_status(
                        &e,
                        PnioStatus::connect_reject(ConnectBlock::ArBlock, 0xfe),
                    )),
                };
                // Remember the controller's address (PrmEnd, later on the same AR, needs
                // it to place the ApplicationReady call, and `tick`'s retries need it with
                // no request in hand at all), and drop any stale outstanding-call seq_num,
                // whenever this Connect actually (re-)established the AR: the nominal
                // Idle -> Connected path, or a controller-reconnect takeover (`Ar` aborts
                // the stale AR and re-establishes a new one within the same `on()` call, so
                // both `Notify`s appear in `actions`). A stray Connect from another host
                // while an AR already exists (refused with `connect_ar_already_exists`) or
                // a rejected/malformed one produces no `Notify { state: Connected, .. }`
                // and must not redirect the real AR's outgoing calls.
                if actions.iter().any(|a| {
                    matches!(
                        a,
                        Action::Notify {
                            state: ArState::Connected,
                            ..
                        }
                    )
                }) {
                    self.controller_addr = Some(SocketAddr::new(from.ip(), PNIO_UDP_PORT));
                    // `call_seq` is NOT reset here: it's scoped to `activity_seed`, which
                    // is fixed for the device's lifetime, not per-AR. DCE-RPC CL duplicate
                    // detection is per `(activity, seq_num)` with a monotonically
                    // increasing seq_num — the same rule our own response cache relies on
                    // — so restarting it at 0 on a reconnect would re-send `(activity_seed,
                    // 0)`, a pair the controller already completed for the previous AR, and
                    // risk being discarded as a duplicate.
                    self.current_call_seq = None;
                }
                actions
            }
            Some(Opnum::Write) => match WriteReq::parse(blocks) {
                Ok(req) => self.handle_write(req, now, &rctx),
                Err(e) => respond(error_status(&e, PnioStatus::write_index_unsupported())),
            },
            Some(Opnum::Control) => match ControlBlock::parse(blocks) {
                Ok(cb) if cb.command == cmd::PRM_END => self.ar.on(Event::PrmEndReq(cb), now),
                Ok(_) => respond(PnioStatus::control_wrong_state()),
                Err(e) => respond(error_status(&e, PnioStatus::control_wrong_state())),
            },
            Some(Opnum::Release) => match ControlBlock::parse(blocks) {
                Ok(cb) => self.ar.on(Event::ReleaseReq(cb), now),
                Err(e) => respond(error_status(&e, PnioStatus::control_wrong_state())),
            },
            // `Read` requires the request's `ar_uuid` to match the established AR
            // (or an established AR to exist at all); `ReadImplicit` skips that
            // check — it's meant to be usable before/without an AR (e.g. the CPU's
            // periodic I&M probes). Both fall back to the PNIORW "invalid index"
            // status for an index/(slot, subslot) we don't serve, rather than
            // `service_unsupported`, so an unrecognized probe decodes sensibly in a
            // trace instead of looking like a Connect-block error.
            Some(Opnum::Read) => match ReadReq::parse(blocks) {
                Ok(req) => self.handle_read(&req, true, &rctx),
                Err(e) => respond(error_status(&e, PnioStatus::read_index_unsupported())),
            },
            Some(Opnum::ReadImplicit) => match ReadReq::parse(blocks) {
                Ok(req) => self.handle_read(&req, false, &rctx),
                Err(e) => respond(error_status(&e, PnioStatus::read_index_unsupported())),
            },
            None => respond(PnioStatus::service_unsupported()),
        };

        self.apply(actions, Some((rctx, cache_key)), true, &mut output, now);
        Ok(output)
    }

    /// Drive the AR machine's timers (activity / ApplicationReady retry) and wrap any
    /// resulting retry call or notification.
    pub fn tick(&mut self, now: Instant) -> CmOutput {
        let mut output = CmOutput::default();
        let actions = self.ar.on(Event::Tick, now);
        self.apply(actions, None, false, &mut output, now);
        self.tick_fragments(now, &mut output);
        output
    }

    /// Force the AR to `Idle` for an externally-observed `reason` (e.g. the RT
    /// runner's consumer watchdog expiring), mapping the resulting actions exactly
    /// like [`Cm::tick`] does. A no-op (no `Notify`) if the AR is already `Idle`.
    pub fn abort(&mut self, reason: AbortReason, now: Instant) -> CmOutput {
        let mut output = CmOutput::default();
        let actions = self.ar.on(Event::Abort(reason), now);
        self.apply(actions, None, false, &mut output, now);
        output
    }

    /// Turn a batch of `Ar` actions into `CmOutput`: build+cache a Response PDU for each
    /// `Respond`, build a Request PDU to the controller for each `CallController`
    /// (`call_is_new` selects a fresh call sequence number vs. reusing the outstanding
    /// one, for `tick`'s retries), and forward `Notify`s unchanged.
    fn apply(
        &mut self,
        actions: Vec<Action>,
        resp_ctx: Option<(RespondCtx, (Uuid, u32))>,
        call_is_new: bool,
        output: &mut CmOutput,
        now: Instant,
    ) {
        for action in actions {
            match action {
                Action::Respond { status, blocks } => match &resp_ctx {
                    Some((ctx, cache_key)) => {
                        let mut pdus = build_response_pdus(ctx, status, blocks);
                        if pdus.len() == 1 {
                            let pdu = pdus.remove(0);
                            self.cache_insert(*cache_key, Cached::One(pdu.clone()));
                            output.send.push(Outgoing {
                                bytes: pdu,
                                to: ctx.from,
                            });
                        } else {
                            self.cache_insert(*cache_key, Cached::Frags(pdus.clone()));
                            self.start_tx(*cache_key, ctx.from, pdus, now, output);
                        }
                    }
                    None => {
                        log::warn!("Respond action with no request context; dropping");
                    }
                },
                Action::CallController { blocks } => {
                    let to = self
                        .controller_addr
                        .expect("controller_addr set at Connect before any AR can reach PrmEnd");
                    let pdu = self.build_call_pdu(blocks, call_is_new);
                    output.send.push(Outgoing { bytes: pdu, to });
                }
                Action::Notify { state, reason } => output.notify.push((state, reason)),
            }
        }
    }

    /// Build the ApplicationReady request PDU: fresh call (`is_new`) advances
    /// `call_seq` and remembers it as the outstanding call; a retry reuses it unchanged.
    fn build_call_pdu(&mut self, blocks: Vec<u8>, is_new: bool) -> Vec<u8> {
        let object = self
            .ar
            .context()
            .expect("ctx present for CallController action")
            .params
            .initiator_object_uuid;
        let seq_num = if is_new {
            let seq_num = self.call_seq;
            self.call_seq += 1;
            self.current_call_seq = Some(seq_num);
            seq_num
        } else {
            self.current_call_seq
                .expect("retry call with no prior new call")
        };
        let header = RpcHeader {
            ptype: PacketType::Request,
            flags1: FLAG1_IDEMPOTENT,
            flags2: 0,
            drep: Drep::BIG,
            serial_hi: 0,
            object,
            interface: PNIO_CONTROLLER_INTERFACE,
            activity: self.activity_seed,
            server_boot: 0,
            if_version: 1,
            seq_num,
            opnum: Opnum::Control.to_u16(),
            ihint: 0xffff,
            ahint: 0xffff,
            frag_len: (NdrRequest::LEN + blocks.len()) as u16,
            frag_num: 0,
            auth_proto: 0,
            serial_lo: 0,
        };
        let ndr = NdrRequest::for_blocks(RPC_ARGS_MAX, blocks.len() as u32);
        let mut pdu = Vec::with_capacity(RpcHeader::LEN + NdrRequest::LEN + blocks.len());
        header.write(&mut pdu);
        ndr.write(&mut pdu, Drep::BIG);
        pdu.extend_from_slice(&blocks);
        pdu
    }

    /// Serve a Write. Records for which the application registered a write handler are
    /// dispatched to it and **never stored** by the AR (so runtime traffic cannot exhaust
    /// the AR's parameter-record cap); everything else (Connect-phase parameter records,
    /// I&M1-3, the `MultipleWrite` container) takes the standard path.
    fn handle_write(&mut self, req: WriteReq, now: Instant, rctx: &RespondCtx) -> Vec<Action> {
        let app: Vec<usize> = req
            .records
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.index != INDEX_MULTIPLE_WRITE && self.registry.write_entry(r.index).is_some()
            })
            .map(|(i, _)| i)
            .collect();
        if app.is_empty() {
            return self.handle_write_standard(req, now);
        }

        if let Err(status) = self.ar.write_access(&req.records, now) {
            return respond(status);
        }
        let mut statuses = vec![PnioStatus::OK; req.records.len()];

        // A request mixing handler records with standard ones: the standard ones go
        // through the AR as usual, and if the AR refuses them the whole call is refused.
        let std_records: Vec<Record> = req
            .records
            .iter()
            .enumerate()
            .filter(|(i, _)| !app.contains(i))
            .map(|(_, r)| r.clone())
            .collect();
        if std_records.iter().any(|r| r.index != INDEX_MULTIPLE_WRITE) {
            let actions = self.handle_write_standard(
                WriteReq {
                    records: std_records,
                },
                now,
            );
            let accepted = actions
                .iter()
                .any(|a| matches!(a, Action::Respond { status, .. } if status.is_ok()));
            if !accepted {
                return actions;
            }
        }

        let mut items = Vec::new();
        for &i in &app {
            let r = &req.records[i];
            if self.model.find(r.slot, r.subslot).is_none() {
                statuses[i] = RecordError::InvalidSlotSubslot.status(Direction::Write);
                continue;
            }
            if r.data.len() > MAX_RECORD_DATA {
                statuses[i] = RecordError::WriteLength.status(Direction::Write);
                continue;
            }
            let Some(entry) = self.registry.write_entry(r.index) else {
                // Unregistered between the scan above and now.
                statuses[i] = RecordError::InvalidIndex.status(Direction::Write);
                continue;
            };
            let rr = RecordRequest {
                api: r.api,
                slot: r.slot,
                subslot: r.subslot,
                index: r.index,
                len: r.data.len() as u32,
            };
            items.push((i, rr, entry));
        }

        if items.iter().any(|(_, _, e)| e.exec == RecordExec::Worker) {
            if self.pending.len() >= MAX_PENDING_JOBS {
                return respond(RecordError::Busy.status(Direction::Write));
            }
            let id = self.next_job_id();
            let work = items
                .into_iter()
                .map(|(i, rr, e)| WriteItem {
                    rec_idx: i,
                    req: rr,
                    data: req.records[i].data.clone(),
                    f: e.f,
                })
                .collect();
            self.jobs_out.push(RecordJob::write(id, work));
            self.pending.push(Pending {
                id,
                key: (rctx.activity, rctx.seq_num),
                ctx: rctx.clone(),
                ar_uuid: self.ar.context().map(|c| c.params.ar_uuid),
                kind: PendingKind::Write { req, statuses },
            });
            return Vec::new();
        }

        for (i, rr, entry) in items {
            statuses[i] = match call_write(&*entry.f, &rr, &req.records[i].data) {
                Ok(()) => PnioStatus::OK,
                Err(e) => e.status(Direction::Write),
            };
        }
        finish_write(&req, &statuses)
    }

    /// The pre-existing Write path: the AR machine stores the parameter records and
    /// answers; I&M1-3 records are additionally applied to the I&M store.
    fn handle_write_standard(&mut self, req: WriteReq, now: Instant) -> Vec<Action> {
        // Kept so the I&M1-3 records can be inspected below: `Event::WriteReq`
        // consumes `req`, but only the AR machine gets to decide whether the Write is
        // accepted at all (foreign ar_uuid, wrong state, record cap).
        let records = req.records.clone();
        let actions = self.ar.on(Event::WriteReq(req), now);
        let accepted = actions
            .iter()
            .any(|a| matches!(a, Action::Respond { status, .. } if status.is_ok()));
        if accepted {
            for r in &records {
                if (INDEX_IM1..=INDEX_IM3).contains(&r.index) {
                    let status = write_im_record(r, &self.model, &mut self.im);
                    if !status.is_ok() {
                        log::warn!(
                            "I&M write rejected: index {:#06x} slot {} \
                             subslot {} status {:#010x}",
                            r.index,
                            r.slot,
                            r.subslot,
                            status.to_u32()
                        );
                    }
                }
            }
        }
        actions
    }

    /// Serve a Read or ReadImplicit request: `check_ar` gates the AR-uuid check
    /// (`Read` requires it to match the established AR; `ReadImplicit` skips it).
    /// Standard records (I&M) are answered first; any other index goes to the
    /// application's read handler, if one is registered.
    fn handle_read(&mut self, req: &ReadReq, check_ar: bool, rctx: &RespondCtx) -> Vec<Action> {
        if check_ar {
            let matches_ar = match self.ar.context() {
                Some(ctx) => ctx.params.ar_uuid == req.ar_uuid,
                None => false,
            };
            if !matches_ar {
                return respond(PnioStatus::read_wrong_ar());
            }
        }
        let standard = {
            let ctx = RecordCtx {
                model: &self.model,
                im0: &self.im0,
                im: &self.im,
            };
            read_record(req, &ctx)
        };
        if let Some(data) = standard {
            return respond_ok(build_read_res(req, &data));
        }
        let Some(entry) = self.registry.read_entry(req.index) else {
            return respond(PnioStatus::read_index_unsupported());
        };
        if self.model.find(req.slot, req.subslot).is_none() {
            return respond(RecordError::InvalidSlotSubslot.status(Direction::Read));
        }
        let rr = RecordRequest {
            api: req.api,
            slot: req.slot,
            subslot: req.subslot,
            index: req.index,
            len: req.record_data_length,
        };
        match entry.exec {
            RecordExec::Inline => match call_read(&*entry.f, &rr) {
                Ok(data) => finish_read(req, &data, rctx.args_max),
                Err(e) => respond(e.status(Direction::Read)),
            },
            RecordExec::Worker => {
                if self.pending.len() >= MAX_PENDING_JOBS {
                    return respond(RecordError::Busy.status(Direction::Read));
                }
                let id = self.next_job_id();
                self.jobs_out.push(RecordJob::read(id, rr, entry.f));
                self.pending.push(Pending {
                    id,
                    key: (rctx.activity, rctx.seq_num),
                    ctx: rctx.clone(),
                    ar_uuid: self.ar.context().map(|c| c.params.ar_uuid),
                    kind: PendingKind::Read(req.clone()),
                });
                Vec::new()
            }
        }
    }

    fn next_job_id(&mut self) -> u64 {
        let id = self.next_job;
        self.next_job += 1;
        id
    }

    fn cache_lookup(&self, key: &(Uuid, u32)) -> Option<Cached> {
        self.cache
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, c)| c.clone())
    }

    fn cache_insert(&mut self, key: (Uuid, u32), cached: Cached) {
        if self.cache.len() >= CACHE_CAPACITY {
            self.cache.pop_front();
        }
        self.cache.push_back((key, cached));
    }

    /// Answers a retransmitted request from the cache: one cached PDU is resent as is,
    /// a fragmented response restarts from its first fragment. `false` if `key` is not
    /// cached.
    fn resend_cached(
        &mut self,
        key: &(Uuid, u32),
        to: SocketAddr,
        now: Instant,
        output: &mut CmOutput,
    ) -> bool {
        match self.cache_lookup(key) {
            Some(Cached::One(bytes)) => {
                log::debug!(
                    "cache hit for activity {} seq_num {}: resending cached response",
                    key.0,
                    key.1
                );
                output.send.push(Outgoing { bytes, to });
                true
            }
            Some(Cached::Frags(frags)) => {
                log::debug!(
                    "cache hit for activity {} seq_num {}: resending fragmented response",
                    key.0,
                    key.1
                );
                self.start_tx(*key, to, frags, now, output);
                true
            }
            None => false,
        }
    }

    /// One fragment of a fragmented request. Fragments are collected, acknowledged
    /// (unless the sender asked for no `fack`), and once the last one and every fragment
    /// before it are in, the reassembled stub is handled as one call.
    fn on_request_fragment(
        &mut self,
        h: RpcHeader,
        body: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<CmOutput, RpcError> {
        let mut output = CmOutput::default();
        if h.interface != PNIO_DEVICE_INTERFACE {
            return Err(RpcError::BadInterface(h.interface));
        }
        let key = (h.activity, h.seq_num);
        if self.resend_cached(&key, from, now, &mut output)
            || self.pending.iter().any(|p| p.key == key)
        {
            return Ok(output);
        }
        if !matches!(&self.rx, Some(r) if r.key == key) {
            self.rx = Some(Reasm {
                key,
                dead: false,
                first: None,
                parts: BTreeMap::new(),
                bytes: 0,
                last: None,
                touched: now,
            });
        }
        let r = self.rx.as_mut().expect("set above");
        if r.dead {
            return Ok(output);
        }
        r.touched = now;
        if !r.parts.contains_key(&h.frag_num) {
            if r.parts.len() >= MAX_FRAGMENTS || r.bytes + body.len() > MAX_STUB {
                log::warn!("fragmented request {key:?} exceeds the stub limit; dropping it");
                r.dead = true;
                r.parts.clear();
                r.bytes = 0;
                return Ok(output);
            }
            r.bytes += body.len();
            r.parts.insert(h.frag_num, body.to_vec());
        }
        if h.frag_num == 0 {
            r.first = Some(h.clone());
        }
        if h.flags1 & FLAG1_LAST_FRAG != 0 {
            r.last = Some(h.frag_num);
        }
        let mut contiguous: Option<u16> = None;
        let mut n = 0u16;
        while r.parts.contains_key(&n) {
            contiguous = Some(n);
            n += 1;
        }
        let complete = matches!((r.last, contiguous), (Some(l), Some(c)) if c >= l);
        if !complete {
            if h.flags1 & FLAG1_NO_FACK == 0 {
                if let Some(c) = contiguous {
                    output.send.push(Outgoing {
                        bytes: frag::build_fack(&h, c, FRAG_WINDOW as u16),
                        to: from,
                    });
                }
            }
            return Ok(output);
        }

        let r = self.rx.take().expect("set above");
        let last = r.last.expect("complete implies last");
        let mut first = r.first.expect("complete implies fragment 0");
        let mut stub = Vec::with_capacity(r.bytes);
        for (n, part) in r.parts {
            if n <= last {
                stub.extend_from_slice(&part);
            }
        }
        first.flags1 &= !(FLAG1_FRAG | FLAG1_LAST_FRAG);
        first.frag_num = 0;
        first.frag_len = 0;
        self.handle_pdu(first, &stub, from, now)
    }

    /// A `fack` from the controller for the response we are fragmenting: it acknowledges
    /// fragments up to its `frag_num`, which opens the window for the next ones.
    fn on_fack(&mut self, h: &RpcHeader, from: SocketAddr, now: Instant) -> CmOutput {
        let mut output = CmOutput::default();
        let Some(tx) = self.tx.as_mut() else {
            log::debug!("fack with no fragmented response in flight; ignoring");
            return output;
        };
        if tx.key != (h.activity, h.seq_num) || tx.to.ip() != from.ip() {
            log::debug!("fack for another call; ignoring");
            return output;
        }
        let through = usize::from(frag::fack_acked_through(h)) + 1;
        tx.acked = tx.acked.max(through.min(tx.frags.len()));
        tx.retries = 0;
        self.pump_tx(now, &mut output);
        output
    }

    /// Starts sending the fragmented response `frags` to `to`.
    fn start_tx(
        &mut self,
        key: (Uuid, u32),
        to: SocketAddr,
        frags: Vec<Vec<u8>>,
        now: Instant,
        output: &mut CmOutput,
    ) {
        self.tx = Some(TxFrag {
            key,
            to,
            frags,
            next: 0,
            acked: 0,
            sent_at: now,
            retries: 0,
        });
        self.pump_tx(now, output);
    }

    /// Sends fragments while the window allows; once the last one is out the transfer is
    /// over (the full response stays cached, so a retried request restarts it).
    fn pump_tx(&mut self, now: Instant, output: &mut CmOutput) {
        let Some(tx) = self.tx.as_mut() else { return };
        let limit = (tx.acked + FRAG_WINDOW).min(tx.frags.len());
        while tx.next < limit {
            output.send.push(Outgoing {
                bytes: tx.frags[tx.next].clone(),
                to: tx.to,
            });
            tx.next += 1;
            tx.sent_at = now;
        }
        if tx.next >= tx.frags.len() {
            self.tx = None;
        }
    }

    /// Timers of the fragmentation layer: resend the first unacknowledged fragment of a
    /// stalled response, and forget a request whose fragments stopped arriving.
    fn tick_fragments(&mut self, now: Instant, output: &mut CmOutput) {
        if let Some(tx) = self.tx.as_mut() {
            if now >= tx.sent_at + FRAG_STALL {
                if tx.retries >= FRAG_MAX_RETRIES {
                    log::warn!(
                        "fragmented response {:?} was never acknowledged; giving up",
                        tx.key
                    );
                    self.tx = None;
                } else {
                    tx.retries += 1;
                    tx.sent_at = now;
                    output.send.push(Outgoing {
                        bytes: tx.frags[tx.acked].clone(),
                        to: tx.to,
                    });
                }
            }
        }
        if matches!(&self.rx, Some(r) if now >= r.touched + RX_TIMEOUT) {
            log::warn!("incomplete fragmented request timed out; dropping it");
            self.rx = None;
        }
    }
}

/// Answers a record read: the `IODReadRes` block followed by `data`, unless the whole
/// response would not fit the controller's `args_max` buffer.
fn finish_read(req: &ReadReq, data: &[u8], args_max: u32) -> Vec<Action> {
    let stub = NdrResponse::LEN + 64 + data.len();
    if args_max != 0 && stub > args_max as usize {
        return respond(RecordError::InvalidRange.status(Direction::Read));
    }
    respond_ok(build_read_res(req, data))
}

/// Answers a Write whose records carry `statuses`. A request with a single record
/// reports its failure as the call's own status, as a Read does; with several records
/// (a `MultipleWrite`) every record carries its own status inside an OK call.
fn finish_write(req: &WriteReq, statuses: &[PnioStatus]) -> Vec<Action> {
    if req.records.len() == 1 && !statuses[0].is_ok() {
        return respond(statuses[0]);
    }
    respond_ok(build_write_res_with(req, statuses))
}

/// Build the Response PDU(s) for a request's [`Action::Respond`]: an OK status echoes the
/// blocks, any other status answers with no blocks (the NDR header still carries the
/// request's `args_max` in `max_count`, matching p-net's convention). A response whose
/// stub exceeds [`FRAG_BODY_MAX`] is split into DCE-RPC fragments.
fn build_response_pdus(ctx: &RespondCtx, status: PnioStatus, blocks: Vec<u8>) -> Vec<Vec<u8>> {
    let out_blocks = if status.is_ok() { blocks } else { Vec::new() };
    let stub_len = NdrResponse::LEN + out_blocks.len();
    let header = RpcHeader {
        ptype: PacketType::Response,
        flags1: FLAG1_IDEMPOTENT | FLAG1_NO_FACK,
        flags2: 0,
        drep: Drep::BIG,
        serial_hi: 0,
        object: ctx.object,
        interface: ctx.interface,
        activity: ctx.activity,
        server_boot: 0,
        if_version: 1,
        seq_num: ctx.seq_num,
        opnum: ctx.opnum,
        ihint: 0xffff,
        ahint: 0xffff,
        frag_len: stub_len.min(usize::from(u16::MAX)) as u16,
        frag_num: 0,
        auth_proto: 0,
        serial_lo: 0,
    };
    let ndr = if status.is_ok() {
        NdrResponse::ok(ctx.args_max, out_blocks.len() as u32)
    } else {
        NdrResponse::error(status.to_u32(), ctx.args_max)
    };
    if stub_len <= FRAG_BODY_MAX {
        let mut pdu = Vec::with_capacity(RpcHeader::LEN + stub_len);
        header.write(&mut pdu);
        ndr.write(&mut pdu, Drep::BIG);
        pdu.extend_from_slice(&out_blocks);
        return vec![pdu];
    }
    let mut stub = Vec::with_capacity(stub_len);
    ndr.write(&mut stub, Drep::BIG);
    stub.extend_from_slice(&out_blocks);
    frag::fragment(&header, &stub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cm::model::DeviceModel;
    use crate::eth::MacAddr;
    use crate::im::SwRevision;
    use crate::rpc::Uuid;
    use crate::testutil::{golden, golden_alarm, RPC_OFF};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    /// Replace every 16-byte window of `bytes` matching `old`'s wire encoding
    /// (PNIO blocks are always big-endian, regardless of the surrounding RPC
    /// `drep`) with `new`'s.
    fn retag_ar_uuid(mut bytes: Vec<u8>, old: Uuid, new: Uuid) -> Vec<u8> {
        let mut old_b = Vec::new();
        old.write(&mut old_b, Drep::BIG);
        let mut new_b = Vec::new();
        new.write(&mut new_b, Drep::BIG);
        let mut i = 0;
        while i + 16 <= bytes.len() {
            if bytes[i..i + 16] == old_b[..] {
                bytes[i..i + 16].copy_from_slice(&new_b);
            }
            i += 1;
        }
        bytes
    }

    const MAC: MacAddr = MacAddr([0x8c, 0xf3, 0x19, 0xcd, 0x19, 0xf8]);
    fn cpu() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 2, 100)), 54766)
    }
    fn cpu_cm() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 2, 100)), 34964)
    }
    fn cm() -> Cm {
        Cm::new(
            DeviceModel::pnet_sample(MAC),
            Uuid::parse_str("14af198a-1234-1056-8079-8cf319cd19f8").unwrap(),
        )
    }
    fn pdu(name: &str) -> Vec<u8> {
        golden(name)[RPC_OFF..].to_vec()
    }

    #[test]
    fn full_exchange_is_byte_exact_including_rpc_headers() {
        let mut cm = cm();
        let now = Instant::now();
        let o = cm.handle_datagram(&pdu("connect_req"), cpu(), now).unwrap();
        assert_eq!(o.send.len(), 1);
        assert_eq!(o.send[0].bytes, pdu("connect_res"));
        assert_eq!(o.send[0].to, cpu());
        assert_eq!(o.notify, vec![(ArState::Connected, None)]);
        let o = cm.handle_datagram(&pdu("write_req"), cpu(), now).unwrap();
        assert_eq!(o.send[0].bytes, pdu("write_res"));
        let o = cm.handle_datagram(&pdu("prmend_req"), cpu(), now).unwrap();
        assert_eq!(o.send[0].bytes, pdu("prmend_res"));
        assert_eq!(o.send[1].bytes, pdu("appready_req"));
        assert_eq!(o.send[1].to, cpu_cm());
        assert_eq!(cm.state(), ArState::AppReadySent);
        let o = cm
            .handle_datagram(&pdu("appready_res"), cpu_cm(), now)
            .unwrap();
        assert!(o.send.is_empty());
        assert_eq!(o.notify, vec![(ArState::Data, None)]);
        assert_eq!(cm.state(), ArState::Data);
    }

    #[test]
    fn retransmitted_request_gets_cached_response() {
        let mut cm = cm();
        let now = Instant::now();
        let first = cm.handle_datagram(&pdu("connect_req"), cpu(), now).unwrap();
        let again = cm.handle_datagram(&pdu("connect_req"), cpu(), now).unwrap();
        assert_eq!(again.send[0].bytes, first.send[0].bytes);
        assert!(again.notify.is_empty());
    }

    #[test]
    fn stray_connect_does_not_redirect_app_ready() {
        let mut cm = cm();
        let now = Instant::now();
        let o = cm.handle_datagram(&pdu("connect_req"), cpu(), now).unwrap();
        assert_eq!(o.notify, vec![(ArState::Connected, None)]);

        // Same Connect request bytes, but from a different host, with a different AR
        // UUID, initiator object UUID, and seq_num (so it's a distinct RPC call, not
        // a cached-response retransmit, and not a same-initiator reconnect either):
        // the AR is already `Connected`, so this must be refused without touching
        // `controller_addr`.
        let mut stray = pdu("connect_req");
        stray[64] = 1; // seq_num (LE low byte): 0 -> 1
        stray[108..124].copy_from_slice(&[0x11; 16]); // ARBlockReq.ARUUID
        stray[132..148].copy_from_slice(&[0x22; 16]); // ARBlockReq.InitiatorObjectUUID
        let stray_from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 2, 77)), 40000);
        let o = cm.handle_datagram(&stray, stray_from, now).unwrap();
        let (n, _) =
            crate::rpc::NdrResponse::parse(&o.send[0].bytes[80..], crate::rpc::Drep::BIG).unwrap();
        assert_eq!(
            PnioStatus(n.status),
            PnioStatus::connect_ar_already_exists()
        );
        assert_eq!(cm.state(), ArState::Connected);

        // The real AR's ApplicationReady call (via PrmEnd) must still go to the real
        // controller, not to the stray host.
        let o = cm.handle_datagram(&pdu("prmend_req"), cpu(), now).unwrap();
        assert_eq!(o.send[1].bytes, pdu("appready_req"));
        assert_eq!(o.send[1].to, cpu_cm());
    }

    #[test]
    fn unsupported_opnum_gets_error_status_response() {
        let mut cm = cm();
        let mut read = pdu("prmend_req");
        read[68] = 2; // opnum Read (LE low byte)
        let o = cm.handle_datagram(&read, cpu(), Instant::now()).unwrap();
        let h = crate::rpc::RpcHeader::parse(&o.send[0].bytes).unwrap();
        assert_eq!(h.ptype, crate::rpc::PacketType::Response);
        assert_eq!(h.opnum, 2);
        let (n, blocks) =
            crate::rpc::NdrResponse::parse(&o.send[0].bytes[80..], crate::rpc::Drep::BIG).unwrap();
        assert_eq!(PnioStatus(n.status), PnioStatus::read_index_unsupported());
        assert!(blocks.is_empty());
    }

    #[test]
    fn unknown_opnum_gets_service_unsupported_status() {
        let mut cm = cm();
        let mut bad = pdu("prmend_req");
        bad[68] = 99; // opnum unmapped by Opnum::from_u16 (LE low byte)
        let o = cm.handle_datagram(&bad, cpu(), Instant::now()).unwrap();
        let (n, blocks) =
            crate::rpc::NdrResponse::parse(&o.send[0].bytes[80..], crate::rpc::Drep::BIG).unwrap();
        assert_eq!(PnioStatus(n.status), PnioStatus::service_unsupported());
        assert!(blocks.is_empty());
    }

    #[test]
    fn rejected_connect_has_error_status_and_no_blocks() {
        let mut cm = Cm::new(
            {
                let mut m = DeviceModel::pnet_sample(MAC);
                m.slots.pop();
                m
            },
            Uuid::NIL,
        );
        let o = cm
            .handle_datagram(&pdu("connect_req"), cpu(), Instant::now())
            .unwrap();
        let (n, blocks) =
            crate::rpc::NdrResponse::parse(&o.send[0].bytes[80..], crate::rpc::Drep::BIG).unwrap();
        assert_eq!(
            PnioStatus(n.status),
            PnioStatus::connect_reject(ConnectBlock::ExpectedSubmodule, 7)
        );
        assert!(blocks.is_empty());
        assert_eq!(cm.state(), ArState::Idle);
    }

    #[test]
    fn wrong_interface_and_garbage_are_errors_not_panics() {
        let mut cm = cm();
        let mut bad = pdu("connect_req");
        bad[24] = 0xff;
        assert!(matches!(
            cm.handle_datagram(&bad, cpu(), Instant::now()),
            Err(RpcError::BadInterface(_))
        ));
        assert!(matches!(
            cm.handle_datagram(&[1, 2, 3], cpu(), Instant::now()),
            Err(RpcError::TooShort { .. })
        ));
    }

    #[test]
    fn reconnect_updates_controller_addr() {
        let mut cm = cm();
        let now = Instant::now();
        let o = cm.handle_datagram(&pdu("connect_req"), cpu(), now).unwrap();
        assert_eq!(o.notify, vec![(ArState::Connected, None)]);
        cm.handle_datagram(&pdu("write_req"), cpu(), now).unwrap();
        cm.handle_datagram(&pdu("prmend_req"), cpu(), now).unwrap();
        let o = cm
            .handle_datagram(&pdu("appready_res"), cpu_cm(), now)
            .unwrap();
        assert_eq!(o.notify, vec![(ArState::Data, None)]);
        assert_eq!(cm.state(), ArState::Data);

        // Same AR (ARUUID unchanged), new SessionKey, from a new source port and a
        // fresh RPC call (new seq_num — the bench also gets a new activity UUID;
        // seq_num alone is enough here to not collide with the cached responses of
        // the exchange above, which used 0/1/2 on this same activity) — as the CPU
        // does on the bench after it aborts and re-Identifies. ARBlockReq starts at
        // PDU offset 108 (ARUUID, 16 bytes), so SessionKey is at [124..126].
        let mut reconnect = pdu("connect_req");
        reconnect[64] = 3; // seq_num (LE low byte): 0 -> 3, a new RPC call
        reconnect[124..126].copy_from_slice(&5u16.to_be_bytes());
        let reconnect_from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 2, 100)), 54800);
        let o = cm.handle_datagram(&reconnect, reconnect_from, now).unwrap();
        assert_eq!(
            o.notify,
            vec![
                (ArState::Idle, Some(AbortReason::ControllerReconnect)),
                (ArState::Connected, None),
            ]
        );
        assert_eq!(o.send.len(), 1);
        let (n, _) =
            crate::rpc::NdrResponse::parse(&o.send[0].bytes[80..], crate::rpc::Drep::BIG).unwrap();
        assert!(PnioStatus(n.status).is_ok());

        // A PrmEnd on the reconnected AR (again a fresh RPC call, not a retransmit of
        // the first one already cached above) must place the ApplicationReady call
        // to the controller address captured by the takeover. The reconnect's source
        // IP matches the original controller's, so the address itself is unchanged
        // here — but this exercises the takeover code path (not the stale
        // `was_idle` guard it replaces) that sets `controller_addr`.
        let mut prmend = pdu("prmend_req");
        prmend[64] = 4; // seq_num (LE low byte): 2 -> 4, a new RPC call
                        // A real controller's PrmEnd carries the SessionKey it just negotiated (5),
                        // not the golden capture's original one (2); SessionKey is at the same
                        // [124..126] offset as in ARBlockReq (see the reconnect above).
        prmend[124..126].copy_from_slice(&5u16.to_be_bytes());
        let o = cm.handle_datagram(&prmend, cpu(), now).unwrap();
        assert_eq!(o.send[1].to, cpu_cm());
        // `call_seq` is scoped to the device's fixed `activity_seed`, not to the AR,
        // so it must keep counting up across the reconnect rather than restarting at
        // 0 (which would resend the RPC-CL pair `(activity_seed, 0)` the controller
        // already completed for the first AR). The call is therefore identical to
        // the golden ApplicationReady request everywhere except `seq_num` (bytes
        // [64..68], big-endian on our own outgoing calls, which is 1, not 0) and
        // SessionKey (bytes [124..126]): the ApplicationReady call is built from the
        // AR's own context — the reconnected session (5) — not from the PrmEnd
        // request that triggered it.
        let mut expected = pdu("appready_req");
        expected[124..126].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(o.send[1].bytes[..64], expected[..64]);
        assert_eq!(o.send[1].bytes[68..124], expected[68..124]);
        assert_eq!(o.send[1].bytes[126..], expected[126..]);
        assert_eq!(
            u32::from_be_bytes(o.send[1].bytes[64..68].try_into().unwrap()),
            1
        );
    }

    #[test]
    fn tick_resends_app_ready_to_controller() {
        let mut cm = cm();
        let now = Instant::now();
        cm.handle_datagram(&pdu("connect_req"), cpu(), now).unwrap();
        cm.handle_datagram(&pdu("prmend_req"), cpu(), now).unwrap();
        let o =
            cm.tick(now + crate::cm::ar::APP_READY_TIMEOUT + std::time::Duration::from_millis(1));
        assert_eq!(o.send[0].bytes, pdu("appready_req"));
        assert_eq!(o.send[0].to, cpu_cm());
    }

    // -----------------------------------------------------------------------
    // Read/ReadImplicit (I&M), against the separate p-net alarm/I&M capture
    // (`docs/alarm-golden-frames.md`, captured 2026-08-30 — a different session
    // than the cm-golden capture above, hence its own `ar_uuid`).
    // -----------------------------------------------------------------------

    fn pnet_im0() -> Im0 {
        Im0 {
            order_id: "12345 Abcdefghijk".into(),
            serial_number: "007".into(),
            hardware_revision: 3,
            software_revision: SwRevision {
                prefix: 'V',
                functional: 0,
                bug_fix: 2,
                internal: 0,
            },
            revision_counter: 0,
            profile_id: 0x1234,
            profile_specific_type: 0x5678,
        }
    }

    /// Brings an AR up to `Data` and re-tags it with the alarm capture's `ar_uuid`.
    ///
    /// The AR established from the cm-golden capture carries `ar_uuid` e5e1aecc-...;
    /// the alarm capture's Read requests carry ef796d60-... (a different p-net
    /// session). Re-tagging the request PDUs aligns the two so the Read is answered
    /// rather than refused as foreign. Only the PNIO blocks' own `ar_uuid` fields
    /// (ARBlockReq, each Write record, PrmEnd's ControlBlock) carry this value — the
    /// RPC header's object/interface/activity UUIDs are unrelated and untouched, and
    /// `appready_res` carries no `ar_uuid` at all.
    fn cm_in_data_with_the_alarm_capture_ar(now: Instant) -> Cm {
        let mut cm = cm();
        let old = Uuid::parse_str("e5e1aecc-b133-4b4d-b187-cc68b0211ed2").unwrap();
        let new = Uuid::parse_str("ef796d60-ef2b-9946-b39e-8531f5b7f966").unwrap();
        let retag = |name: &str| retag_ar_uuid(pdu(name), old, new);

        cm.handle_datagram(&retag("connect_req"), cpu(), now)
            .unwrap();
        cm.handle_datagram(&retag("write_req"), cpu(), now).unwrap();
        let o = cm
            .handle_datagram(&retag("prmend_req"), cpu(), now)
            .unwrap();
        assert_eq!(o.send[1].to, cpu_cm());
        let o = cm
            .handle_datagram(&pdu("appready_res"), cpu_cm(), now)
            .unwrap();
        assert_eq!(o.notify, vec![(ArState::Data, None)]);
        assert_eq!(cm.state(), ArState::Data);
        cm.set_im(pnet_im0(), crate::im::ImStore::new());
        cm
    }

    #[test]
    fn read_response_matches_the_pnet_im0_golden_byte_exact() {
        let now = Instant::now();
        let mut cm = cm_in_data_with_the_alarm_capture_ar(now);
        let o = cm
            .handle_datagram(&golden_alarm("im0_read_req")[RPC_OFF..], cpu(), now)
            .unwrap();
        assert_eq!(o.send.len(), 1);
        assert_eq!(o.send[0].bytes, golden_alarm("im0_read_res")[RPC_OFF..]);
        assert_eq!(o.send[0].to, cpu());
    }

    /// The capture reads I&M0 on the interface submodule (slot 0, subslot 0x8000)
    /// too, and p-net answers it with the very same record — `IM_Supported = 0x000E`
    /// included, not a zeroed mask.
    #[test]
    fn read_response_on_the_interface_submodule_matches_the_golden_byte_exact() {
        let now = Instant::now();
        let mut cm = cm_in_data_with_the_alarm_capture_ar(now);
        let o = cm
            .handle_datagram(&golden_alarm("im0_read_req_if")[RPC_OFF..], cpu(), now)
            .unwrap();
        assert_eq!(o.send.len(), 1);
        assert_eq!(o.send[0].bytes, golden_alarm("im0_read_res_if")[RPC_OFF..]);
        assert_eq!(o.send[0].to, cpu());
    }

    #[test]
    fn read_with_a_foreign_ar_uuid_is_refused() {
        let mut cm = cm();
        let now = Instant::now();
        cm.handle_datagram(&pdu("connect_req"), cpu(), now).unwrap();
        cm.handle_datagram(&pdu("write_req"), cpu(), now).unwrap();
        cm.handle_datagram(&pdu("prmend_req"), cpu(), now).unwrap();
        cm.handle_datagram(&pdu("appready_res"), cpu_cm(), now)
            .unwrap();
        assert_eq!(cm.state(), ArState::Data);

        // Unpatched: the alarm capture's `ar_uuid` (ef796d60-...) is genuinely
        // foreign to the AR just established (e5e1aecc-...).
        let o = cm
            .handle_datagram(&golden_alarm("im0_read_req")[RPC_OFF..], cpu(), now)
            .unwrap();
        let (n, blocks) =
            crate::rpc::NdrResponse::parse(&o.send[0].bytes[80..], crate::rpc::Drep::BIG).unwrap();
        assert_eq!(PnioStatus(n.status), PnioStatus::read_wrong_ar());
        assert!(blocks.is_empty());
    }

    #[test]
    fn read_implicit_answers_ok_from_idle_without_an_ar() {
        let mut cm = cm();
        assert_eq!(cm.state(), ArState::Idle);
        let mut req = golden_alarm("im0_read_req")[RPC_OFF..].to_vec();
        req[68] = 5; // opnum: Read (2) -> ReadImplicit (5), LE low byte
        let o = cm.handle_datagram(&req, cpu(), Instant::now()).unwrap();
        assert_eq!(o.send.len(), 1);
        let h = crate::rpc::RpcHeader::parse(&o.send[0].bytes).unwrap();
        assert_eq!(h.opnum, 5);
        let (n, blocks) =
            crate::rpc::NdrResponse::parse(&o.send[0].bytes[80..], crate::rpc::Drep::BIG).unwrap();
        assert!(PnioStatus(n.status).is_ok());
        assert!(!blocks.is_empty());
        assert_eq!(cm.state(), ArState::Idle);
    }

    // -----------------------------------------------------------------------
    // Application record handlers (RDREC / WRREC) and DCE-RPC fragmentation.
    // Synthetic requests: there is no capture of these flows yet, so these tests
    // pin the behaviour we intend, not bytes seen on a wire.
    // -----------------------------------------------------------------------

    use crate::cm::handlers::{RecordError, RecordExec};
    use crate::rpc::frag::{self, FRAG_BODY_MAX, MAX_STUB};
    use crate::rpc::{NdrRequest, PacketType, RpcHeader, FLAG1_FRAG, FLAG1_LAST_FRAG};

    const AR: &str = "ef796d60-ef2b-9946-b39e-8531f5b7f966";
    const SLOT: u16 = 0;
    const SUBSLOT: u16 = 1;

    fn data_cm() -> Cm {
        cm_in_data_with_the_alarm_capture_ar(Instant::now())
    }

    fn ar_uuid() -> Uuid {
        Uuid::parse_str(AR).unwrap()
    }

    /// A request header to call `opnum` as activity `act`, call number `seq`.
    fn req_header(opnum: u16, act: u8, seq: u32) -> RpcHeader {
        let mut h = RpcHeader::parse(&golden_alarm("im0_read_req")[RPC_OFF..]).unwrap();
        h.opnum = opnum;
        h.seq_num = seq;
        h.activity = Uuid([act; 16]);
        h.flags1 = crate::rpc::FLAG1_IDEMPOTENT;
        h
    }

    fn read_block(ar: Uuid, slot: u16, subslot: u16, index: u16, len: u32) -> Vec<u8> {
        let mut b = Vec::new();
        BlockHeader::write(&mut b, ty::IOD_READ_REQ_HEADER, 58);
        b.extend_from_slice(&1u16.to_be_bytes()); // seq
        ar.write(&mut b, Drep::BIG);
        b.extend_from_slice(&0u32.to_be_bytes()); // api
        b.extend_from_slice(&slot.to_be_bytes());
        b.extend_from_slice(&subslot.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&index.to_be_bytes());
        b.extend_from_slice(&len.to_be_bytes());
        b.extend_from_slice(&[0u8; 16]); // target ar uuid
        b.extend_from_slice(&[0u8; 8]);
        b
    }

    fn write_record_block(ar: Uuid, slot: u16, subslot: u16, index: u16, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        BlockHeader::write(&mut b, ty::IOD_WRITE_REQ_HEADER, 58);
        b.extend_from_slice(&1u16.to_be_bytes());
        ar.write(&mut b, Drep::BIG);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&slot.to_be_bytes());
        b.extend_from_slice(&subslot.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&index.to_be_bytes());
        b.extend_from_slice(&(data.len() as u32).to_be_bytes());
        b.extend_from_slice(&[0u8; 24]);
        b.extend_from_slice(data);
        b
    }

    fn stub_of(h: &RpcHeader, args_max: u32, blocks: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        NdrRequest::for_blocks(args_max, blocks.len() as u32).write(&mut s, h.drep);
        s.extend_from_slice(blocks);
        s
    }

    fn datagram(h: &RpcHeader, args_max: u32, blocks: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        h.write(&mut d);
        d.extend_from_slice(&stub_of(h, args_max, blocks));
        d
    }

    /// The call's fragments, as the controller would send them.
    fn request_fragments(h: &RpcHeader, args_max: u32, blocks: &[u8]) -> Vec<Vec<u8>> {
        frag::fragment(h, &stub_of(h, args_max, blocks))
    }

    /// Joins the fragments of a response and parses it.
    fn parse_response(pdus: &[Vec<u8>]) -> (PnioStatus, Vec<u8>) {
        let mut stub = Vec::new();
        for p in pdus {
            stub.extend_from_slice(&p[RpcHeader::LEN..]);
        }
        let (n, blocks) = crate::rpc::NdrResponse::parse(&stub, Drep::BIG).unwrap();
        (PnioStatus(n.status), blocks.to_vec())
    }

    fn sent(o: &CmOutput) -> Vec<Vec<u8>> {
        o.send.iter().map(|s| s.bytes.clone()).collect()
    }

    fn call(cm: &mut Cm, d: &[u8], now: Instant) -> CmOutput {
        cm.handle_datagram(d, cpu(), now).unwrap()
    }

    /// The record data after the 64-byte `IODReadRes` block.
    fn read_data(blocks: &[u8]) -> &[u8] {
        assert_eq!(&blocks[..2], &0x8009u16.to_be_bytes());
        &blocks[64..]
    }

    fn write_status_of(blocks: &[u8], i: usize) -> PnioStatus {
        let o = i * 64 + 44;
        PnioStatus(u32::from_be_bytes(blocks[o..o + 4].try_into().unwrap()))
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn inline_read_handler_answers_the_record() {
        let mut cm = data_cm();
        cm.registry()
            .on_read(0x20, RecordExec::Inline, |r| {
                assert_eq!(
                    (r.slot, r.subslot, r.index, r.len),
                    (SLOT, SUBSLOT, 0x20, 64)
                );
                Ok(vec![1, 2, 3])
            })
            .unwrap();
        let h = req_header(2, 1, 1000);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x20, 64)),
            Instant::now(),
        );
        assert_eq!(o.send.len(), 1);
        let (status, blocks) = parse_response(&sent(&o));
        assert!(status.is_ok());
        assert_eq!(read_data(&blocks), &[1, 2, 3]);
        // the record_data_length of the IODReadRes is the data length
        assert_eq!(&blocks[36..40], &3u32.to_be_bytes());
    }

    #[test]
    fn unregistered_index_is_still_invalid_index() {
        let mut cm = data_cm();
        let h = req_header(2, 1, 1001);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x21, 64)),
            Instant::now(),
        );
        let (status, blocks) = parse_response(&sent(&o));
        assert_eq!(status, PnioStatus::read_index_unsupported());
        assert!(blocks.is_empty());
    }

    #[test]
    fn read_errors_map_to_pniorw_statuses() {
        let mut cm = data_cm();
        cm.registry()
            .on_read(0x22, RecordExec::Inline, |_| {
                Err(RecordError::StateConflict)
            })
            .unwrap();
        cm.registry()
            .on_read(0x23, RecordExec::Inline, |_| Ok(vec![0; 100]))
            .unwrap();
        let now = Instant::now();
        let h = req_header(2, 1, 1002);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x22, 64)),
            now,
        );
        assert_eq!(
            parse_response(&sent(&o)).0,
            RecordError::StateConflict.status(Direction::Read)
        );
        // the record does not fit the buffer the controller offers
        let h = req_header(2, 1, 1003);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x23, 99)),
            now,
        );
        assert_eq!(
            parse_response(&sent(&o)).0,
            RecordError::InvalidRange.status(Direction::Read)
        );
        // unknown slot/subslot
        let h = req_header(2, 1, 1004);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), 9, 9, 0x23, 200)),
            now,
        );
        assert_eq!(
            parse_response(&sent(&o)).0,
            RecordError::InvalidSlotSubslot.status(Direction::Read)
        );
    }

    #[test]
    fn read_with_a_foreign_ar_never_reaches_the_handler() {
        let mut cm = data_cm();
        cm.registry()
            .on_read(0x24, RecordExec::Inline, |_| panic!("must not be called"))
            .unwrap();
        let other = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let h = req_header(2, 1, 1005);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(other, SLOT, SUBSLOT, 0x24, 64)),
            Instant::now(),
        );
        assert_eq!(parse_response(&sent(&o)).0, PnioStatus::read_wrong_ar());
    }

    #[test]
    fn large_read_is_fragmented_and_reassembles_exactly() {
        let mut cm = data_cm();
        let data = pattern(4000);
        let d2 = data.clone();
        cm.registry()
            .on_read(0x30, RecordExec::Inline, move |_| Ok(d2.clone()))
            .unwrap();
        let h = req_header(2, 1, 1010);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x30, 8192)),
            Instant::now(),
        );
        let pdus = sent(&o);
        assert_eq!(
            pdus.len(),
            3,
            "4000 + 84 bytes of headers is 3 fragments, all within the window"
        );
        for (i, p) in pdus.iter().enumerate() {
            let rh = RpcHeader::parse_any(p).unwrap();
            assert_eq!(rh.ptype, PacketType::Response);
            assert_eq!(rh.frag_num as usize, i);
            assert!(rh.flags1 & FLAG1_FRAG != 0);
            assert_eq!(rh.flags1 & FLAG1_LAST_FRAG != 0, i == 2);
            assert!(p.len() <= RpcHeader::LEN + FRAG_BODY_MAX);
        }
        let (status, blocks) = parse_response(&pdus);
        assert!(status.is_ok());
        assert_eq!(read_data(&blocks), &data[..]);
    }

    #[test]
    fn fragmented_response_is_paced_by_facks_and_restarted_by_a_retry() {
        let mut cm = data_cm();
        let data = pattern(20_000);
        let d2 = data.clone();
        cm.registry()
            .on_read(0x31, RecordExec::Inline, move |_| Ok(d2.clone()))
            .unwrap();
        let h = req_header(2, 1, 1011);
        let req = datagram(
            &h,
            65536,
            &read_block(ar_uuid(), SLOT, SUBSLOT, 0x31, 65536),
        );
        let t0 = Instant::now();
        let o = call(&mut cm, &req, t0);
        let mut pdus = sent(&o);
        assert_eq!(pdus.len(), 8, "one window");
        // the controller acknowledges fragments 0..=3: four more may go out
        let ack = frag::build_fack(&h, 3, 8);
        let o = call(&mut cm, &ack, t0);
        assert_eq!(o.send.len(), 4);
        pdus.extend(sent(&o));
        // ... and 0..=11 releases the rest (20000 + headers = 15 fragments)
        let ack = frag::build_fack(&h, 11, 8);
        let o = call(&mut cm, &ack, t0);
        pdus.extend(sent(&o));
        assert_eq!(pdus.len(), 15);
        let (status, blocks) = parse_response(&pdus);
        assert!(status.is_ok());
        assert_eq!(read_data(&blocks), &data[..]);
        // a late fack after completion is harmless
        assert!(call(&mut cm, &frag::build_fack(&h, 14, 8), t0)
            .send
            .is_empty());
        // the controller never saw the end and asks again: the response restarts
        let o = call(&mut cm, &req, t0);
        let again = sent(&o);
        assert_eq!(again.len(), 8);
        assert_eq!(again[0], pdus[0]);
    }

    #[test]
    fn stalled_fragmented_response_resends_the_first_unacknowledged_fragment() {
        let mut cm = data_cm();
        cm.registry()
            .on_read(0x32, RecordExec::Inline, |_| Ok(pattern(30_000)))
            .unwrap();
        let h = req_header(2, 1, 1012);
        let t0 = Instant::now();
        let o = call(
            &mut cm,
            &datagram(
                &h,
                65536,
                &read_block(ar_uuid(), SLOT, SUBSLOT, 0x32, 65536),
            ),
            t0,
        );
        let first = sent(&o);
        assert!(cm.next_deadline().is_some());
        let o = cm.tick(t0 + Duration::from_millis(300));
        assert_eq!(o.send.len(), 1);
        assert_eq!(o.send[0].bytes, first[0]);
        // never acknowledged: after the retry budget the transfer is abandoned
        let mut t = t0 + Duration::from_millis(300);
        for _ in 0..10 {
            t += Duration::from_millis(300);
            cm.tick(t);
        }
        assert!(cm.tick(t + Duration::from_secs(1)).send.is_empty());
    }

    #[test]
    fn inline_write_handler_gets_the_data_and_is_acknowledged() {
        let mut cm = data_cm();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = seen.clone();
        cm.registry()
            .on_write(0x40, RecordExec::Inline, move |r, d| {
                assert_eq!(
                    (r.slot, r.subslot, r.index, r.len),
                    (SLOT, SUBSLOT, 0x40, 5)
                );
                s2.lock().unwrap().extend_from_slice(d);
                Ok(())
            })
            .unwrap();
        let h = req_header(3, 1, 1020);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x40, &[9, 8, 7, 6, 5]);
        let o = call(&mut cm, &datagram(&h, 65536, &blocks), Instant::now());
        let (status, resp) = parse_response(&sent(&o));
        assert!(status.is_ok());
        assert_eq!(resp.len(), 64);
        assert_eq!(&resp[..2], &0x8008u16.to_be_bytes());
        assert_eq!(write_status_of(&resp, 0), PnioStatus::OK);
        assert_eq!(*seen.lock().unwrap(), vec![9, 8, 7, 6, 5]);
    }

    #[test]
    fn failed_single_write_is_the_calls_status() {
        let mut cm = data_cm();
        cm.registry()
            .on_write(0x41, RecordExec::Inline, |_, _| {
                Err(RecordError::WriteLength)
            })
            .unwrap();
        let h = req_header(3, 1, 1021);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x41, &[1]);
        let o = call(&mut cm, &datagram(&h, 65536, &blocks), Instant::now());
        assert_eq!(
            parse_response(&sent(&o)).0,
            RecordError::WriteLength.status(Direction::Write)
        );
    }

    #[test]
    fn multiple_write_reports_each_records_own_status() {
        let mut cm = data_cm();
        cm.registry()
            .on_write(0x42, RecordExec::Inline, |_, d| {
                if d.len() == 4 {
                    Ok(())
                } else {
                    Err(RecordError::WriteLength)
                }
            })
            .unwrap();
        let ok = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x42, &[1, 2, 3, 4]);
        let bad = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x42, &[1, 2, 3]);
        let nowhere = write_record_block(ar_uuid(), 9, 9, 0x42, &[1, 2, 3, 4]);
        let mut inner = Vec::new();
        for rec in [&ok, &bad, &nowhere] {
            inner.extend_from_slice(rec);
            while inner.len() % 4 != 0 {
                inner.push(0);
            }
        }
        let mut outer = Vec::new();
        BlockHeader::write(&mut outer, ty::IOD_WRITE_REQ_HEADER, 58);
        outer.extend_from_slice(&1u16.to_be_bytes());
        ar_uuid().write(&mut outer, Drep::BIG);
        outer.extend_from_slice(&0xffff_ffffu32.to_be_bytes());
        outer.extend_from_slice(&0xffffu16.to_be_bytes());
        outer.extend_from_slice(&0xffffu16.to_be_bytes());
        outer.extend_from_slice(&0u16.to_be_bytes());
        outer.extend_from_slice(&INDEX_MULTIPLE_WRITE.to_be_bytes());
        outer.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        outer.extend_from_slice(&[0u8; 24]);
        outer.extend_from_slice(&inner);

        let h = req_header(3, 1, 1022);
        let o = call(&mut cm, &datagram(&h, 65536, &outer), Instant::now());
        let (status, resp) = parse_response(&sent(&o));
        assert!(
            status.is_ok(),
            "a MultipleWrite is an OK call carrying per-record statuses"
        );
        assert_eq!(resp.len(), 4 * 64);
        assert_eq!(write_status_of(&resp, 0), PnioStatus::OK); // the container
        assert_eq!(write_status_of(&resp, 1), PnioStatus::OK);
        assert_eq!(
            write_status_of(&resp, 2),
            RecordError::WriteLength.status(Direction::Write)
        );
        assert_eq!(
            write_status_of(&resp, 3),
            RecordError::InvalidSlotSubslot.status(Direction::Write)
        );
    }

    #[test]
    fn runtime_writes_do_not_consume_the_ars_record_cap() {
        let mut cm = data_cm();
        cm.registry()
            .on_write(0x43, RecordExec::Inline, |_, _| Ok(()))
            .unwrap();
        let before = cm.context().unwrap().records.len();
        let payload = pattern(1000);
        // 200 x 1000 bytes would blow both the 64-record and the 64 KiB cap if stored
        for seq in 0..200u32 {
            let h = req_header(3, 1, 2000 + seq);
            let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x43, &payload);
            let o = call(&mut cm, &datagram(&h, 65536, &blocks), Instant::now());
            assert!(parse_response(&sent(&o)).0.is_ok(), "write {seq}");
        }
        assert_eq!(cm.context().unwrap().records.len(), before);
        assert_eq!(cm.state(), ArState::Data);
    }

    #[test]
    fn write_with_a_foreign_ar_never_reaches_the_handler() {
        let mut cm = data_cm();
        cm.registry()
            .on_write(0x44, RecordExec::Inline, |_, _| {
                panic!("must not be called")
            })
            .unwrap();
        let other = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let h = req_header(3, 1, 1023);
        let blocks = write_record_block(other, SLOT, SUBSLOT, 0x44, &[1]);
        let o = call(&mut cm, &datagram(&h, 65536, &blocks), Instant::now());
        assert_eq!(parse_response(&sent(&o)).0, PnioStatus::write_wrong_ar());
    }

    #[test]
    fn fragmented_write_is_reassembled_acknowledged_and_handled_once() {
        let mut cm = data_cm();
        let data = pattern(5000);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let s2 = seen.clone();
        cm.registry()
            .on_write(0x45, RecordExec::Inline, move |_, d| {
                s2.lock().unwrap().push(d.to_vec());
                Ok(())
            })
            .unwrap();
        let h = req_header(3, 7, 1030);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x45, &data);
        let frags = request_fragments(&h, 65536, &blocks);
        assert!(frags.len() >= 4);
        let now = Instant::now();
        // every fragment but the last is acknowledged, in order, up to itself
        for (i, f) in frags[..frags.len() - 1].iter().enumerate() {
            let o = call(&mut cm, f, now);
            assert_eq!(o.send.len(), 1, "fragment {i}");
            let fack = RpcHeader::parse_any(&o.send[0].bytes).unwrap();
            assert_eq!(fack.ptype, PacketType::Fack);
            assert_eq!(fack.frag_num as usize, i);
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "nothing handled before the last fragment"
        );
        let o = call(&mut cm, frags.last().unwrap(), now);
        let (status, resp) = parse_response(&sent(&o));
        assert!(status.is_ok());
        assert_eq!(write_status_of(&resp, 0), PnioStatus::OK);
        assert_eq!(*seen.lock().unwrap(), vec![data]);
        // the controller retransmits a fragment of the finished call: the cached
        // response comes back and the handler does not run again
        let o = call(&mut cm, &frags[0], now);
        assert_eq!(parse_response(&sent(&o)).0, PnioStatus::OK);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn fragments_may_arrive_out_of_order_and_duplicated() {
        let mut cm = data_cm();
        let data = pattern(6000);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let s2 = seen.clone();
        cm.registry()
            .on_write(0x46, RecordExec::Inline, move |_, d| {
                s2.lock().unwrap().push(d.to_vec());
                Ok(())
            })
            .unwrap();
        let h = req_header(3, 7, 1031);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x46, &data);
        let frags = request_fragments(&h, 65536, &blocks);
        let n = frags.len();
        let now = Instant::now();
        // the last one first: nothing is acknowledged (fragment 0 is missing) ...
        assert!(call(&mut cm, &frags[n - 1], now).send.is_empty());
        // ... then 1, then a duplicate of 1, then 0: the ack follows the contiguous run
        assert!(call(&mut cm, &frags[1], now).send.is_empty());
        assert!(call(&mut cm, &frags[1], now).send.is_empty());
        let o = call(&mut cm, &frags[0], now);
        let fack = RpcHeader::parse_any(&o.send[0].bytes).unwrap();
        assert_eq!(fack.frag_num, 1);
        for f in &frags[2..n - 1] {
            call(&mut cm, f, now);
        }
        assert_eq!(*seen.lock().unwrap(), vec![data]);
    }

    #[test]
    fn no_fack_flag_suppresses_acknowledgements() {
        let mut cm = data_cm();
        cm.registry()
            .on_write(0x47, RecordExec::Inline, |_, _| Ok(()))
            .unwrap();
        let mut h = req_header(3, 7, 1032);
        h.flags1 |= FLAG1_NO_FACK;
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x47, &pattern(4000));
        let mut frags = request_fragments(&h, 65536, &blocks);
        for f in &mut frags {
            f[2] |= FLAG1_NO_FACK; // fragment() clears it; the sender sets it
        }
        let n = frags.len();
        for f in &frags[..n - 1] {
            assert!(call(&mut cm, f, Instant::now()).send.is_empty());
        }
        assert!(!call(&mut cm, &frags[n - 1], Instant::now()).send.is_empty());
    }

    #[test]
    fn reassembly_is_bounded_and_times_out() {
        let mut cm = data_cm();
        cm.registry()
            .on_write(0x48, RecordExec::Inline, |_, _| Ok(()))
            .unwrap();
        let h = req_header(3, 7, 1033);
        // a stub bigger than MAX_STUB is dropped, not buffered without limit
        let huge = vec![0u8; MAX_STUB * 2];
        let frags = frag::fragment(&h, &huge);
        let now = Instant::now();
        let mut acks = 0;
        for f in &frags[..frags.len() - 1] {
            acks += call(&mut cm, f, now).send.len();
        }
        assert!(
            acks < frags.len() / 2 + 2,
            "acknowledgements stop once the request is dropped"
        );
        assert_eq!(cm.pending_jobs(), 0);
        // an incomplete request is forgotten after the timeout
        let h = req_header(3, 7, 1034);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x48, &pattern(4000));
        let frags = request_fragments(&h, 65536, &blocks);
        call(&mut cm, &frags[0], now);
        assert!(cm.next_deadline().is_some());
        cm.tick(now + Duration::from_secs(6));
        // the fragments after the timeout start a fresh, incomplete reassembly: no response
        let o = call(&mut cm, frags.last().unwrap(), now + Duration::from_secs(6));
        assert!(o.send.iter().all(|s| {
            RpcHeader::parse_any(&s.bytes)
                .map(|h| h.ptype != PacketType::Response)
                .unwrap_or(false)
        }));
    }

    #[test]
    fn worker_read_is_deferred_then_answered_when_the_job_completes() {
        let mut cm = data_cm();
        cm.registry()
            .on_read(0x50, RecordExec::Worker, |_| Ok(pattern(2500)))
            .unwrap();
        let h = req_header(2, 1, 1040);
        let req = datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x50, 4096));
        let now = Instant::now();
        let o = call(&mut cm, &req, now);
        assert!(o.send.is_empty(), "no response until the worker is done");
        assert_eq!(cm.pending_jobs(), 1);
        // the controller's retry while the job runs is swallowed
        assert!(call(&mut cm, &req, now).send.is_empty());
        let jobs = cm.take_jobs();
        assert_eq!(jobs.len(), 1);
        assert!(cm.take_jobs().is_empty());
        let o = cm.complete_job(jobs.into_iter().next().unwrap().run(), now);
        assert_eq!(cm.pending_jobs(), 0);
        let (status, blocks) = parse_response(&sent(&o));
        assert!(status.is_ok());
        assert_eq!(read_data(&blocks), &pattern(2500)[..]);
        // and now a retry is served from the cache
        assert!(!call(&mut cm, &req, now).send.is_empty());
    }

    #[test]
    fn worker_write_carries_per_record_results() {
        let mut cm = data_cm();
        cm.registry()
            .on_write(0x51, RecordExec::Worker, |_, d| {
                if d == [1, 2, 3] {
                    Ok(())
                } else {
                    Err(RecordError::InvalidParameter)
                }
            })
            .unwrap();
        let h = req_header(3, 1, 1041);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x51, &[9]);
        let now = Instant::now();
        assert!(call(&mut cm, &datagram(&h, 65536, &blocks), now)
            .send
            .is_empty());
        let done = cm.take_jobs().into_iter().next().unwrap().run();
        let o = cm.complete_job(done, now);
        assert_eq!(
            parse_response(&sent(&o)).0,
            RecordError::InvalidParameter.status(Direction::Write)
        );
    }

    #[test]
    fn worker_result_for_a_vanished_ar_is_dropped() {
        let mut cm = data_cm();
        cm.registry()
            .on_read(0x52, RecordExec::Worker, |_| Ok(vec![1]))
            .unwrap();
        let h = req_header(2, 1, 1042);
        let now = Instant::now();
        call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x52, 64)),
            now,
        );
        let job = cm.take_jobs().into_iter().next().unwrap();
        cm.abort(AbortReason::ControllerRelease, now);
        assert_eq!(cm.state(), ArState::Idle);
        assert!(cm.complete_job(job.run(), now).send.is_empty());
    }

    #[test]
    fn too_many_outstanding_jobs_are_answered_busy() {
        let mut cm = data_cm();
        cm.registry()
            .on_read(0x53, RecordExec::Worker, |_| Ok(vec![1]))
            .unwrap();
        let now = Instant::now();
        for seq in 0..MAX_PENDING_JOBS as u32 {
            let h = req_header(2, 1, 3000 + seq);
            assert!(call(
                &mut cm,
                &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x53, 64)),
                now
            )
            .send
            .is_empty());
        }
        let h = req_header(2, 1, 3999);
        let o = call(
            &mut cm,
            &datagram(&h, 65536, &read_block(ar_uuid(), SLOT, SUBSLOT, 0x53, 64)),
            now,
        );
        assert_eq!(
            parse_response(&sent(&o)).0,
            RecordError::Busy.status(Direction::Read)
        );
    }

    #[test]
    fn fragmented_response_to_a_fragmented_request_round_trips_a_big_block() {
        // WRREC 6000 bytes then RDREC them back, both fragmented, through one handler pair.
        let mut cm = data_cm();
        let store = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let (w, r) = (store.clone(), store.clone());
        cm.registry()
            .on_write(0x60, RecordExec::Inline, move |_, d| {
                *w.lock().unwrap() = d.to_vec();
                Ok(())
            })
            .unwrap();
        cm.registry()
            .on_read(0x60, RecordExec::Inline, move |_| {
                Ok(r.lock().unwrap().clone())
            })
            .unwrap();
        let data = pattern(6000);
        let now = Instant::now();
        let h = req_header(3, 7, 1050);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x60, &data);
        let mut last = CmOutput::default();
        for f in request_fragments(&h, 65536, &blocks) {
            last = call(&mut cm, &f, now);
        }
        assert!(parse_response(&sent(&last)).0.is_ok());
        let h = req_header(2, 7, 1051);
        let o = call(
            &mut cm,
            &datagram(
                &h,
                65536,
                &read_block(ar_uuid(), SLOT, SUBSLOT, 0x60, 65536),
            ),
            now,
        );
        let (status, blocks) = parse_response(&sent(&o));
        assert!(status.is_ok());
        assert_eq!(read_data(&blocks), &data[..]);
    }

    #[test]
    fn im_records_and_golden_flows_are_untouched_by_an_empty_registry() {
        // the registry is empty here: the golden I&M0 read must still be byte-exact
        let now = Instant::now();
        let mut cm = cm_in_data_with_the_alarm_capture_ar(now);
        let o = cm
            .handle_datagram(&golden_alarm("im0_read_req")[RPC_OFF..], cpu(), now)
            .unwrap();
        assert_eq!(o.send[0].bytes, golden_alarm("im0_read_res")[RPC_OFF..]);
    }

    #[test]
    fn fragmentation_boundaries_are_exact() {
        // A response stub is NDR (20) + IODReadRes (64) + data: it fits one datagram up to
        // exactly FRAG_BODY_MAX, and one byte more takes two.
        let fits = FRAG_BODY_MAX - NdrResponse::LEN - 64;
        for (len, frags) in [(fits - 1, 1), (fits, 1), (fits + 1, 2)] {
            let mut cm = data_cm();
            cm.registry()
                .on_read(0x80, RecordExec::Inline, move |_| Ok(pattern(len)))
                .unwrap();
            let h = req_header(2, 1, 4000 + len as u32);
            let req = datagram(
                &h,
                65536,
                &read_block(ar_uuid(), SLOT, SUBSLOT, 0x80, 65536),
            );
            let o = call(&mut cm, &req, Instant::now());
            assert_eq!(o.send.len(), frags, "response of {len} data bytes");
            let (status, blocks) = parse_response(&sent(&o));
            assert!(status.is_ok());
            assert_eq!(read_data(&blocks), &pattern(len)[..]);
        }
        // The same on the request side: the request stub is NDR (20) + IODWriteReq (64) + data.
        let fits = FRAG_BODY_MAX - NdrRequest::LEN - 64;
        for (len, frags) in [(fits, 1), (fits + 1, 2)] {
            let mut cm = data_cm();
            let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let g2 = got.clone();
            cm.registry()
                .on_write(0x81, RecordExec::Inline, move |_, d| {
                    *g2.lock().unwrap() = d.to_vec();
                    Ok(())
                })
                .unwrap();
            let h = req_header(3, 1, 4100 + len as u32);
            let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x81, &pattern(len));
            let pdus = if frags == 1 {
                vec![datagram(&h, 65536, &blocks)]
            } else {
                request_fragments(&h, 65536, &blocks)
            };
            assert_eq!(pdus.len(), frags, "request of {len} data bytes");
            for p in &pdus {
                call(&mut cm, p, Instant::now());
            }
            assert_eq!(*got.lock().unwrap(), pattern(len), "write of {len} bytes");
        }
    }

    #[test]
    fn a_maximum_size_record_round_trips_in_both_directions() {
        let mut cm = data_cm();
        let store = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let (w, r) = (store.clone(), store.clone());
        cm.registry()
            .on_write(0x82, RecordExec::Inline, move |_, d| {
                *w.lock().unwrap() = d.to_vec();
                Ok(())
            })
            .unwrap();
        cm.registry()
            .on_read(0x82, RecordExec::Inline, move |_| {
                Ok(r.lock().unwrap().clone())
            })
            .unwrap();
        let data = pattern(MAX_RECORD_DATA);
        let now = Instant::now();

        // WRREC of 64 KiB: ~48 fragments, the handler runs once, after the last
        let h = req_header(3, 7, 5000);
        let blocks = write_record_block(ar_uuid(), SLOT, SUBSLOT, 0x82, &data);
        let frags = request_fragments(&h, 65536, &blocks);
        assert!(frags.len() > 40);
        let mut last = CmOutput::default();
        for f in &frags {
            last = call(&mut cm, f, now);
        }
        assert!(parse_response(&sent(&last)).0.is_ok());
        assert_eq!(*store.lock().unwrap(), data);

        // RDREC of the same 64 KiB, the controller acknowledging as it receives
        let h = req_header(2, 7, 5001);
        let mut o = call(
            &mut cm,
            &datagram(
                &h,
                65536 + 1024,
                &read_block(ar_uuid(), SLOT, SUBSLOT, 0x82, 65536),
            ),
            now,
        );
        let mut pdus = sent(&o);
        while !o.send.is_empty() {
            let last = RpcHeader::parse_any(pdus.last().unwrap()).unwrap();
            if last.flags1 & FLAG1_LAST_FRAG != 0 {
                break;
            }
            o = call(&mut cm, &frag::build_fack(&h, last.frag_num, 8), now);
            pdus.extend(sent(&o));
        }
        let nums: Vec<u16> = pdus
            .iter()
            .map(|p| RpcHeader::parse_any(p).unwrap().frag_num)
            .collect();
        assert_eq!(
            nums,
            (0..nums.len() as u16).collect::<Vec<_>>(),
            "in order, none missing"
        );
        let (status, blocks) = parse_response(&pdus);
        assert!(status.is_ok());
        assert_eq!(read_data(&blocks), &data[..]);
    }
}
