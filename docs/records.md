# Application records — `RDREC` / `WRREC`

The cyclic image is for small, fast process data. For anything bigger, or anything that
must arrive whole — a recipe, a calibration table, a log excerpt, a firmware chunk — a
PROFINET controller reads and writes **records** over the acyclic DCE-RPC `Read` / `Write`
services. In an S7 program those are the `RDREC` and `WRREC` blocks; the
`(api, slot, subslot, index)` they address is what this crate calls a record.

`pnio` serves the standard I&M records itself. This page is about the ones **you** define.

## Using it

```rust
use pnio::api::{RecordError, RecordExec};

// WRREC from the controller → your closure, with the whole record.
dev.on_write_record(0x0100, RecordExec::Inline, |req, data| {
    if data.len() < 8 { return Err(RecordError::WriteLength); }
    store(req.slot, data);          // all-or-nothing: called once, with every byte
    Ok(())
})?;

// RDREC from the controller → your closure produces the bytes.
dev.on_read_record(0x0100, RecordExec::Worker, |req| {
    Ok(load_table(req.slot))        // up to 64 KiB; may block (it runs on a worker)
})?;
```

* **Indices** `0x0000..=0x7FFF` are yours. `0x8000..` belongs to the standard and to this
  crate (I&M `0xAFF0..=0xAFF3`, `MultipleWrite` `0xE040`, …); registering one is refused
  with `RegisterError::ReservedIndex`. In `0x0000..=0x7FFF`, `0x7B`–`0x7D` are what the
  bench controller wrote as parameter records during Connect (`docs/cm-golden-frames.md`);
  avoid them unless you mean to take them over.
* **Every slot/subslot** of the device model answers; the request tells you which one it
  was (`req.slot`, `req.subslot`). An unknown slot/subslot is answered "invalid
  slot/subslot" without calling you.
* **Registering is live.** `on_*_record` / `remove_record_handler` may be called at any
  time, from any thread.

### Threading is optional, per handler

| `RecordExec` | Runs on | Use it when |
|---|---|---|
| `Inline` | the acyclic thread, inside the request | the closure is short and never blocks (copy a buffer, flip an atomic) |
| `Worker` | a dedicated `pnio-records` thread | the closure computes, does I/O, takes a lock someone holds for long |

The acyclic thread also serves DCP, alarms and RPC retransmissions, so a slow `Inline`
handler delays all of them. A `Worker` handler does not: the request is parked, the loop
keeps running (it wakes every 2 ms while a job is outstanding), and the response leaves
when the closure returns. A retry of the same call while it runs is ignored; at most 8
requests may be parked at once, the ninth is answered `Busy`. The worker thread is
started on the first such request. **Neither mode touches the cyclic real-time thread.**

A panicking handler is caught and reported as `ModuleFailure`.

## What goes on the wire

| Situation | Controller sees |
|---|---|
| Handler returns `Ok` | the record (`IODReadRes` + data) / OK write |
| Handler returns `Err(e)` | a PNIORW status: `ErrorCode 0xDE` (read) / `0xDF` (write), `ErrorDecode 0x80`, `ErrorCode1` from `e` (see `RecordError`) |
| Index not registered | "invalid index" (`0xB0`) — as before |
| Read record larger than the buffer the controller offered | "invalid range" (`0xB7`) |
| `Read` with a foreign AR UUID, `Write` with a foreign AR UUID | refused, handler not called |
| A single-record write fails | the call's own status is the error (as a read) |
| A `MultipleWrite` | an OK call; each record carries its own status |

### Large records: DCE-RPC fragmentation

A UDP datagram carries at most 1392 bytes of RPC payload (Ethernet 1500 − IPv4 20 − UDP 8
− RPC header 80). Bigger requests and responses are split into numbered fragments of that
size and reassembled; IP never fragments.

* **Requests** (`WRREC`): fragments are collected, each acknowledged with a `fack` (unless
  the sender set `NO_FACK`) up to the highest contiguous one, and the handler runs **once**,
  after the last fragment and all before it arrived. Out-of-order and duplicate fragments
  are fine. A call that exceeds 64 KiB + 4 KiB of stub, or that stops arriving for 5 s,
  is dropped.
* **Responses** (`RDREC`): fragments are sent in a window of 8; each controller `fack`
  opens the window further; if none comes for 250 ms the first unacknowledged fragment is
  resent (6 times at most). The finished response stays cached, so a controller that
  retries the request gets it again from fragment 0 without running the handler twice.

Records are capped at **64 KiB**. Move more than that in chunks (see below).

### Runtime writes do not use up the AR

The AR keeps the parameter records written during start-up (64 records / 64 KiB per AR),
and refuses further writes once that is full. A write handled by one of *your* handlers
bypasses that store entirely, so it can be repeated for as long as the AR lives.

## Moving thousands of bytes safely

The transport gives you ordered, complete records or an error — never half a record. What
it does **not** give you is end-to-end integrity: UDP's checksum is 16 bits, and nothing
verifies that the bytes your program stored are the ones the controller's program meant.
For data that matters:

1. **Frame the payload yourself**: `version | total_len | chunk_no | chunk_count | crc32 |
   data`. Reject (`RecordError::InvalidParameter`) what does not verify; the controller's
   `WRREC` then reports a non-zero status instead of silently "succeeding".
2. **Commit atomically.** Your write handler is called once with the whole record; build the
   new value off to the side and swap it in, rather than updating in place.
3. **Chunk above 64 KiB** with an index per chunk (or a chunk number in your header) and
   one final "commit" write that carries the overall length and CRC.
4. **The controller drives.** A device cannot push a record; to say "new data is ready",
   raise a diagnosis (`raise_diagnosis`) or set a bit in the cyclic image, and let the PLC
   `RDREC` it. Poll `RDREC` only at a rate the handler can sustain.
5. **Keep handlers idempotent.** A retried call is answered from the cache and is not
   re-run, but a controller that times out and starts a *new* call (new sequence number)
   will run your handler again.

## What is verified, and what is not

Everything above is covered by unit and integration tests (`cm::tests`, `device::tests`):
fragmentation in both directions with out-of-order and duplicate fragments, the limits,
per-record statuses, the worker path and its failure modes, and that the golden captures
are still byte-exact.

**But there is no capture of an application `RDREC`/`WRREC`, and none of a fragmented
exchange, from a real controller** — the golden frames this crate is pinned to all fit one
datagram. So the following come from IEC 61158-6-10 / the DCE-RPC connectionless
specification and from Wireshark's dissector, not from observed S7 traffic, and need a
bench run with TIA before being trusted:

* the `fack` body layout and header fields, and whether the controller expects a `fack`
  per fragment or a different pacing;
* the `FRAG` / `LAST_FRAG` flag combination on the final fragment;
* the PNIORW `ErrorCode1` values in `RecordError` and the rule that a failed single-record
  write is reported as the call's status rather than inside the `IODWriteRes`;
* the 1392-byte fragment size against what the S7-1500 accepts.

To close this: capture an `RDREC` and a `WRREC` of a few KiB with Wireshark on the
bench (`docs/bench-capture-protocol.md`), add them as goldens, and replay them.
