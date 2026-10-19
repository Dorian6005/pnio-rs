//! DCE-RPC connectionless fragmentation helpers: the `fack` PDU and response
//! fragmenting.
//!
//! A single UDP datagram carries at most 1472 bytes (Ethernet MTU 1500 - IPv4 20 -
//! UDP 8); the 80-byte RPC header leaves [`FRAG_BODY_MAX`] bytes of *stub* (the NDR
//! header plus the PNIO blocks). Anything larger is split into numbered fragments so
//! that IP never has to fragment, each fragment being acknowledged and retransmitted on
//! its own.

use super::{PacketType, RpcHeader, FLAG1_FRAG, FLAG1_LAST_FRAG, FLAG1_NO_FACK};

/// Largest stub carried by one fragment. `1500 - 20 - 8 - 80 = 1392`, a multiple of 8 as
/// DCE-RPC requires for every fragment but the last.
pub const FRAG_BODY_MAX: usize = 1392;

/// Upper bound on the reassembled stub of one call (record data plus block headers).
pub const MAX_STUB: usize = 64 * 1024 + 4096;

/// Upper bound on the number of fragments of one call.
pub const MAX_FRAGMENTS: usize = MAX_STUB / 8;

/// `fack` body version.
const FACK_BODY_VERSION: u8 = 1;

/// Fixed part of a `fack` body, in bytes.
pub const FACK_BODY_LEN: usize = 16;

/// Builds the `fack` PDU acknowledging, for the call `req`, every fragment up to and
/// including `frag_num`. `window` is the number of fragments the sender may have
/// outstanding.
pub fn build_fack(req: &RpcHeader, frag_num: u16, window: u16) -> Vec<u8> {
    let header = RpcHeader {
        ptype: PacketType::Fack,
        flags1: FLAG1_NO_FACK,
        flags2: 0,
        drep: req.drep,
        serial_hi: 0,
        object: req.object,
        interface: req.interface,
        activity: req.activity,
        server_boot: req.server_boot,
        if_version: req.if_version,
        seq_num: req.seq_num,
        opnum: req.opnum,
        ihint: 0xffff,
        ahint: 0xffff,
        frag_len: FACK_BODY_LEN as u16,
        frag_num,
        auth_proto: 0,
        serial_lo: 0,
    };
    let mut pdu = Vec::with_capacity(RpcHeader::LEN + FACK_BODY_LEN);
    header.write(&mut pdu);
    let d = req.drep;
    pdu.push(FACK_BODY_VERSION);
    pdu.push(0); // pad
    d.put_u16(&mut pdu, window);
    d.put_u32(&mut pdu, MAX_STUB as u32); // max_tsdu
    d.put_u32(&mut pdu, FRAG_BODY_MAX as u32); // max_frag_size
    d.put_u16(&mut pdu, 0); // serial_num
    d.put_u16(&mut pdu, 0); // selack_len
    pdu
}

/// Splits `stub` into complete fragment PDUs built from `template` (whose `ptype`,
/// UUIDs, `seq_num`, `opnum` and `drep` are kept). Fragment `i` carries
/// `frag_num = i` and [`FLAG1_FRAG`]; the last one also [`FLAG1_LAST_FRAG`]. `NO_FACK` is
/// cleared so the receiver acknowledges them. A stub that fits one fragment is *not*
/// split: callers handle that case with their normal single-PDU path.
pub fn fragment(template: &RpcHeader, stub: &[u8]) -> Vec<Vec<u8>> {
    let n = stub.len().div_ceil(FRAG_BODY_MAX).max(1);
    let mut out = Vec::with_capacity(n);
    for (i, chunk) in stub.chunks(FRAG_BODY_MAX).enumerate() {
        let mut h = template.clone();
        h.flags1 = (template.flags1 & !(FLAG1_NO_FACK | FLAG1_LAST_FRAG)) | FLAG1_FRAG;
        if i + 1 == n {
            h.flags1 |= FLAG1_LAST_FRAG;
        }
        h.frag_num = i as u16;
        h.frag_len = chunk.len() as u16;
        let mut pdu = Vec::with_capacity(RpcHeader::LEN + chunk.len());
        h.write(&mut pdu);
        pdu.extend_from_slice(chunk);
        out.push(pdu);
    }
    out
}

/// The `frag_num` a `fack` body/header acknowledges up to: parsed from the header, kept
/// as a function so callers do not depend on the field's meaning.
pub fn fack_acked_through(h: &RpcHeader) -> u16 {
    h.frag_num
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{Drep, Uuid, PNIO_DEVICE_INTERFACE};

    fn template() -> RpcHeader {
        RpcHeader {
            ptype: PacketType::Response,
            flags1: 0x28,
            flags2: 0,
            drep: Drep::BIG,
            serial_hi: 0,
            object: Uuid::NIL,
            interface: PNIO_DEVICE_INTERFACE,
            activity: Uuid([7; 16]),
            server_boot: 0,
            if_version: 1,
            seq_num: 9,
            opnum: 2,
            ihint: 0xffff,
            ahint: 0xffff,
            frag_len: 0,
            frag_num: 0,
            auth_proto: 0,
            serial_lo: 0,
        }
    }

    #[test]
    fn fragments_are_numbered_flagged_and_reassemble() {
        let stub: Vec<u8> = (0..(FRAG_BODY_MAX * 2 + 100)).map(|i| i as u8).collect();
        let frags = fragment(&template(), &stub);
        assert_eq!(frags.len(), 3);
        let mut joined = Vec::new();
        for (i, f) in frags.iter().enumerate() {
            let h = RpcHeader::parse_any(f).unwrap();
            assert_eq!(h.frag_num as usize, i);
            assert!(h.is_fragment());
            assert_eq!(h.flags1 & FLAG1_NO_FACK, 0, "fragments must be fackable");
            assert_eq!(h.flags1 & FLAG1_LAST_FRAG != 0, i == 2);
            assert_eq!(h.frag_len as usize, f.len() - RpcHeader::LEN);
            if i < 2 {
                assert_eq!(f.len() - RpcHeader::LEN, FRAG_BODY_MAX);
                assert_eq!(FRAG_BODY_MAX % 8, 0);
            }
            joined.extend_from_slice(&f[RpcHeader::LEN..]);
        }
        assert_eq!(joined, stub);
    }

    #[test]
    fn fack_acknowledges_through_the_given_fragment() {
        let pdu = build_fack(&template(), 4, 8);
        assert_eq!(pdu.len(), RpcHeader::LEN + FACK_BODY_LEN);
        let h = RpcHeader::parse_any(&pdu).unwrap();
        assert_eq!(h.ptype, PacketType::Fack);
        assert_eq!(fack_acked_through(&h), 4);
        assert_eq!((h.activity, h.seq_num), (Uuid([7; 16]), 9));
        assert_eq!(pdu[RpcHeader::LEN], 1); // body version
    }
}
