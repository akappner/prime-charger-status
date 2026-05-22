// ── Protocol constants ────────────────────────────────────────────────────────

pub const ADVERTISED_SERVICE_UUID: &str = "0000ff09-0000-1000-8000-00805f9b34fb";
pub const WRITE_CHAR_UUID: &str = "8c850002-0302-41c5-b46e-cf057c562025";
pub const NOTIFY_CHAR_UUID: &str = "8c850003-0302-41c5-b46e-cf057c562025";

/// 40-byte static used in every handshake (A2 field).
/// Python source: bytes.fromhex("32633337376466613039636462373932" +
///                               "343838396534323932613337663631633863356564353264")
pub const A2_STATIC: [u8; 40] = hex_literal::hex!(
    "32633337376466613039636462373932"
    "343838396534323932613337663631633863356564353264"
);

/// First 16 bytes of A2_STATIC used as the initial AES key.
pub const INITIAL_KEY: [u8; 16] = {
    let mut k = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        k[i] = A2_STATIC[i];
        i += 1;
    }
    k
};

// ── TLV iterator ──────────────────────────────────────────────────────────────

/// Zero-allocation TLV iterator. Borrows the input slice and yields `TlvEntry`
/// structs containing tag and value slices without copying.
pub struct TlvIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

pub struct TlvEntry<'a> {
    pub tag: u8,
    pub val: &'a [u8],
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = TlvEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 1 >= self.buf.len() {
            return None;
        }
        let tag = self.buf[self.pos];
        let len = self.buf[self.pos + 1] as usize;
        let end = self.pos + 2 + len;
        if end > self.buf.len() {
            return None;
        }
        let val = &self.buf[self.pos + 2..end];
        self.pos = end;
        Some(TlvEntry { tag, val })
    }
}

pub fn tlv_iter(buf: &[u8], offset: usize) -> TlvIter<'_> {
    TlvIter { buf, pos: offset }
}

/// Build TLV bytes from `(tag, value)` pairs.
pub fn build_tlv(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(tag, val) in items {
        out.push(tag);
        out.push(val.len() as u8);
        out.extend_from_slice(val);
    }
    out
}

// ── Packet builders ───────────────────────────────────────────────────────────

/// Build plain inner payload: `03 00 group cmd_high cmd_low TLV...`
pub fn build_payload(group: u8, cmd: u16, tlv: &[(u8, &[u8])]) -> Vec<u8> {
    let cmd_high = (cmd >> 8) as u8;
    let cmd_low = cmd as u8;
    let mut out = vec![0x03, 0x00, group, cmd_high, cmd_low];
    out.extend_from_slice(&build_tlv(tlv));
    out
}

/// Build encrypted inner payload: `03 00 group (cmd_high | 0x40) cmd_low ciphertext...`
pub fn build_encrypted_payload(group: u8, cmd: u16, ciphertext: &[u8]) -> Vec<u8> {
    let cmd_high = ((cmd >> 8) as u8) | 0x40;
    let cmd_low = cmd as u8;
    let mut out = vec![0x03, 0x00, group, cmd_high, cmd_low];
    out.extend_from_slice(ciphertext);
    out
}

/// Wrap payload in `FF 09 [len_le16] [payload] [xor_checksum]`.
pub fn frame_packet(payload: &[u8]) -> Vec<u8> {
    let total_len = (payload.len() + 5) as u16;
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.extend_from_slice(&[0xFF, 0x09]);
    out.extend_from_slice(&total_len.to_le_bytes());
    out.extend_from_slice(payload);
    let xor: u8 = out.iter().fold(0u8, |a, &b| a ^ b);
    out.push(xor);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_roundtrip() {
        let items: &[(u8, &[u8])] = &[(0xA1, &[0x01, 0x02]), (0xFE, &[0xAA, 0xBB, 0xCC, 0xDD])];
        let buf = build_tlv(items);
        let parsed: Vec<_> = tlv_iter(&buf, 0).map(|e| (e.tag, e.val.to_vec())).collect();
        assert_eq!(parsed[0], (0xA1, vec![0x01, 0x02]));
        assert_eq!(parsed[1], (0xFE, vec![0xAA, 0xBB, 0xCC, 0xDD]));
    }

    #[test]
    fn frame_xor() {
        let payload = build_payload(0x01, 0x0001, &[(0xA1, &[0x01, 0x02, 0x03, 0x04])]);
        let pkt = frame_packet(&payload);
        // XOR of all bytes except the last must equal the last byte
        let xor: u8 = pkt[..pkt.len() - 1].iter().fold(0u8, |a, &b| a ^ b);
        assert_eq!(xor, *pkt.last().unwrap());
    }

    #[test]
    fn a2_static_length() {
        assert_eq!(A2_STATIC.len(), 40);
        assert_eq!(INITIAL_KEY.len(), 16);
    }
}
