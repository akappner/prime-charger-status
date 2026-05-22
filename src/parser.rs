use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::Instant;

use crate::protocol::tlv_iter;
use crate::state::{ChannelState, ConnectionMode, DashboardState, PortState};

// ── Decoded packet ────────────────────────────────────────────────────────────

/// Packet decoded from raw BLE notification bytes.
pub struct DecodedPacket {
    /// `[03 00] [group]` — first 3 bytes of the inner payload.
    pub pattern: [u8; 3],
    /// Command ID with ENC (0x40) and ACK (0x08) flags stripped.
    pub cmd: u16,
    /// True if the payload is AES-CBC encrypted.
    pub is_enc: bool,
    /// True if this is an ACK/response packet.
    pub is_ack: bool,
    /// Everything after the 5-byte header (ciphertext or plaintext TLV).
    pub body: Vec<u8>,
}

/// Decode a raw BLE notification into a `DecodedPacket`.
///
/// Frame layout: `FF 09 [len_le16] [payload] [xor]`
/// Payload:      `03 00 [group] [cmd_high] [cmd_low] [body...]`
pub fn decode_packet(raw: &[u8]) -> Option<DecodedPacket> {
    if raw.len() < 7 {
        return None;
    }
    // Strip `FF 09 len_le16` prefix and trailing XOR checksum.
    let payload = &raw[4..raw.len() - 1];
    if payload.len() < 5 {
        return None;
    }
    let pattern = [payload[0], payload[1], payload[2]];
    let cmd_high = payload[3];
    let cmd_low = payload[4];
    let is_enc = cmd_high & 0x40 != 0;
    let is_ack = cmd_high & 0x08 != 0;
    let cmd = (((cmd_high & !0x48) as u16) << 8) | (cmd_low as u16);
    let body = payload[5..].to_vec();
    Some(DecodedPacket {
        pattern,
        cmd,
        is_enc,
        is_ack,
        body,
    })
}

// ── Fragment buffer ───────────────────────────────────────────────────────────

/// Reassembles fragmented encrypted responses.
///
/// Pattern `03 01 0F` payloads carry a one-byte fragment header:
///   - high nibble = 1-based fragment index
///   - low nibble  = total fragment count
#[derive(Default)]
pub struct FragmentBuffer {
    pending: HashMap<[u8; 2], BTreeMap<u8, Vec<u8>>>,
    total: HashMap<[u8; 2], u8>,
}

impl FragmentBuffer {
    /// Feed a fragment. Returns `Some(reassembled_ciphertext)` when complete.
    pub fn feed(
        &mut self,
        cmd_key: [u8; 2],
        index: u8,
        total: u8,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        if total == 0 {
            // Treat as non-fragmented data.
            return Some(data);
        }
        if total == 1 {
            return Some(data);
        }
        if index == 1 {
            // New sequence: clear any stale fragments.
            self.pending.remove(&cmd_key);
        }
        self.pending.entry(cmd_key).or_default().insert(index, data);
        self.total.insert(cmd_key, total);

        let frags = self.pending.get(&cmd_key)?;
        if frags.len() as u8 == total {
            let assembled: Vec<u8> = frags.values().flatten().cloned().collect();
            self.pending.remove(&cmd_key);
            self.total.remove(&cmd_key);
            Some(assembled)
        } else {
            None
        }
    }
}

// ── Status parsers ────────────────────────────────────────────────────────────

/// Apply a comprehensive status payload (TLV offset already resolved) to
/// `DashboardState`. Called for cmds 0x0300, 0x0D00, 0x8200, 0x820A, 0x8402, 0x8405.
pub fn apply_status(data: &[u8], offset: usize, state: &mut DashboardState) {
    for entry in tlv_iter(data, offset) {
        match entry.tag {
            0xA1 if !entry.val.is_empty() => {
                state.device_status = entry.val[0];
            }
            // USB ports: tags A4–A9 → indices 0–5
            0xA4 => apply_port(&mut state.ports[0], entry.val),
            0xA5 => apply_port(&mut state.ports[1], entry.val),
            0xA6 => apply_port(&mut state.ports[2], entry.val),
            0xA7 => apply_port(&mut state.ports[3], entry.val),
            0xA8 => apply_port(&mut state.ports[4], entry.val),
            0xA9 => apply_port(&mut state.ports[5], entry.val),
            // Power channels: tags AA–AE → indices 0–4
            0xAA => apply_channel(&mut state.channels[0], entry.val),
            0xAB => apply_channel(&mut state.channels[1], entry.val),
            0xAC => apply_channel(&mut state.channels[2], entry.val),
            0xAD => apply_channel(&mut state.channels[3], entry.val),
            0xAE => apply_channel(&mut state.channels[4], entry.val),
            // Temperature: v[0]=type, v[1]=°C
            0xB3 if entry.val.len() >= 2 => {
                state.temperature = entry.val[1] as i32;
            }
            // Timestamp: v[1..5] = 4-byte LE unix seconds
            0xFE if entry.val.len() >= 5 => {
                state.device_ts =
                    u32::from_le_bytes(entry.val[1..5].try_into().unwrap());
                state.last_update = Some(Instant::now());
            }
            _ => {}
        }
    }
}

/// Apply live-power payload (same tag layout as comprehensive status).
pub fn apply_live_power(data: &[u8], offset: usize, state: &mut DashboardState) {
    // Same structure — reuse apply_status.
    apply_status(data, offset, state);
}

fn apply_port(port: &mut PortState, v: &[u8]) {
    if v.len() < 8 {
        return;
    }
    port.mode = ConnectionMode::from_byte(v[1]);
    if port.mode != ConnectionMode::NotConnected {
        port.volts = u16::from_le_bytes([v[2], v[3]]) as f32 / 1000.0;
        port.amps = u16::from_le_bytes([v[4], v[5]]) as f32 / 1000.0;
        port.watts = u16::from_le_bytes([v[6], v[7]]) as f32 / 100.0;
    } else {
        port.volts = 0.0;
        port.amps = 0.0;
        port.watts = 0.0;
    }
}

fn apply_channel(ch: &mut ChannelState, v: &[u8]) {
    if v.len() < 14 {
        return;
    }
    ch.mode = ConnectionMode::from_byte(v[1]);
    if ch.mode != ConnectionMode::NotConnected {
        ch.volts = u16::from_le_bytes([v[2], v[3]]) as f32 / 100.0;
        ch.amps = u16::from_le_bytes([v[4], v[5]]) as f32 / 100.0;
        ch.max_volts = u16::from_le_bytes([v[6], v[7]]) as f32 / 100.0;
        ch.max_amps = u16::from_le_bytes([v[8], v[9]]) as f32 / 100.0;
        ch.max_watts = u16::from_le_bytes([v[11], v[12]]) as f32 / 10.0;
    } else {
        ch.volts = 0.0;
        ch.amps = 0.0;
    }
}

/// Parse session-key-exchange response (cmd 0x0022).
/// Returns `Some((new_key, new_iv))` if a new session key was found.
pub fn parse_session_key_response(data: &[u8], offset: usize) -> (Option<[u8; 16]>, Option<[u8; 16]>) {
    let mut new_key: Option<[u8; 16]> = None;
    let mut new_iv: Option<[u8; 16]> = None;

    for entry in tlv_iter(data, offset) {
        if entry.val.len() == 16 {
            match entry.tag {
                0xA1 | 0xA3 => {
                    new_key = Some(entry.val.try_into().unwrap());
                }
                0xA4 => {
                    new_iv = Some(entry.val.try_into().unwrap());
                }
                _ => {}
            }
        }
    }
    (new_key, new_iv)
}

/// Extract device info (serial, firmware, MAC) from handshake 0x0029 response.
/// TLV starts at offset 6 (after 5-byte header + leading 0x00 byte).
pub fn extract_handshake_info(payload: &[u8]) -> (String, String, String) {
    let mut version = String::new();
    let mut serial = String::new();
    let mut mac = String::new();

    for entry in tlv_iter(payload, 6) {
        match entry.tag {
            0xA3 => version = bytes_to_ascii(entry.val),
            0xA4 => serial = bytes_to_ascii(entry.val),
            0xA5 => {
                mac = entry
                    .val
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":")
            }
            _ => {}
        }
    }
    (serial, version, mac)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

pub fn bytes_to_ascii(b: &[u8]) -> String {
    b.iter()
        .map(|&c| if (0x20..0x7F).contains(&c) { c as char } else { '.' })
        .collect()
}

pub fn hex_str(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_single() {
        let mut fb = FragmentBuffer::default();
        let data = vec![1, 2, 3];
        let result = fb.feed([0xC0, 0x02], 1, 1, data.clone());
        assert_eq!(result, Some(data));
    }

    #[test]
    fn fragment_reassembly() {
        let mut fb = FragmentBuffer::default();
        let key = [0xC0u8, 0x02u8];
        assert!(fb.feed(key, 1, 3, vec![1]).is_none());
        assert!(fb.feed(key, 2, 3, vec![2]).is_none());
        let result = fb.feed(key, 3, 3, vec![3]);
        assert_eq!(result, Some(vec![1, 2, 3]));
    }

    #[test]
    fn decode_packet_basic() {
        // Build a minimal valid-looking packet
        let payload = &[0x03u8, 0x00, 0x01, 0x00, 0x01, 0xA1, 0x01, 0x21];
        let mut pkt = vec![0xFF, 0x09];
        let len = (payload.len() + 5) as u16;
        pkt.extend_from_slice(&len.to_le_bytes());
        pkt.extend_from_slice(payload);
        let xor: u8 = pkt.iter().fold(0u8, |a, &b| a ^ b);
        pkt.push(xor);

        let dec = decode_packet(&pkt).unwrap();
        assert_eq!(dec.cmd, 0x0001);
        assert!(!dec.is_enc);
    }
}
