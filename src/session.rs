use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use btleplug::platform::Peripheral;
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::ble;
use crate::crypto::{aes_cbc_decrypt, aes_cbc_encrypt, pad_iv, CryptoKeys};
use crate::parser::{
    apply_live_power, apply_status, decode_packet, extract_handshake_info,
    hex_str, parse_session_key_response, FragmentBuffer,
};
use crate::protocol::{
    build_encrypted_payload, build_payload, frame_packet, A2_STATIC, INITIAL_KEY,
};
use crate::state::{DeviceInfo, SessionPhase, SharedState};

// ── Telemetry stage-7b A3 field ───────────────────────────────────────────────
const STAGE7B_UUID: &[u8] = b"79ebed35-dc9c-4904-b40c-72c4e863aa10";

// ── DeviceSession ────────────────────────────────────────────────────────────

pub struct DeviceSession {
    peripheral: Peripheral,
    crypto: CryptoKeys,
    device_info: DeviceInfo,
    frag_buf: FragmentBuffer,
    rx: mpsc::Receiver<Vec<u8>>,
    state: SharedState,
    /// Whether to print raw protocol debug output (mirrors the Python prints).
    pub verbose: bool,
}

impl DeviceSession {
    /// Connect to `peripheral`, set up the notification stream, and return a
    /// ready-to-use session. Also prints GATT service information.
    pub async fn new(peripheral: Peripheral, state: SharedState, verbose: bool) -> Result<Self> {
        // Connect + discover + subscribe
        let notif_stream = ble::connect_and_setup(&peripheral)
            .await
            .context("BLE connect/setup failed")?;

        if verbose {
            ble::print_gatt_services(&peripheral).await?;
        }

        // Forward BLE notification stream into an mpsc channel.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        tokio::spawn(async move {
            futures::pin_mut!(notif_stream);
            while let Some(notif) = notif_stream.next().await {
                if tx.send(notif.value).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            peripheral,
            crypto: CryptoKeys::None,
            device_info: DeviceInfo::default(),
            frag_buf: FragmentBuffer::default(),
            rx,
            state,
            verbose,
        })
    }

    // ── Sending ───────────────────────────────────────────────────────────────

    async fn send_raw(&self, packet: &[u8]) -> Result<()> {
        ble::write_gatt(&self.peripheral, packet).await
    }

    pub async fn send_plain(&self, group: u8, cmd: u16, tlv: &[(u8, &[u8])]) -> Result<()> {
        let payload = build_payload(group, cmd, tlv);
        let packet = frame_packet(&payload);
        if self.verbose {
            let cmd_clean = ((payload[3] & !0x40) as u16) << 8 | payload[4] as u16;
            println!("\n→ SEND cmd=0x{cmd_clean:04X}");
            println!("  Packet: {}", hex_str(&packet));
        }
        self.send_raw(&packet).await
    }

    pub async fn send_encrypted(&self, group: u8, cmd: u16, tlv: &[(u8, &[u8])]) -> Result<()> {
        let (key, iv) = self
            .crypto
            .key_iv()
            .context("Crypto not ready — send_encrypted called before key exchange")?;
        let plaintext = crate::protocol::build_tlv(tlv);
        let ciphertext = aes_cbc_encrypt(key, iv, &plaintext);
        let payload = build_encrypted_payload(group, cmd, &ciphertext);
        let packet = frame_packet(&payload);
        if self.verbose {
            println!("\n→ SEND cmd=0x{cmd:04X} (encrypted)");
            println!("  Packet: {}", hex_str(&packet));
        }
        self.send_raw(&packet).await
    }

    // ── Receiving ─────────────────────────────────────────────────────────────

    async fn wait_raw(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        tokio::time::timeout(timeout, self.rx.recv())
            .await
            .context("Timeout waiting for BLE notification")?
            .context("Notification channel closed")
    }

    /// Wait for a notification, decrypt if needed, route to parser, return content.
    pub async fn recv_and_decode(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let raw = self.wait_raw(timeout).await?;

        if self.verbose {
            println!("\n← RECV  raw={}", hex_str(&raw));
        }

        let Some(pkt) = decode_packet(&raw) else {
            return Ok(raw);
        };

        if self.verbose {
            let flags = match (pkt.is_enc, pkt.is_ack) {
                (true, true) => "ENC|ACK",
                (true, false) => "ENC",
                (false, true) => "ACK",
                (false, false) => "none",
            };
            println!(
                "  cmd=0x{:04X}  flags=[{}]  pattern={:02X}{:02X}{:02X}",
                pkt.cmd, flags, pkt.pattern[0], pkt.pattern[1], pkt.pattern[2]
            );
        }

        if !pkt.is_enc {
            // Return the inner payload (strip FF 09 len header + XOR checksum)
            // so callers receive the same slice Python's recv_and_decode returns.
            return Ok(raw[4..raw.len() - 1].to_vec());
        }

        let Some((key, iv)) = self.crypto.key_iv() else {
            if self.verbose {
                println!("  [DECRYPT_ERROR] No key available");
            }
            return Ok(raw);
        };
        let key = *key;
        let iv = *iv;

        // Fragment handling: pattern `03 01 0F` has a fragment-header byte.
        let ciphertext: Vec<u8> = if pkt.pattern == [0x03, 0x01, 0x0F] && !pkt.body.is_empty() {
            let frag_byte = pkt.body[0];
            let frag_index = (frag_byte >> 4) & 0xF;
            let frag_total = frag_byte & 0xF;
            let frag_data = pkt.body[1..].to_vec();
            let cmd_key = [
                (pkt.cmd >> 8) as u8,
                (pkt.cmd & 0xFF) as u8,
            ];

            if self.verbose {
                println!("  fragment {frag_index}/{frag_total} ({} B)", frag_data.len());
            }

            match self.frag_buf.feed(cmd_key, frag_index, frag_total, frag_data) {
                Some(assembled) => {
                    if self.verbose {
                        println!("  reassembled — {} B ciphertext", assembled.len());
                    }
                    assembled
                }
                None => {
                    if self.verbose {
                        println!("  buffered — waiting for more");
                    }
                    return Ok(raw);
                }
            }
        } else {
            pkt.body.clone()
        };

        match aes_cbc_decrypt(&key, &iv, &ciphertext) {
            Ok(decrypted) => {
                if self.verbose {
                    println!("  Decrypted: {}", hex_str(&decrypted));
                }
                self.route_decrypted(pkt.cmd, &decrypted).await;
                Ok(decrypted)
            }
            Err(e) => {
                if self.verbose {
                    println!("  [DECRYPT_ERROR] {e}");
                }
                Ok(raw)
            }
        }
    }

    /// Route decrypted payload to the appropriate parser and update shared state.
    async fn route_decrypted(&mut self, cmd: u16, data: &[u8]) {
        let offset = if data.first() == Some(&0x00) { 1 } else { 0 };

        match cmd {
            0x0300 | 0x0D00 | 0x8200 | 0x820A | 0x8402 | 0x8405 => {
                let mut st = self.state.lock().await;
                apply_status(data, offset, &mut st);
            }
            0x050E => {
                let mut st = self.state.lock().await;
                apply_live_power(data, offset, &mut st);
            }
            0x0022 => {
                let (new_key, new_iv) = parse_session_key_response(data, offset);
                let initial_iv = match &self.crypto {
                    CryptoKeys::Initial { iv, .. } => *iv,
                    _ => [0u8; 16],
                };
                if let Some(key) = new_key {
                    let iv = new_iv.unwrap_or(initial_iv);
                    self.crypto = CryptoKeys::Session { key, iv };
                    if self.verbose {
                        println!("  ✓ Session key active");
                    }
                } else {
                    // No new key — reuse initial key/IV for session.
                    let (key, iv) = match &self.crypto {
                        CryptoKeys::Initial { key, iv } => (*key, *iv),
                        _ => (INITIAL_KEY, initial_iv),
                    };
                    self.crypto = CryptoKeys::Session { key, iv };
                    if self.verbose {
                        println!("  ✓ Session active (reusing initial key+IV)");
                    }
                }
                let mut st = self.state.lock().await;
                st.session_phase = SessionPhase::Session;
            }
            _ => {
                if self.verbose {
                    println!("  [unknown cmd=0x{cmd:04X}]");
                }
            }
        }
    }

    // ── Telemetry helpers ─────────────────────────────────────────────────────

    pub async fn solicit_telemetry(&mut self) -> Result<()> {
        let ts = current_ts_bytes();
        let stage7b_a3: Vec<u8> = {
            let mut v = vec![0x04u8];
            v.extend_from_slice(STAGE7B_UUID);
            v
        };

        // 0x0200 — lightweight probe
        self.send_encrypted(
            0x0F,
            0x0200,
            &[(0xA1, &[0x21u8]), (0xFE, &ts)],
        )
        .await?;
        self.drain_notifications(Duration::from_millis(1500)).await;

        // 0x020A — full probe
        self.send_encrypted(
            0x0F,
            0x020A,
            &[
                (0xA1, &[0x21u8]),
                (0xA2, &hex_literal::hex!("044742")),
                (0xA3, &stage7b_a3),
                (0xA5, &[0x01u8, 0x01]),
                (0xFE, &ts),
            ],
        )
        .await?;
        self.drain_notifications(Duration::from_millis(1500)).await;

        Ok(())
    }

    /// Drain all queued notifications up to `timeout`.
    async fn drain_notifications(&mut self, timeout: Duration) {
        loop {
            match self.recv_and_decode(Duration::from_millis(100)).await {
                Ok(_) => {}
                Err(_) => break,
            }
            if timeout.is_zero() {
                break;
            }
        }
    }

    async fn keepalive(&mut self) -> Result<()> {
        let ts = current_ts_bytes();
        self.send_encrypted(0x11, 0x0030, &[(0xA1, &[0x21u8]), (0xFE, &ts)])
            .await
    }

    // ── Handshake ─────────────────────────────────────────────────────────────

    pub async fn run_handshake(&mut self) -> Result<()> {
        let ts = current_ts_bytes();
        let a2 = A2_STATIC.as_ref();

        {
            let mut st = self.state.lock().await;
            st.session_phase = SessionPhase::Handshake;
        }

        // Step 1 — 0x0001
        println!("\n─── Step 1 / 4 : Handshake 0x0001 ─────────────────────────");
        self.send_plain(0x01, 0x0001, &[(0xA1, &ts), (0xA2, a2)])
            .await?;
        self.recv_and_decode(Duration::from_secs(5)).await?;

        // Step 2 — 0x0003
        println!("\n─── Step 2 / 4 : Handshake 0x0003 ─────────────────────────");
        self.send_plain(
            0x01,
            0x0003,
            &[
                (0xA1, &ts),
                (0xA2, a2),
                (0xA3, &[0x20]),
                (0xA4, &[0x00, 0xF0]),
            ],
        )
        .await?;
        self.recv_and_decode(Duration::from_secs(5)).await?;

        // Step 3 — 0x0029 (get serial number)
        println!("\n─── Step 3 / 4 : Info request 0x0029 ──────────────────────");
        self.send_plain(0x01, 0x0029, &[(0xA1, &ts), (0xA2, a2)])
            .await?;
        let info_resp = self.recv_and_decode(Duration::from_secs(5)).await?;
        let (serial, firmware, mac) = extract_handshake_info(&info_resp);

        if serial.is_empty() {
            bail!("Serial number not extracted from handshake — aborting");
        }

        let initial_iv = pad_iv(serial.as_bytes());
        println!(
            "\n  ✓ Serial: {serial:?}   FW: {firmware:?}   MAC: {mac}"
        );
        println!(
            "  Initial IV (S/N padded): {}",
            hex_str(&initial_iv)
        );

        self.device_info = DeviceInfo { serial, firmware, mac };
        self.crypto = CryptoKeys::Initial {
            key: INITIAL_KEY,
            iv: initial_iv,
        };

        {
            let mut st = self.state.lock().await;
            st.device_info = self.device_info.clone();
        }

        // Step 4 — 0x0005
        println!("\n─── Step 4 / 4 : Handshake 0x0005 ─────────────────────────");
        self.send_plain(
            0x01,
            0x0005,
            &[
                (0xA1, &ts),
                (0xA2, a2),
                (0xA3, &[0x20]),
                (0xA4, &[0x00, 0xF0]),
                (0xA5, &[0x02]),
            ],
        )
        .await?;
        self.recv_and_decode(Duration::from_secs(5)).await?;

        println!("\n✓ Unencrypted handshake complete");

        // Step 5 — 0x0022 (initial encrypted / session key exchange)
        println!("\n─── Initial encryption (cmd 0x0022) ────────────────────────");
        self.send_encrypted(
            0x01,
            0x0022,
            &[
                (0xA1, &ts),
                (0xA2, a2),
                (0xA3, &[0u8; 4]),
                (0xA5, &[0u8; 40]),
            ],
        )
        .await?;

        // Wait for session key response
        println!("  Waiting for session key response…");
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            while let Ok(Ok(_)) = tokio::time::timeout(
                Duration::from_millis(50),
                self.recv_and_decode(Duration::from_millis(50)),
            )
            .await
            {}
            if self.crypto.is_session() {
                break;
            }
        }

        if !self.crypto.is_session() {
            bail!(
                "Timed out waiting for session key.\n\
                 The device may use a different TLV tag — \
                 check decrypted hex and update parse_session_key_response()."
            );
        }

        // Drain any queued notifications
        while self
            .rx
            .try_recv()
            .is_ok()
        {}

        Ok(())
    }

    // ── Telemetry poll loop ───────────────────────────────────────────────────

    /// `ready` is notified once the handshake completes, before telemetry begins.
    pub async fn run_telemetry(
        &mut self,
        interval_secs: f64,
        ready: Option<Arc<tokio::sync::Notify>>,
    ) -> Result<()> {
        self.run_handshake().await?;
        if let Some(n) = &ready {
            n.notify_one();
        }
        self.solicit_telemetry().await?;

        println!(
            "\n─── Polling telemetry every {interval_secs}s (Ctrl-C to exit) ──"
        );

        let interval = Duration::from_secs_f64(interval_secs);
        let mut keepalive_counter = 0u32;

        loop {
            let deadline = tokio::time::Instant::now() + interval;

            // Drain all incoming notifications until the deadline.
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match self.recv_and_decode(remaining).await {
                    Ok(_) => {}
                    Err(_) => break,
                }
            }

            // Re-poll lightweight probe.
            let ts = current_ts_bytes();
            self.send_encrypted(0x0F, 0x0200, &[(0xA1, &[0x21u8]), (0xFE, &ts)])
                .await?;

            // Keepalive every ~10 polls.
            keepalive_counter += 1;
            if keepalive_counter >= (10.0 / interval_secs).ceil() as u32 {
                keepalive_counter = 0;
                if let Err(e) = self.keepalive().await {
                    eprintln!("  [KEEPALIVE ERROR] {e}");
                }
            }
        }
    }

    // ── Command mode ─────────────────────────────────────────────────────────

    pub async fn run_commands(
        &mut self,
        cmds: Vec<u16>,
        group: u8,
        listen: bool,
    ) -> Result<()> {
        self.run_handshake().await?;

        for (i, cmd_id) in cmds.iter().enumerate() {
            println!(
                "\n─── Command {}/{} 0x{cmd_id:04X} (group 0x{group:02X}) ──────────────",
                i + 1,
                cmds.len()
            );
            self.send_encrypted(group, *cmd_id, &[(0xA1, &[0x21u8])])
                .await?;

            let mut got_any = false;
            loop {
                match self.recv_and_decode(Duration::from_secs(3)).await {
                    Ok(_) => {
                        got_any = true;
                    }
                    Err(_) => break,
                }
            }
            if !got_any {
                println!("  (no response within 3 s)");
            }
        }

        if listen {
            println!("\n─── Listening for additional notifications (Ctrl-C to exit) ──");
            let mut keepalive_t = tokio::time::Instant::now();
            loop {
                match self.recv_and_decode(Duration::from_secs(60)).await {
                    Ok(_) => {}
                    Err(_) => {}
                }
                if keepalive_t.elapsed() >= Duration::from_secs(10) {
                    keepalive_t = tokio::time::Instant::now();
                    let _ = self.keepalive().await;
                }
            }
        }

        Ok(())
    }

    // ── Brute-force scan ──────────────────────────────────────────────────────

    pub async fn run_scan(&mut self) -> Result<()> {
        self.run_handshake().await?;

        println!("\n─── Brute-force command-ID scan (group 0x11) ──────────────");
        let mut hits: Vec<(u16, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut keepalive_t = tokio::time::Instant::now();

        for cmd_id in 0x0200u16..=0xFFFF {
            if keepalive_t.elapsed() >= Duration::from_secs(10) {
                keepalive_t = tokio::time::Instant::now();
                let _ = self.keepalive().await;
            }

            self.send_encrypted(0x11, cmd_id, &[(0xA1, &[0x21u8])])
                .await?;

            loop {
                match tokio::time::timeout(
                    Duration::from_millis(150),
                    self.rx.recv(),
                )
                .await
                {
                    Ok(Some(raw)) => {
                        if raw.len() >= 9 {
                            let rch = raw[7];
                            let rcl = raw[8];
                            let rcmd = (((rch & !0x48) as u16) << 8) | rcl as u16;
                            let plain = if rch & 0x40 != 0 {
                                let ct = &raw[9..raw.len() - 1];
                                if let Some((k, iv)) = self.crypto.key_iv() {
                                    aes_cbc_decrypt(k, iv, ct).unwrap_or_default()
                                } else {
                                    Vec::new()
                                }
                            } else {
                                Vec::new()
                            };
                            println!("  ★ resp cmd=0x{rcmd:04X} ← {}", hex_str(&raw));
                            if !plain.is_empty() {
                                println!("      plain: {}", hex_str(&plain));
                            }
                            hits.push((rcmd, raw, plain));
                        }
                    }
                    _ => break,
                }
            }
        }

        println!("\n✓ Probe complete — {} responses captured", hits.len());
        println!(
            "\n  Serial : {}\n  FW     : {}\n  MAC    : {}",
            self.device_info.serial,
            self.device_info.firmware,
            self.device_info.mac,
        );
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn current_ts_bytes() -> [u8; 4] {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    secs.to_le_bytes()
}
