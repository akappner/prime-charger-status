#!/usr/bin/env python3
"""
BLE Device Connector — Linux shell utility
Implements the full handshake + AES-CBC encrypted session protocol.

Install deps:  pip3 install bleak cryptography
Run:           python3 ble_connect.py [--mac AA:BB:CC:DD:EE:FF]
               python3 ble_connect.py --scan          # scan first
"""

import asyncio
import argparse
import curses
import os
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from functools import reduce

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding

# ── UUIDs ─────────────────────────────────────────────────────────────────────
ADVERTISED_SERVICE_UUID  = "0000ff09-0000-1000-8000-00805f9b34fb"
FULL_SERVICE_UUID        = "8c850001-0302-41c5-b46e-cf057c562025"
WRITE_CHARACTERISTIC     = "8c850002-0302-41c5-b46e-cf057c562025"
NOTIFY_CHARACTERISTIC    = "8c850003-0302-41c5-b46e-cf057c562025"

# ── Protocol constants ─────────────────────────────────────────────────────────
A2_STATIC_HEX = (
    "32633337376466613039636462373932"
    "343838396534323932613337663631633863356564353264"
)
A2_STATIC      = bytes.fromhex(A2_STATIC_HEX)
INITIAL_KEY    = A2_STATIC[:16]   # first 16 raw bytes of A2_STATIC


# ── Dashboard state ───────────────────────────────────────────────────────────

@dataclass
class PortState:
    name: str
    mode: str = "Not Connected"
    connected: bool = False
    volts: float = 0.0
    amps: float = 0.0
    watts: float = 0.0


@dataclass
class ChannelState:
    name: str
    mode: str = "Not Connected"
    connected: bool = False
    volts: float = 0.0
    amps: float = 0.0
    max_volts: float = 0.0
    max_amps: float = 0.0
    max_watts: float = 0.0


@dataclass
class DashboardState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    running: bool = True
    session_state: str = "INACTIVE"
    device_status: int = 0
    temperature: int = 0
    timestamp: int = 0
    last_update: float = 0.0
    device_info: dict = field(default_factory=dict)
    error: str = ""
    ports: dict = field(default_factory=lambda: {
        name: PortState(name)
        for name in ("USB-C1", "USB-C2", "USB-C3", "USB-C4", "USB-A1", "USB-A2")
    })
    channels: dict = field(default_factory=lambda: {
        name: ChannelState(name)
        for name in ("PWR-1", "PWR-2", "PWR-3", "PWR-4", "PWR-5")
    })


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """PKCS7-padded AES-128-CBC encrypt (matches WebCrypto AES-CBC)."""
    padder = crypto_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """PKCS7-unpadded AES-128-CBC decrypt."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = crypto_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def pad_iv(iv_bytes: bytes, length: int = 16) -> bytes:
    """Ensure IV is exactly 16 bytes (pad with zeros or truncate)."""
    if len(iv_bytes) >= length:
        return iv_bytes[:length]
    return iv_bytes.ljust(length, b'\x00')


# ── Packet builders ────────────────────────────────────────────────────────────

def build_tlv(tlv_list: list) -> bytes:
    """Build TLV buffer from list of (type, value_bytes) tuples."""
    out = bytearray()
    for t, v in tlv_list:
        out += bytes([t, len(v)]) + bytes(v)
    return bytes(out)


def build_payload(group: int, command: int, tlv_list: list) -> bytes:
    """Build the inner payload: 03 00 group cmdHigh cmdLow TLV..."""
    cmd_high = (command >> 8) & 0xFF
    cmd_low  =  command       & 0xFF
    return bytes([0x03, 0x00, group, cmd_high, cmd_low]) + build_tlv(tlv_list)


def build_encrypted_payload(group: int, command: int, tlv_list: list,
                             key: bytes, iv: bytes) -> bytes:
    """Build encrypted inner payload: 03 00 group (cmdHigh|0x40) cmdLow cipher..."""
    cmd_high = ((command >> 8) & 0xFF) | 0x40   # set encryption flag
    cmd_low  =   command       & 0xFF
    plaintext  = build_tlv(tlv_list)
    ciphertext = aes_cbc_encrypt(key, iv, plaintext)
    return bytes([0x03, 0x00, group, cmd_high, cmd_low]) + ciphertext


def frame_packet(payload: bytes) -> bytes:
    """Wrap payload in FF 09 [len_le16] [payload] [xor_checksum]."""
    total_len = len(payload) + 5
    header = bytes([0xFF, 0x09]) + struct.pack('<H', total_len)
    msg_for_checksum = header + payload
    checksum = reduce(lambda a, b: a ^ b, msg_for_checksum, 0)
    return msg_for_checksum + bytes([checksum])


# ── Hex/ASCII helpers ─────────────────────────────────────────────────────────

def hex_str(b: bytes) -> str:
    return b.hex().upper()

def bytes_to_ascii(b: bytes) -> str:
    return ''.join(chr(c) if 0x20 <= c < 0x7F else '.' for c in b)

def parse_tlv(payload: bytes, offset: int = 0):
    """Generator yielding (type, value_bytes) from a TLV blob."""
    i = offset
    while i + 1 < len(payload):
        t   = payload[i]
        ln  = payload[i + 1]
        if i + 2 + ln > len(payload):
            print(f"  [TLV_ERROR] type=0x{t:02X} length={ln} exceeds payload at i={i}")
            return
        yield t, payload[i + 2 : i + 2 + ln]
        i += 2 + ln


# ── Main session class ────────────────────────────────────────────────────────

class DeviceSession:
    def __init__(self, dashboard: DashboardState | None = None):
        self.client        = None
        self.device_info   = {}
        self.crypto_state  = "INACTIVE"
        self.session_key   = None
        self.session_iv    = None
        self.initial_key   = INITIAL_KEY
        self.initial_iv    = None    # set after S/N extracted
        self._notify_queue = asyncio.Queue()
        self._write_lock   = asyncio.Lock()
        # Buffers fragments of multi-packet encrypted replies (pattern 03 01 0F).
        # Keyed by (cmd_high & ~0x48, cmd_low).
        self._frag_buf: dict[bytes, dict[int, bytes]] = {}
        self._frag_total: dict[bytes, int] = {}
        self.dashboard     = dashboard

    # ── Sending ────────────────────────────────────────────────────────────────

    async def send(self, payload: bytes, label: str = ""):
        packet = frame_packet(payload)
        cmd_high = payload[3] if len(payload) > 3 else 0
        cmd_low  = payload[4] if len(payload) > 4 else 0
        enc_flag = bool(cmd_high & 0x40)
        cmd      = ((cmd_high & ~0x40) << 8) | cmd_low
        tag = f" [{label}]" if label else ""
        print(f"\n→ SEND{tag} cmd=0x{cmd:04X} {'(encrypted)' if enc_flag else ''}")
        print(f"  Packet: {hex_str(packet)}")
        async with self._write_lock:
            await self.client.write_gatt_char(WRITE_CHARACTERISTIC, packet,
                                              response=True)

    async def send_plain(self, group: int, command: int, tlv_list: list,
                         label: str = ""):
        payload = build_payload(group, command, tlv_list)
        await self.send(payload, label)

    async def send_encrypted(self, group: int, command: int, tlv_list: list,
                              label: str = ""):
        key = self.session_key if self.crypto_state == "Session" else self.initial_key
        iv  = self.session_iv  if self.crypto_state == "Session" else self.initial_iv
        if key is None or iv is None:
            raise RuntimeError("Crypto not ready — key or IV is None")
        payload = build_encrypted_payload(group, command, tlv_list, key, iv)
        await self.send(payload, label)

    async def solicit_telemetry(self):
        """Send telemetry-solicit commands modelled on Anker Prime stage-7.

        Two encrypted packets with pattern 03 00 0F (group 0x0F):
          • cmd 0x0200 — small probe (TLV A1, FE)
          • cmd 0x020A — fuller probe (TLV A1, A2, A3, A5, FE)
        The plaintext payloads mirror prime_device.py NEGOTIATION_COMMAND_7
        and NEGOTIATION_COMMAND_8, but encrypted with this session's AES-CBC
        key/IV instead of the Prime AES-GCM scheme.
        """
        ts_bytes = struct.pack('<I', int(time.time()))
        # Stage-7b A3 field: leading 0x04 + ASCII UUID (from SolixBLE)
        stage7b_a3 = bytes([0x04]) + b"79ebed35-dc9c-4904-b40c-72c4e863aa10"

        print("\n─── Telemetry-solicit 0x0200 (group 0x0F) ─────────────────")
        await self.send_encrypted(0x0F, 0x0200, [
            (0xA1, bytes([0x21])),
            (0xFE, ts_bytes),
        ], label="TELEMETRY-0200")
        while True:
            try:
                await self.recv_and_decode(timeout=1.5)
            except asyncio.TimeoutError:
                break

        print("\n─── Telemetry-solicit 0x020A (group 0x0F) ─────────────────")
        await self.send_encrypted(0x0F, 0x020A, [
            (0xA1, bytes([0x21])),
            (0xA2, bytes.fromhex("044742")),
            (0xA3, stage7b_a3),
            (0xA5, bytes([0x01, 0x01])),
            (0xFE, ts_bytes),
        ], label="TELEMETRY-020A")
        while True:
            try:
                await self.recv_and_decode(timeout=1.5)
            except asyncio.TimeoutError:
                break

    async def _keepalive_loop(self, interval: float = 10.0):
        """Periodically send GET_SOFTWARE_VERSION to keep the link alive."""
        while True:
            await asyncio.sleep(interval)
            try:
                await self.send_encrypted(
                    0x11, CMD_ALIASES["GET_SOFTWARE_VERSION"],
                    [(0xA1, bytes([0x21]))], label="KEEPALIVE",
                )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"  [KEEPALIVE ERROR] {e!r}")
                return

    # ── Notifications ─────────────────────────────────────────────────────────

    def _on_notify(self, _handle, raw: bytearray):
        asyncio.get_event_loop().call_soon_threadsafe(
            self._notify_queue.put_nowait, bytes(raw)
        )

    async def wait_response(self, timeout: float = 5.0) -> bytes:
        return await asyncio.wait_for(self._notify_queue.get(), timeout=timeout)

    async def recv_and_decode(self, timeout: float = 5.0) -> bytes:
        """Wait for notification, print it, decrypt if needed, return content."""
        raw = await self.wait_response(timeout)
        print(f"\n← RECV  raw={hex_str(raw)}")

        if len(raw) < 6:
            print("  (short packet — no command header)")
            return raw

        payload = raw[4 : -1]    # strip FF 09 len_le16 prefix and checksum
        pattern   = bytes(payload[0:3])
        cmd_high  = payload[3]
        cmd_low   = payload[4]
        is_enc    = bool(cmd_high & 0x40)
        is_ack    = bool(cmd_high & 0x08)
        cmd       = ((cmd_high & ~0x48) << 8) | cmd_low
        flags     = ' | '.join(filter(None, [
            "ENC"  if is_enc else "",
            "ACK"  if is_ack else ""
        ])) or "none"
        print(f"  cmd=0x{cmd:04X}  flags=[{flags}]  pattern={pattern.hex()}")

        content = payload
        if is_enc:
            key = self.session_key if self.crypto_state == "Session" else self.initial_key
            iv  = self.session_iv  if self.crypto_state == "Session" else self.initial_iv
            if key is None:
                print("  [DECRYPT_ERROR] No key available")
                return payload
            ciphertext = payload[5:]

            # Pattern 03 01 0F replies prefix the ciphertext with a 1-byte
            # fragment header: high nibble = 1-based fragment index, low
            # nibble = total fragments. We buffer per-cmd until complete.
            if pattern == b'\x03\x01\x0f' and ciphertext:
                frag_byte  = ciphertext[0]
                frag_index = (frag_byte >> 4) & 0xF
                frag_total =  frag_byte       & 0xF
                frag_data  = ciphertext[1:]
                key_cmd    = bytes([cmd_high & ~0x48, cmd_low])
                print(f"  fragment {frag_index}/{frag_total} "
                      f"({len(frag_data)} B)")
                if frag_total == 0:
                    print("  [FRAG_ERROR] total=0; treating byte as data")
                elif frag_total == 1:
                    ciphertext = frag_data
                else:
                    if key_cmd not in self._frag_buf or frag_index == 1:
                        self._frag_buf[key_cmd]   = {}
                        self._frag_total[key_cmd] = frag_total
                    self._frag_buf[key_cmd][frag_index] = frag_data
                    have = len(self._frag_buf[key_cmd])
                    if have < frag_total:
                        print(f"  buffered {have}/{frag_total} — "
                              "waiting for more")
                        return raw
                    ciphertext = b"".join(
                        self._frag_buf[key_cmd][i]
                        for i in sorted(self._frag_buf[key_cmd])
                    )
                    del self._frag_buf[key_cmd]
                    del self._frag_total[key_cmd]
                    print(f"  reassembled — {len(ciphertext)} B ciphertext")

            try:
                decrypted = aes_cbc_decrypt(key, iv, ciphertext)
                print(f"  Decrypted: {hex_str(decrypted)}")
                content = decrypted
                self._route_decrypted(cmd, decrypted)
            except Exception as e:
                print(f"  [DECRYPT_ERROR] {e}")
        else:
            tlv_offset = 6 if len(content) > 5 and content[5] == 0x00 else 5
            self._print_tlv(content, offset=tlv_offset)

        return content

    def _route_decrypted(self, cmd: int, data: bytes):
        """Route decrypted payload to the right parser.

        cmd is already stripped of ENC (0x40) and ACK (0x08) flags.
        Mapping from raw on-wire cmd bytes to stripped cmd value:
          C4 02 → 0x8402   4300 → 0x0300   C4 05 → 0x8405
        """
        offset = 1 if (data and data[0] == 0x00) else 0
        # Telemetry status packets.
        # 0x8200/0x820A = ACK response to our 0x0200/0x020A solicit (device sets bit 0x8000 + ACK flag).
        # 0x8402/0x8405 = unsolicited telemetry push (raw cmd bytes C402/C405, ENC flag stripped).
        if cmd in (0x0300, 0x0D00, 0x8200, 0x820A, 0x8402, 0x8405):
            self._parse_comprehensive_status(data, offset)
        elif cmd == 0x050E:
            self._parse_live_power(data, offset)
        elif cmd == 0x0522:
            self._parse_temperature(data, offset)
        elif cmd == 0x0022:
            self._parse_session_key_response(data, offset)
        else:
            print(f"  [unknown cmd=0x{cmd:04X} — raw TLV dump]")
            self._print_tlv(data, offset)

    # ── TLV printer ───────────────────────────────────────────────────────────

    def _print_tlv(self, payload: bytes, offset: int = 0):
        for t, v in parse_tlv(payload, offset):
            print(f"  TLV type=0x{t:02X} len={len(v):3d}  "
                  f"hex={hex_str(v)[:48]}{'…' if len(v)>24 else ''}"
                  f"  ascii={bytes_to_ascii(v)}")

    # ── Info extraction ───────────────────────────────────────────────────────

    def _extract_handshake_info(self, payload: bytes):
        for t, v in parse_tlv(payload, offset=6):
            if   t == 0xA3: self.device_info['version']       = bytes_to_ascii(v)
            elif t == 0xA4: self.device_info['serial_number'] = bytes_to_ascii(v)
            elif t == 0xA5: self.device_info['mac_address']   = ':'.join(f'{b:02X}' for b in v)
        sn = self.device_info.get('serial_number', '')
        fw = self.device_info.get('version', '?')
        mac = self.device_info.get('mac_address', '?')
        print(f"\n  ✓ Serial: {sn!r}   FW: {fw!r}   MAC: {mac}")
        if self.dashboard:
            with self.dashboard.lock:
                self.dashboard.device_info = dict(self.device_info)

    def _parse_session_key_response(self, data: bytes, offset: int):
        """
        Parse the device's response to command 0x0022 (session key exchange).
        The device returns a new AES key + IV embedded in TLV fields.
        Common layout (device-specific — adjust tags if needed):
          A3 = new session key (16 bytes)
          A4 = new session IV  (16 bytes)
        If the structure differs, enable DEBUG_MODE and inspect the hex above.
        """
        print("  [0x0022 response — session key exchange]")
        new_key = None
        new_iv  = None
        for t, v in parse_tlv(data, offset):
            print(f"  TLV 0x{t:02X}: {hex_str(v)}")
            if t == 0xA1 and len(v) == 16:
                new_key = v
                print(f"    → New session KEY (tag 0xA1): {hex_str(v)}")
            elif t == 0xA3 and len(v) == 16:
                new_key = v
                print(f"    → New session KEY (tag 0xA3): {hex_str(v)}")
            elif t == 0xA4 and len(v) == 16:
                new_iv = v
                print(f"    → New session IV  (tag 0xA4): {hex_str(v)}")

        if new_key:
            self.session_key  = new_key
            self.session_iv   = new_iv if new_iv else self.initial_iv
            self.crypto_state = "Session"
            iv_note = "new IV" if new_iv else "reusing initial IV (S/N)"
            print(f"\n  ✓ Session key active — {iv_note}")
        else:
            print("  [INFO] No session key in response — "
                  "reusing initial key+IV for session (device-specific)")
            self.session_key  = self.initial_key
            self.session_iv   = self.initial_iv
            self.crypto_state = "Session"
        if self.dashboard:
            with self.dashboard.lock:
                self.dashboard.session_state = self.crypto_state

    # ── Status parsers ────────────────────────────────────────────────────────

    @staticmethod
    def _mode_str(b: int) -> str:
        return {0: 'Not Connected', 1: 'Output', 2: 'Input'}.get(b, f'Unknown(0x{b:02X})')

    def _parse_port(self, tag: str, v: bytes):
        """Parse a port TLV value and print its status, voltage, current, and power.

        Layout per SolixBLE prime_charger_250w:
          v[1]    — connection status (0=not connected, 1=output, 2=input)
          v[2:4]  — voltage in mV (little-endian uint16 → divide by 1000 for V)
          v[4:6]  — current in mA (little-endian uint16 → divide by 1000 for A)
          v[6:8]  — power in cW  (little-endian uint16 → divide by 100 for W)
        """
        if len(v) < 8:
            print(f"  Port {tag}: (too short — {len(v)} bytes)")
            return
        status = v[1]
        mode = self._mode_str(status)
        connected = status != 0
        print(f"  Port {tag}: {mode}", end="")
        if connected:
            volts = struct.unpack_from('<H', v, 2)[0] / 1000.0
            amps  = struct.unpack_from('<H', v, 4)[0] / 1000.0
            watts = struct.unpack_from('<H', v, 6)[0] / 100.0
            print(f"  {volts:.3f} V  {amps:.3f} A  {watts:.2f} W", end="")
        print()
        if self.dashboard and tag in self.dashboard.ports:
            p = self.dashboard.ports[tag]
            with self.dashboard.lock:
                p.mode = mode
                p.connected = connected
                if connected:
                    p.volts = volts
                    p.amps  = amps
                    p.watts = watts
                else:
                    p.volts = p.amps = p.watts = 0.0

    def _parse_power_channel(self, tag: str, v: bytes):
        """Parse a 20-byte extended power channel TLV (tags AA–AE).

        Observed layout (20 bytes):
          v[0]    — type marker (0x04)
          v[1]    — connection status (0=off, 1=on/output, 2=input)
          v[2:4]  — voltage raw LE uint16 (unit TBD — divide by 100 for V)
          v[4:6]  — current raw LE uint16 (unit TBD — divide by 100 for A)
          v[6:8]  — max/rated voltage LE uint16 (same unit as v[2:4])
          v[8:10] — max/rated current LE uint16
          v[11:13]— max/rated power LE uint16 (divide by 10 for W)
        """
        if len(v) < 14:
            print(f"  Channel {tag}: (too short — {len(v)} bytes)")
            return
        status = v[1]
        mode = self._mode_str(status)
        connected = status != 0
        print(f"  Channel {tag}: {mode}", end="")
        if connected:
            volts     = struct.unpack_from('<H', v,  2)[0] / 100.0
            amps      = struct.unpack_from('<H', v,  4)[0] / 100.0
            max_volts = struct.unpack_from('<H', v,  6)[0] / 100.0
            max_amps  = struct.unpack_from('<H', v,  8)[0] / 100.0
            max_watts = struct.unpack_from('<H', v, 11)[0] / 10.0
            print(f"  {volts:.2f}V  {amps:.2f}A"
                  f"  (max {max_volts:.2f}V / {max_amps:.2f}A / {max_watts:.1f}W)", end="")
        print()
        if self.dashboard and tag in self.dashboard.channels:
            ch = self.dashboard.channels[tag]
            with self.dashboard.lock:
                ch.mode = mode
                ch.connected = connected
                if connected:
                    ch.volts      = volts
                    ch.amps       = amps
                    ch.max_volts  = max_volts
                    ch.max_amps   = max_amps
                    ch.max_watts  = max_watts
                else:
                    ch.volts = ch.amps = 0.0

    def _parse_comprehensive_status(self, data: bytes, offset: int):
        """Parse a comprehensive status packet (cmds 0x0300, 0x0D00, 0x8402, 0x8405).

        Observed TLV structure:
          0xA1        — device status/mode flag byte
          0xA2, 0xA3  — 3-byte aggregate measurements
          0xA4–0xA9   — 8-byte USB port entries (status + V/I/P)
          0xAA–0xAE   — 20-byte power channel entries (status + V/I + rated limits)
          0xB3        — temperature: v[0]=type, v[1]=°C
          0xFE        — timestamp (4-byte LE unix seconds at v[1:5])
        """
        print("  [Status]")
        usb_port_map = {
            0xA4: "USB-C1", 0xA5: "USB-C2", 0xA6: "USB-C3",
            0xA7: "USB-C4", 0xA8: "USB-A1", 0xA9: "USB-A2",
        }
        pwr_channel_map = {
            0xAA: "PWR-1", 0xAB: "PWR-2", 0xAC: "PWR-3",
            0xAD: "PWR-4", 0xAE: "PWR-5",
        }
        for t, v in parse_tlv(data, offset):
            if t == 0xA1 and len(v) >= 1:
                print(f"  Device status: 0x{v[0]:02X}")
                if self.dashboard:
                    with self.dashboard.lock:
                        self.dashboard.device_status = v[0]
            elif t in (0xA2, 0xA3) and len(v) >= 3:
                val = struct.unpack_from('<H', v, 1)[0]
                print(f"  TLV 0x{t:02X}: type=0x{v[0]:02X}  value={val}  (raw)")
            elif t in usb_port_map:
                self._parse_port(usb_port_map[t], v)
            elif t in pwr_channel_map:
                self._parse_power_channel(pwr_channel_map[t], v)
            elif t == 0xB3 and len(v) >= 2:
                print(f"  Temperature: {v[1]}°C")
                if self.dashboard:
                    with self.dashboard.lock:
                        self.dashboard.temperature = v[1]
            elif t == 0xFE and len(v) >= 5:
                ts = struct.unpack_from('<I', v, 1)[0]
                print(f"  Timestamp: {ts}")
                if self.dashboard:
                    with self.dashboard.lock:
                        self.dashboard.timestamp   = ts
                        self.dashboard.last_update = time.time()
            else:
                print(f"  TLV 0x{t:02X}: {hex_str(v)[:48]}{'…' if len(v)>24 else ''}")

    def _parse_live_power(self, data: bytes, offset: int):
        """Parse a live-power packet — same layout as comprehensive status."""
        print("  [Live power]")
        usb_port_map = {
            0xA4: "USB-C1", 0xA5: "USB-C2", 0xA6: "USB-C3",
            0xA7: "USB-C4", 0xA8: "USB-A1", 0xA9: "USB-A2",
        }
        pwr_channel_map = {
            0xAA: "PWR-1", 0xAB: "PWR-2", 0xAC: "PWR-3",
            0xAD: "PWR-4", 0xAE: "PWR-5",
        }
        for t, v in parse_tlv(data, offset):
            if t in usb_port_map:
                self._parse_port(usb_port_map[t], v)
            elif t in pwr_channel_map:
                self._parse_power_channel(pwr_channel_map[t], v)
            elif t == 0xB3 and len(v) >= 2:
                print(f"  Temperature: {v[1]}°C")
                if self.dashboard:
                    with self.dashboard.lock:
                        self.dashboard.temperature = v[1]
                        self.dashboard.last_update = time.time()
            else:
                print(f"  TLV 0x{t:02X}: {hex_str(v)[:48]}{'…' if len(v)>24 else ''}")

    def _parse_temperature(self, data: bytes, offset: int):
        print("  [Temperature]")
        self._print_tlv(data, offset)

    # ── Main sequence ─────────────────────────────────────────────────────────

    async def run(self, mac_address: str, cmds: list[int] | None = None,
                  group: int = 0x11, listen: bool = False,
                  telemetry_interval: float | None = None):
        async with BleakClient(mac_address) as client:
            self.client = client
            print(f"\n✓ Connected to {mac_address}")

            print("\n─── GATT services & characteristics ──────────────────────")
            for service in client.services:
                print(f"  Service {service.uuid}  (handle {service.handle})  {service.description}")
                for char in service.characteristics:
                    props = ','.join(char.properties)
                    print(f"    Char  {char.uuid}  (handle {char.handle})  [{props}]  {char.description}")
                    for desc in char.descriptors:
                        print(f"      Desc  {desc.uuid}  (handle {desc.handle})")
            print()

            await client.start_notify(NOTIFY_CHARACTERISTIC, self._on_notify)
            print("✓ Notifications enabled\n")

            ts = int(time.time())
            ts_bytes = struct.pack('<I', ts)
            print(f"Session UTC: {ts} → {hex_str(ts_bytes)}")

            # ── Step 1: Handshake 0x0001 ──────────────────────────────────────
            print("\n─── Step 1 / 4 : Handshake 0x0001 ─────────────────────────")
            await self.send_plain(0x01, 0x0001, [
                (0xA1, ts_bytes),
                (0xA2, A2_STATIC),
            ], label="HS-0001")
            await self.recv_and_decode()

            # ── Step 2: Handshake 0x0003 ──────────────────────────────────────
            print("\n─── Step 2 / 4 : Handshake 0x0003 ─────────────────────────")
            await self.send_plain(0x01, 0x0003, [
                (0xA1, ts_bytes),
                (0xA2, A2_STATIC),
                (0xA3, bytes([0x20])),
                (0xA4, bytes([0x00, 0xF0])),
            ], label="HS-0003")
            await self.recv_and_decode()

            # ── Step 3: Handshake 0x0029 (device info) ───────────────────────
            print("\n─── Step 3 / 4 : Info request 0x0029 ──────────────────────")
            await self.send_plain(0x01, 0x0029, [
                (0xA1, ts_bytes),
                (0xA2, A2_STATIC),
            ], label="HS-0029")
            info_resp = await self.recv_and_decode()
            self._extract_handshake_info(info_resp)

            sn = self.device_info.get('serial_number', '')
            if not sn:
                raise RuntimeError("Serial number not extracted — aborting")

            self.initial_iv = pad_iv(sn.encode('ascii'))
            print(f"  Initial IV (S/N padded): {hex_str(self.initial_iv)}")

            # ── Step 4: Handshake 0x0005 ──────────────────────────────────────
            print("\n─── Step 4 / 4 : Handshake 0x0005 ─────────────────────────")
            await self.send_plain(0x01, 0x0005, [
                (0xA1, ts_bytes),
                (0xA2, A2_STATIC),
                (0xA3, bytes([0x20])),
                (0xA4, bytes([0x00, 0xF0])),
                (0xA5, bytes([0x02])),
            ], label="HS-0005")
            await self.recv_and_decode()

            print("\n✓ Unencrypted handshake complete")

            # ── Step 5: Initial encrypted command 0x0022 ──────────────────────
            print("\n─── Initial encryption (cmd 0x0022) ────────────────────────")
            print(f"  Key: {hex_str(self.initial_key)}")
            print(f"  IV:  {hex_str(self.initial_iv)}")
            await self.send_encrypted(0x01, 0x0022, [
                (0xA1, ts_bytes),
                (0xA2, A2_STATIC),
                (0xA3, bytes(4)),     # 4 zero bytes
                (0xA5, bytes(40)),    # 40 zero bytes
            ], label="ENC-0022")

            # Wait for session key response (may take a moment)
            print("  Waiting for session key response…")
            for attempt in range(10):
                await asyncio.sleep(0.5)
                try:
                    # Drain any queued notifications
                    while not self._notify_queue.empty():
                        await self.recv_and_decode(timeout=0.1)
                except asyncio.TimeoutError:
                    pass
                if self.crypto_state == "Session":
                    break

            if self.crypto_state != "Session":
                raise RuntimeError(
                    "Timed out waiting for session key.\n"
                    "The device may use a different TLV tag for the key — "
                    "check the decrypted hex above and update _parse_session_key_response()."
                )

            # Drain anything pending before issuing commands
            while not self._notify_queue.empty():
                self._notify_queue.get_nowait()

            if telemetry_interval is not None:
                await self.solicit_telemetry()

                print(f"\n─── Polling telemetry every {telemetry_interval}s "
                      "(Ctrl-C to exit) ──")
                try:
                    loop = asyncio.get_event_loop()
                    while True:
                        deadline = loop.time() + telemetry_interval
                        # Drain any incoming notifications until the deadline.
                        while True:
                            remaining = deadline - loop.time()
                            if remaining <= 0:
                                break
                            try:
                                await self.recv_and_decode(timeout=remaining)
                            except asyncio.TimeoutError:
                                break

                        # Re-poll. 0x0200 is the lightweight probe; re-sending
                        # it triggers a fresh telemetry reply from the device.
                        ts_bytes = struct.pack('<I', int(time.time()))
                        await self.send_encrypted(0x0F, 0x0200, [
                            (0xA1, bytes([0x21])),
                            (0xFE, ts_bytes),
                        ], label="POLL")
                finally:
                    await client.stop_notify(NOTIFY_CHARACTERISTIC)
                return

            if cmds:
                for idx, cmd_id in enumerate(cmds, 1):
                    print(f"\n─── Command {idx}/{len(cmds)} 0x{cmd_id:04X} "
                          f"(group 0x{group:02X}) ──────────────")
                    payload = build_encrypted_payload(
                        group, cmd_id,
                        [(0xA1, bytes([0x21]))],
                        self.session_key, self.session_iv,
                    )
                    packet = frame_packet(payload)
                    print(f"→ SEND cmd=0x{cmd_id:04X} (encrypted)")
                    print(f"  Packet: {hex_str(packet)}")
                    await client.write_gatt_char(
                        WRITE_CHARACTERISTIC, packet, response=True,
                    )

                    # Collect any responses for up to 3 seconds of idle time
                    got_any = False
                    while True:
                        try:
                            await self.recv_and_decode(timeout=3.0)
                            got_any = True
                        except asyncio.TimeoutError:
                            break
                    if not got_any:
                        print("  (no response within 3 s)")

                if listen:
                    print("\n─── Listening for additional notifications "
                          "(Ctrl-C to exit) ──")
                    ka_task = asyncio.create_task(self._keepalive_loop())
                    try:
                        while True:
                            try:
                                await self.recv_and_decode(timeout=60.0)
                            except asyncio.TimeoutError:
                                continue
                    finally:
                        ka_task.cancel()

                await client.stop_notify(NOTIFY_CHARACTERISTIC)
                return

            # ── Step 6: Brute-force scan over command IDs ───────────────────
            print("\n─── Brute-force command-ID scan (group 0x11) ──────────────")
            hits = []
            ka_task = asyncio.create_task(self._keepalive_loop())

            for cmd_id in [x for x in range(0x0200, 0xFFFF) for _ in range (1)]:
                try:
                    payload = build_encrypted_payload(
                        0x11, cmd_id,
                        [(0xA1, bytes([0x21]))],
                        self.session_key, self.session_iv,
                    )
                    packet = frame_packet(payload)
                    await client.write_gatt_char(
                        WRITE_CHARACTERISTIC, packet, response=True,
                    )
                except Exception as e:
                    print(f"\n  ✗ Send error at cmd=0x{cmd_id:04X}: {e!r}")
                    break

                # Drain every notification that arrived; associate each one
                # with the cmd id parsed from its own packet, not the cmd we
                # just sent (responses can arrive after several more sends).
                while True:
                    try:
                        raw = await asyncio.wait_for(
                            self._notify_queue.get(), timeout=0.15,
                        )
                    except asyncio.TimeoutError:
                        break
                    if len(raw) >= 9:
                        rch  = raw[7]
                        rcl  = raw[8]
                        rcmd = ((rch & ~0x48) << 8) | rcl
                        is_enc = bool(rch & 0x40)
                    else:
                        rcmd, is_enc = -1, False
                    plain = b""
                    if is_enc:
                        ciphertext = bytes(raw[9:-1])
                        try:
                            plain = aes_cbc_decrypt(
                                self.session_key, self.session_iv, ciphertext,
                            )
                        except Exception as e:
                            plain = f"[DECRYPT_ERROR {e}]".encode()
                    hits.append((rcmd, raw, plain))
                    label = f"0x{rcmd:04X}" if rcmd >= 0 else "(short)"
                    print(f"  ★ resp cmd={label} ← {hex_str(raw)}")
                    if plain:
                        plain_repr = (hex_str(plain) if isinstance(plain, bytes)
                                                       and all(0 <= b <= 255 for b in plain)
                                                  else repr(plain))
                        print(f"      plain: {plain_repr}")

                if cmd_id % 0x0100 < 0xFF:
                    print(f"  … scanned 0x0000–0x{cmd_id:04X} ({len(hits)} hits)")

            print(f"\n✓ Probe complete — {len(hits)} responses captured")
            for c, r, p in hits:
                print(f"  0x{c:04X}: raw={hex_str(r)}")
                if p:
                    print(f"           plain={hex_str(p) if isinstance(p, bytes) else p}")

            ka_task.cancel()

            print(f"\n  Serial : {self.device_info.get('serial_number')}")
            print(f"  FW     : {self.device_info.get('version')}")
            print(f"  MAC    : {self.device_info.get('mac_address')}")

            await client.stop_notify(NOTIFY_CHARACTERISTIC)


# ── Scan helper ───────────────────────────────────────────────────────────────

def _print_adv_services(uuids: list[str]) -> None:
    if uuids:
        for u in uuids:
            print(f"          advertised: {u}")
    else:
        print(f"          (no services advertised)")


async def scan():
    print("Scanning for 3 seconds…")
    discovered = await BleakScanner.discover(timeout=3.0, return_adv=True)
    found = []
    for d, adv in discovered.values():
        uuids = [str(u).lower() for u in (adv.service_uuids or [])]
        rssi = adv.rssi if adv.rssi is not None else 0
        is_target = ADVERTISED_SERVICE_UUID in uuids or "ff09" in ' '.join(uuids)
        marker = "***" if is_target else "   "
        print(f"  {marker} {d.address}  RSSI={rssi:4}  {d.name}")
        _print_adv_services(uuids)
        if is_target:
            found.append(d)
    if found:
        print(f"\nTarget device(s) advertising 0xff09: {[d.address for d in found]}")
    else:
        print("\nNo device advertising 0xff09 found.")
    return found


async def scan_for_mac(mac: str) -> None:
    """Brief scan to print advertised services for a specific MAC."""
    print(f"Scanning 3 s for advertised services of {mac}…")
    discovered = await BleakScanner.discover(timeout=3.0, return_adv=True)
    match = next(
        ((d, adv) for d, adv in discovered.values()
         if d.address.upper() == mac.upper()),
        None,
    )
    if not match:
        print(f"  {mac} not seen in scan (device may be out of range or not advertising)")
        return
    d, adv = match
    uuids = [str(u).lower() for u in (adv.service_uuids or [])]
    rssi = adv.rssi if adv.rssi is not None else 0
    print(f"  {d.address}  RSSI={rssi:4}  {d.name}")
    _print_adv_services(uuids)


# ── Dashboard UI ─────────────────────────────────────────────────────────────

_C_HEADER  = 1   # cyan
_C_ON      = 2   # green  — output / active
_C_INPUT   = 3   # yellow — input mode
_C_OFF     = 4   # dim    — not connected
_C_WARN    = 5   # red    — error / unknown


def _init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(_C_HEADER, curses.COLOR_CYAN,    -1)
    curses.init_pair(_C_ON,     curses.COLOR_GREEN,   -1)
    curses.init_pair(_C_INPUT,  curses.COLOR_YELLOW,  -1)
    curses.init_pair(_C_OFF,    curses.COLOR_WHITE,   -1)
    curses.init_pair(_C_WARN,   curses.COLOR_RED,     -1)


def _mode_color(mode: str) -> int:
    if mode == "Output":
        return curses.color_pair(_C_ON)
    if mode == "Input":
        return curses.color_pair(_C_INPUT)
    return curses.color_pair(_C_OFF) | curses.A_DIM


def _safe_addstr(win, y: int, x: int, text: str, attr: int = 0):
    """addstr that silently ignores writes outside the window bounds."""
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x < 0 or x >= max_x:
        return
    available = max_x - x - 1
    if available <= 0:
        return
    try:
        win.addstr(y, x, text[:available], attr)
    except curses.error:
        pass


def _draw_dashboard(stdscr, state: DashboardState, mac: str):
    stdscr.erase()
    with state.lock:
        info    = dict(state.device_info)
        ports   = {k: (v.mode, v.connected, v.volts, v.amps, v.watts)
                   for k, v in state.ports.items()}
        chans   = {k: (v.mode, v.connected, v.volts, v.amps,
                       v.max_volts, v.max_amps, v.max_watts)
                   for k, v in state.channels.items()}
        temp       = state.temperature
        ts         = state.timestamp
        last_upd   = state.last_update
        sess       = state.session_state
        dev_status = state.device_status
        error      = state.error

    H = curses.color_pair(_C_HEADER) | curses.A_BOLD
    row = 0

    # ── Title bar ────────────────────────────────────────────────────────────
    sn   = info.get('serial_number', '—')
    fw   = info.get('version', '—')
    title = f" Anker BLE Dashboard   MAC: {mac}   SN: {sn}   FW: {fw}   [{sess}] "
    _safe_addstr(stdscr, row, 0, title.center(curses.COLS - 1), H)
    row += 1

    # ── Device status & last update ──────────────────────────────────────────
    upd_str = time.strftime("%H:%M:%S", time.localtime(last_upd)) if last_upd else "—"
    ts_str  = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "—"
    status_line = (f"  Device status: 0x{dev_status:02X}   "
                   f"Temp: {temp}°C   "
                   f"Device ts: {ts_str}   "
                   f"Last update: {upd_str}")
    _safe_addstr(stdscr, row, 0, status_line)
    row += 1

    # ── USB Ports ─────────────────────────────────────────────────────────────
    row += 1
    _safe_addstr(stdscr, row, 2, "USB Ports", H)
    row += 1
    _safe_addstr(stdscr, row, 2,
                 f"{'Port':<10} {'Mode':<16} {'Voltage':>9} {'Current':>9} {'Power':>9}",
                 curses.A_UNDERLINE)
    row += 1
    for name, (mode, connected, volts, amps, watts) in ports.items():
        attr = _mode_color(mode)
        line = f"  {name:<8}   {mode:<14} "
        _safe_addstr(stdscr, row, 0, line, attr)
        if connected:
            detail = f"  {volts:>7.3f} V  {amps:>7.3f} A  {watts:>7.2f} W"
            _safe_addstr(stdscr, row, len(line), detail, attr)
        row += 1

    # ── Power Channels ────────────────────────────────────────────────────────
    row += 1
    _safe_addstr(stdscr, row, 2, "Power Channels", H)
    row += 1
    _safe_addstr(stdscr, row, 2,
                 f"{'Channel':<10} {'Mode':<16} {'Voltage':>8} {'Current':>8}"
                 f"   {'Max V':>6} {'Max A':>6} {'Max W':>7}",
                 curses.A_UNDERLINE)
    row += 1
    for name, (mode, connected, volts, amps, mv, ma, mw) in chans.items():
        attr = _mode_color(mode)
        line = f"  {name:<8}   {mode:<14} "
        _safe_addstr(stdscr, row, 0, line, attr)
        if connected:
            detail = (f"  {volts:>6.2f} V  {amps:>6.2f} A"
                      f"   {mv:>5.2f}V  {ma:>5.2f}A  {mw:>6.1f}W")
            _safe_addstr(stdscr, row, len(line), detail, attr)
        row += 1

    # ── Error / footer ────────────────────────────────────────────────────────
    if error:
        row += 1
        _safe_addstr(stdscr, row, 2, f"ERROR: {error}",
                     curses.color_pair(_C_WARN) | curses.A_BOLD)
        row += 1

    footer_row = max(row + 1, curses.LINES - 1)
    _safe_addstr(stdscr, footer_row, 0,
                 " q: quit ".ljust(curses.COLS - 1),
                 curses.color_pair(_C_HEADER))

    stdscr.refresh()


def _run_dashboard_ui(stdscr, state: DashboardState, mac: str):
    """Curses main loop — runs in the main thread."""
    curses.curs_set(0)
    stdscr.nodelay(True)
    _init_colors()

    while state.running:
        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            state.running = False
            break
        _draw_dashboard(stdscr, state, mac)
        time.sleep(0.1)


def _run_ble_in_thread(session: DeviceSession, mac: str,
                       telemetry_interval: float, state: DashboardState):
    """Run the asyncio BLE session in a background thread, silencing stdout."""
    # Redirect stdout so the raw protocol dumps don't corrupt the curses screen.
    null_fd = open(os.devnull, 'w')
    old_stdout = sys.stdout
    sys.stdout = null_fd
    try:
        asyncio.run(session.run(mac, telemetry_interval=telemetry_interval))
    except Exception as e:
        with state.lock:
            state.error = f"{type(e).__name__}: {e}"
    finally:
        sys.stdout = old_stdout
        null_fd.close()
        state.running = False   # signal the curses loop to exit


# ── Entry point ───────────────────────────────────────────────────────────────

CMD_ALIASES = {
    "GET_SOFTWARE_VERSION": 0x30,
}


async def main():
    def _cmd_int(s: str) -> int:
        upper = s.upper()
        if upper in CMD_ALIASES:
            return CMD_ALIASES[upper]
        return int(s, 0)

    alias_help = ", ".join(f"{n}=0x{v:02X}" for n, v in CMD_ALIASES.items())
    parser = argparse.ArgumentParser(description="BLE device connector")
    parser.add_argument('--mac',  help="Device MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    parser.add_argument('--scan', action='store_true', help="Scan and list nearby devices")
    parser.add_argument('--cmd', type=_cmd_int, default=None, action='append',
                        help=f"Send this command after handshake and print the "
                             f"response. May be specified multiple times to send "
                             f"commands in sequence (e.g. --cmd 0xFE --cmd "
                             f"GET_SOFTWARE_VERSION). Aliases: {alias_help}")
    parser.add_argument('--group', type=_cmd_int, default=0x11,
                        help="Group byte for --cmd (default 0x11)")
    parser.add_argument('--listen', action='store_true',
                        help="After --cmd, keep the connection open and print "
                             "any further notifications (Ctrl-C to exit)")
    parser.add_argument('--telemetry', type=float, nargs='?', const=2.0,
                        default=None, metavar='N',
                        help="After handshake, send the Prime-style "
                             "telemetry-solicit commands (group 0x0F, "
                             "cmds 0x0200 + 0x020A) and then re-poll 0x0200 "
                             "every N seconds (default 2). Streams "
                             "notifications until Ctrl-C.")
    parser.add_argument('--dashboard', action='store_true',
                        help="Show a live curses dashboard of port/channel "
                             "status. Only valid together with --telemetry.")
    args = parser.parse_args()

    if args.dashboard and args.telemetry is None:
        parser.error("--dashboard requires --telemetry")

    if args.scan or not args.mac:
        found = await scan()
        if not args.mac:
            if found:
                args.mac = found[0].address
                print(f"\nAuto-selected: {args.mac}")
            else:
                sys.exit("No device found. Pass --mac AA:BB:CC:DD:EE:FF explicitly.")
    else:
        await scan_for_mac(args.mac)

    if args.dashboard:
        dash_state = DashboardState()
        session    = DeviceSession(dashboard=dash_state)
        ble_thread = threading.Thread(
            target=_run_ble_in_thread,
            args=(session, args.mac, args.telemetry, dash_state),
            daemon=True,
        )
        ble_thread.start()
        try:
            curses.wrapper(_run_dashboard_ui, dash_state, args.mac)
        finally:
            dash_state.running = False
            ble_thread.join(timeout=5)
        if dash_state.error:
            print(f"\n✗ ERROR: {dash_state.error}", file=sys.stderr)
            sys.exit(1)
        return

    session = DeviceSession()
    try:
        await session.run(args.mac, cmds=args.cmd, group=args.group,
                          listen=args.listen,
                          telemetry_interval=args.telemetry)
    except Exception as e:
        import traceback
        print(f"\n✗ ERROR: {type(e).__name__}: {e!r}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
