use std::sync::Arc;
use std::time::{Instant, UNIX_EPOCH};
use tokio::sync::Mutex;

// ── Connection mode ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ConnectionMode {
    #[default]
    NotConnected,
    Output,
    Input,
}

impl ConnectionMode {
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Output,
            2 => Self::Input,
            _ => Self::NotConnected,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotConnected => "Not Connected",
            Self::Output => "Output",
            Self::Input => "Input",
        }
    }
}

// ── Port and channel state ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct PortState {
    pub name: &'static str,
    pub mode: ConnectionMode,
    pub volts: f32,
    pub amps: f32,
    pub watts: f32,
}

#[derive(Debug, Clone, Default)]
pub struct ChannelState {
    pub name: &'static str,
    pub mode: ConnectionMode,
    pub volts: f32,
    pub amps: f32,
    pub max_volts: f32,
    pub max_amps: f32,
    pub max_watts: f32,
}

// ── Device info ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub serial: String,
    pub firmware: String,
    pub mac: String,
}

// ── Session phase ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Default)]
pub enum SessionPhase {
    #[default]
    Inactive,
    #[allow(dead_code)]
    Connecting,
    Handshake,
    Session,
    #[allow(dead_code)]
    Error,
}

impl SessionPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inactive => "INACTIVE",
            Self::Connecting => "CONNECTING",
            Self::Handshake => "HANDSHAKE",
            Self::Session => "SESSION",
            Self::Error => "ERROR",
        }
    }
}

// ── Dashboard state ───────────────────────────────────────────────────────────

pub const PORT_NAMES: [&str; 6] = ["USB-C1", "USB-C2", "USB-C3", "USB-C4", "USB-A1", "USB-A2"];
pub const CHANNEL_NAMES: [&str; 5] = ["PWR-1", "PWR-2", "PWR-3", "PWR-4", "PWR-5"];

#[derive(Debug, Clone)]
pub struct DashboardState {
    pub session_phase: SessionPhase,
    pub device_status: u8,
    pub temperature: i32,
    pub device_ts: u32,
    pub last_update: Option<Instant>,
    pub device_info: DeviceInfo,
    pub error: Option<String>,
    /// USB ports: indices 0–5 → USB-C1..C4, USB-A1..A2
    pub ports: [PortState; 6],
    /// Power channels: indices 0–4 → PWR-1..5
    pub channels: [ChannelState; 5],
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            session_phase: SessionPhase::default(),
            device_status: 0,
            temperature: 0,
            device_ts: 0,
            last_update: None,
            device_info: DeviceInfo::default(),
            error: None,
            ports: std::array::from_fn(|i| PortState {
                name: PORT_NAMES[i],
                ..Default::default()
            }),
            channels: std::array::from_fn(|i| ChannelState {
                name: CHANNEL_NAMES[i],
                ..Default::default()
            }),
        }
    }
}

impl DashboardState {
    /// Format the device timestamp as HH:MM:SS, or "—" if not yet set.
    pub fn device_ts_str(&self) -> String {
        if self.device_ts == 0 {
            return "—".to_string();
        }
        let d = std::time::Duration::from_secs(self.device_ts as u64);
        let epoch = UNIX_EPOCH + d;
        let dt: chrono::DateTime<chrono::Local> = epoch.into();
        dt.format("%H:%M:%S").to_string()
    }

    /// Seconds since last telemetry update, or None.
    pub fn secs_since_update(&self) -> Option<f64> {
        self.last_update.map(|t| t.elapsed().as_secs_f64())
    }
}

// ── Shared state alias ────────────────────────────────────────────────────────

pub type SharedState = Arc<Mutex<DashboardState>>;

pub fn new_shared() -> SharedState {
    Arc::new(Mutex::new(DashboardState::default()))
}
