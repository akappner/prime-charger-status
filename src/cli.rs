use clap::Parser;

fn parse_cmd_id(s: &str) -> Result<u16, String> {
    let upper = s.to_uppercase();
    if upper == "GET_SOFTWARE_VERSION" {
        return Ok(0x0030);
    }
    u16::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .or_else(|_| s.parse::<u16>())
        .map_err(|_| format!("'{s}' is not a valid command ID (use hex 0xNNNN or decimal)"))
}

#[derive(Parser, Debug)]
#[command(
    name = "ankerstatus",
    about = "Anker PowerStation BLE monitor",
    long_about = "Connects to an Anker power device via BLE, performs the encrypted handshake, \
                  and displays live telemetry."
)]
pub struct Args {
    /// Device MAC address or CoreBluetooth UUID (e.g. AA:BB:CC:DD:EE:FF).
    /// If omitted, auto-selects the first device advertising service 0xff09.
    #[arg(long)]
    pub mac: Option<String>,

    /// Scan for nearby devices and print them, then exit.
    #[arg(long)]
    pub scan: bool,

    /// Send this command after handshake and print the response.
    /// May be repeated (e.g. --cmd 0xFE --cmd GET_SOFTWARE_VERSION).
    #[arg(long = "cmd", value_parser = parse_cmd_id, action = clap::ArgAction::Append)]
    pub cmds: Vec<u16>,

    /// Group byte for --cmd (default 0x11).
    #[arg(long, default_value = "0x11", value_parser = parse_cmd_id)]
    pub group: u16,

    /// After --cmd, keep the connection open and print further notifications.
    #[arg(long)]
    pub listen: bool,

    /// After handshake, poll telemetry every N seconds (default 2.0).
    /// Pass without a value to use the default: --telemetry
    #[arg(long, default_missing_value = "2.0", num_args = 0..=1)]
    pub telemetry: Option<f64>,

    /// Show a live ratatui dashboard. Requires --telemetry.
    #[arg(long)]
    pub dashboard: bool,

    /// Serve a JSON REST API on this address (e.g. 0.0.0.0:8888).
    /// Implies --telemetry if neither --telemetry nor --dashboard is given.
    #[arg(long)]
    pub server: Option<std::net::SocketAddr>,

    /// Print raw protocol traffic (hex dumps, TLV dumps, etc.).
    #[arg(short, long)]
    pub verbose: bool,
}
