mod ble;
mod cli;
mod crypto;
mod parser;
mod protocol;
mod server;
mod session;
mod state;
mod ui;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use btleplug::api::Peripheral as _;
use clap::Parser;

use crate::cli::Args;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    if args.dashboard && args.telemetry.is_none() && args.server.is_none() {
        bail!("--dashboard requires --telemetry or --server");
    }

    let adapter = ble::get_adapter().await?;

    // ── Scan-only mode ────────────────────────────────────────────────────────
    if args.scan && args.mac.is_none() {
        let found = ble::scan_and_print(&adapter).await?;
        if found.is_empty() {
            eprintln!("No Anker device found.");
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── Find the target device ────────────────────────────────────────────────
    let peripheral = if let Some(ref id) = args.mac {
        let all = ble::scan_devices(&adapter, 3).await?;
        all.into_iter()
            .find(|p| p.id().to_string().eq_ignore_ascii_case(id))
            .with_context(|| format!("Device '{id}' not found in scan"))?
    } else {
        println!("Scanning for Anker device…");
        let found = ble::scan_and_print(&adapter).await?;
        found.into_iter().next().context(
            "No Anker device found. Pass --mac <address> to specify one explicitly.",
        )?
    };

    let device_id = peripheral.id().to_string();
    println!("\nAuto-selected: {device_id}");

    let shared = state::new_shared();

    // ── REST server (optional) ────────────────────────────────────────────────
    if let Some(addr) = args.server {
        let state_srv = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(e) = server::run_server(addr, state_srv).await {
                eprintln!("REST server error: {e:#}");
            }
        });
    }

    // --server alone implies telemetry at the default interval.
    let effective_telemetry = if args.telemetry.is_none() && args.server.is_some() && !args.dashboard {
        Some(2.0f64)
    } else {
        args.telemetry
    };

    // ── Dashboard mode ────────────────────────────────────────────────────────
    if args.dashboard {
        let interval = effective_telemetry.unwrap_or(2.0);
        let state_ble = Arc::clone(&shared);
        let verbose = args.verbose;

        // The BLE task signals here once the handshake is done.
        let ready = Arc::new(tokio::sync::Notify::new());
        let ready_ble = Arc::clone(&ready);

        let ble_handle = tokio::spawn(async move {
            let mut sess = session::DeviceSession::new(peripheral, state_ble, verbose)
                .await
                .expect("BLE setup failed");
            if let Err(e) = sess.run_telemetry(interval, Some(ready_ble)).await {
                eprintln!("\n✗ BLE error: {e:#}");
            }
        });

        // Block here until the handshake is complete, then open the dashboard.
        ready.notified().await;
        ui::run_dashboard(shared, device_id).await?;
        ble_handle.abort();
        return Ok(());
    }

    // ── Telemetry streaming mode ──────────────────────────────────────────────
    let mut sess =
        session::DeviceSession::new(peripheral, Arc::clone(&shared), args.verbose).await?;

    if let Some(interval) = effective_telemetry {
        sess.run_telemetry(interval, None).await?;
        return Ok(());
    }

    // ── Command mode ─────────────────────────────────────────────────────────
    if !args.cmds.is_empty() {
        sess.run_commands(args.cmds, args.group as u8, args.listen)
            .await?;
        return Ok(());
    }

    // ── Default: brute-force scan ─────────────────────────────────────────────
    sess.run_scan().await?;
    Ok(())
}
