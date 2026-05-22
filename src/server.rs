use std::net::SocketAddr;

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use crate::state::SharedState;

#[derive(Serialize)]
struct DeviceInfoJson {
    serial: String,
    firmware: String,
    mac: String,
}

#[derive(Serialize)]
struct PortJson {
    name: String,
    mode: String,
    volts: f32,
    amps: f32,
    watts: f32,
}

#[derive(Serialize)]
struct ChannelJson {
    name: String,
    mode: String,
    volts: f32,
    amps: f32,
    max_volts: f32,
    max_amps: f32,
    max_watts: f32,
}

#[derive(Serialize)]
struct StatusResponse {
    session_phase: String,
    device_status: u8,
    temperature: i32,
    device_ts: u32,
    secs_since_update: Option<f64>,
    device_info: DeviceInfoJson,
    ports: Vec<PortJson>,
    channels: Vec<ChannelJson>,
    error: Option<String>,
}

async fn get_status(State(state): State<SharedState>) -> Json<StatusResponse> {
    let s = state.lock().await;
    Json(StatusResponse {
        session_phase: s.session_phase.as_str().to_string(),
        device_status: s.device_status,
        temperature: s.temperature,
        device_ts: s.device_ts,
        secs_since_update: s.secs_since_update(),
        device_info: DeviceInfoJson {
            serial: s.device_info.serial.clone(),
            firmware: s.device_info.firmware.clone(),
            mac: s.device_info.mac.clone(),
        },
        ports: s
            .ports
            .iter()
            .map(|p| PortJson {
                name: p.name.to_string(),
                mode: p.mode.as_str().to_string(),
                volts: p.volts,
                amps: p.amps,
                watts: p.watts,
            })
            .collect(),
        channels: s
            .channels
            .iter()
            .map(|ch| ChannelJson {
                name: ch.name.to_string(),
                mode: ch.mode.as_str().to_string(),
                volts: ch.volts,
                amps: ch.amps,
                max_volts: ch.max_volts,
                max_amps: ch.max_amps,
                max_watts: ch.max_watts,
            })
            .collect(),
        error: s.error.clone(),
    })
}

pub async fn run_server(addr: SocketAddr, state: SharedState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/status", get(get_status))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("REST server listening on http://{addr}/status");
    axum::serve(listener, app).await?;
    Ok(())
}
