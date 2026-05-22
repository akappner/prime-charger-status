use anyhow::{Context, Result};
use btleplug::api::{
    Central, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use uuid::Uuid;

use crate::protocol::{ADVERTISED_SERVICE_UUID, NOTIFY_CHAR_UUID, WRITE_CHAR_UUID};

/// Return the first available Bluetooth adapter.
pub async fn get_adapter() -> Result<Adapter> {
    let manager = Manager::new().await.context("Failed to create BLE manager")?;
    manager
        .adapters()
        .await
        .context("Failed to list adapters")?
        .into_iter()
        .next()
        .context("No Bluetooth adapter found")
}

/// Scan for `duration_secs` and return all discovered peripherals.
pub async fn scan_devices(adapter: &Adapter, duration_secs: u64) -> Result<Vec<Peripheral>> {
    adapter
        .start_scan(ScanFilter::default())
        .await
        .context("Failed to start BLE scan")?;
    tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
    adapter.stop_scan().await.context("Failed to stop BLE scan")?;
    adapter
        .peripherals()
        .await
        .context("Failed to list peripherals")
}

#[allow(dead_code)]
/// Find the first peripheral advertising the Anker service UUID (`0xff09`).
/// Performs a 3-second scan and returns the first match, if any.
pub async fn find_anker_device(adapter: &Adapter) -> Result<Option<Peripheral>> {
    let target = Uuid::parse_str(ADVERTISED_SERVICE_UUID)
        .context("Invalid ADVERTISED_SERVICE_UUID")?;

    let peripherals = scan_devices(adapter, 3).await?;
    for p in peripherals {
        if let Ok(Some(props)) = p.properties().await {
            if props.services.contains(&target) {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}

/// Scan and print all discovered devices (mirrors Python `scan()`).
pub async fn scan_and_print(adapter: &Adapter) -> Result<Vec<Peripheral>> {
    let target = Uuid::parse_str(ADVERTISED_SERVICE_UUID)
        .context("Invalid ADVERTISED_SERVICE_UUID")?;

    println!("Scanning for 3 seconds…");
    let peripherals = scan_devices(adapter, 3).await?;

    let mut found = Vec::new();
    for p in &peripherals {
        let props = p.properties().await?.unwrap_or_default();
        let rssi = props.rssi.unwrap_or(0);
        let name = props.local_name.as_deref().unwrap_or("None").to_string();
        let is_target = props.services.contains(&target);
        let marker = if is_target { "***" } else { "   " };
        // On macOS btleplug uses a CoreBluetooth UUID as the ID, not a MAC.
        println!("  {marker} {id}  RSSI={rssi:4}  {name}", id = p.id());
        for svc in &props.services {
            println!("          advertised: {svc}");
        }
        if is_target {
            found.push(p.clone());
        }
    }

    if !found.is_empty() {
        let ids: Vec<_> = found.iter().map(|p| p.id().to_string()).collect();
        println!("\nTarget device(s) advertising 0xff09: {ids:?}");
    } else {
        println!("\nNo device advertising 0xff09 found.");
    }
    Ok(found)
}

// ── GATT helpers ──────────────────────────────────────────────────────────────

/// Connect to `peripheral`, discover services, subscribe to the notify
/// characteristic, and return a notification stream.
///
/// The returned stream yields raw `Vec<u8>` values via the `mpsc` sender;
/// call `connect_and_setup` and then move the peripheral + receiver into
/// `DeviceSession`.
pub async fn connect_and_setup(
    peripheral: &Peripheral,
) -> Result<impl futures::Stream<Item = btleplug::api::ValueNotification> + use<>> {
    peripheral
        .connect()
        .await
        .context("Failed to connect to peripheral")?;
    peripheral
        .discover_services()
        .await
        .context("Failed to discover GATT services")?;

    let notify_uuid =
        Uuid::parse_str(NOTIFY_CHAR_UUID).context("Invalid NOTIFY_CHAR_UUID")?;
    let chars = peripheral.characteristics();
    let notify_char = chars
        .iter()
        .find(|c| c.uuid == notify_uuid)
        .context("Notify characteristic not found")?
        .clone();

    let stream = peripheral
        .notifications()
        .await
        .context("Failed to get notification stream")?;

    peripheral
        .subscribe(&notify_char)
        .await
        .context("Failed to subscribe to notify characteristic")?;

    Ok(stream)
}

/// Write `data` to the WRITE characteristic with response.
pub async fn write_gatt(peripheral: &Peripheral, data: &[u8]) -> Result<()> {
    let write_uuid = Uuid::parse_str(WRITE_CHAR_UUID).context("Invalid WRITE_CHAR_UUID")?;
    let chars = peripheral.characteristics();
    let ch = chars
        .iter()
        .find(|c| c.uuid == write_uuid)
        .context("Write characteristic not found")?
        .clone();
    peripheral
        .write(&ch, data, WriteType::WithResponse)
        .await
        .context("GATT write failed")?;
    Ok(())
}

/// Print GATT services and characteristics (mirrors Python startup dump).
pub async fn print_gatt_services(peripheral: &Peripheral) -> Result<()> {
    println!("\n─── GATT services & characteristics ──────────────────────");
    for service in peripheral.services() {
        println!("  Service {}  {}", service.uuid, service.primary);
        for ch in &service.characteristics {
            let props: Vec<&str> = {
                let p = &ch.properties;
                let mut v = Vec::new();
                if p.contains(btleplug::api::CharPropFlags::READ) { v.push("read"); }
                if p.contains(btleplug::api::CharPropFlags::WRITE) { v.push("write"); }
                if p.contains(btleplug::api::CharPropFlags::WRITE_WITHOUT_RESPONSE) { v.push("write-no-resp"); }
                if p.contains(btleplug::api::CharPropFlags::NOTIFY) { v.push("notify"); }
                if p.contains(btleplug::api::CharPropFlags::INDICATE) { v.push("indicate"); }
                v
            };
            println!("    Char  {}  [{}]", ch.uuid, props.join(","));
        }
    }
    println!();
    Ok(())
}
