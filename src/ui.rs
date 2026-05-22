use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::state::{ConnectionMode, DashboardState, SharedState};

pub async fn run_dashboard(state: SharedState, device_id: String) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = dashboard_loop(&mut terminal, state, device_id).await;
    ratatui::restore();
    result
}

async fn dashboard_loop(
    terminal: &mut ratatui::DefaultTerminal,
    state: SharedState,
    device_id: String,
) -> Result<()> {
    loop {
        // Snapshot state quickly to minimize lock hold time.
        let snapshot = state.lock().await.clone();

        terminal.draw(|frame| render(frame, &snapshot, &device_id))?;

        // Non-blocking keyboard event check.
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc) {
                    break;
                }
            }
        }

        // Yield to tokio so the BLE task makes progress.
        tokio::task::yield_now().await;
    }
    Ok(())
}

fn render(frame: &mut Frame, state: &DashboardState, device_id: &str) {
    let area = frame.area();

    // ── Layout: title / status / ports / channels / footer ───────────────────
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Length(1), // status bar
            Constraint::Length(1), // spacer
            Constraint::Length(8), // USB ports (header + 6 rows + borders)
            Constraint::Length(1), // spacer
            Constraint::Min(8),    // power channels
            Constraint::Length(1), // footer
        ])
        .split(area);

    let header_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

    // ── Title ─────────────────────────────────────────────────────────────────
    let sn = if state.device_info.serial.is_empty() {
        "—".to_string()
    } else {
        state.device_info.serial.clone()
    };
    let fw = if state.device_info.firmware.is_empty() {
        "—".to_string()
    } else {
        state.device_info.firmware.clone()
    };
    let title = format!(
        " Anker BLE Dashboard   ID: {}   SN: {}   FW: {}   [{}] ",
        device_id,
        sn,
        fw,
        state.session_phase.as_str()
    );
    let title_widget = Paragraph::new(title)
        .style(header_style)
        .alignment(Alignment::Center);
    frame.render_widget(title_widget, chunks[0]);

    // ── Status bar ────────────────────────────────────────────────────────────
    let upd_str = state
        .secs_since_update()
        .map(|s| format!("{s:.1}s ago"))
        .unwrap_or_else(|| "—".to_string());
    let ts_str = state.device_ts_str();
    let status_line = format!(
        "  Status: 0x{:02X}   Temp: {}°C   Device ts: {}   Last update: {}",
        state.device_status, state.temperature, ts_str, upd_str
    );
    if let Some(ref err) = state.error {
        let err_widget = Paragraph::new(format!("  ERROR: {err}"))
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
        frame.render_widget(err_widget, chunks[1]);
    } else {
        frame.render_widget(Paragraph::new(status_line), chunks[1]);
    }

    // ── USB Ports table ───────────────────────────────────────────────────────
    let port_header = Row::new(vec![
        Cell::from("Port").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Mode").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Voltage").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Current").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Power").style(Style::default().add_modifier(Modifier::UNDERLINED)),
    ]);

    let port_rows: Vec<Row> = state
        .ports
        .iter()
        .map(|p| {
            let style = mode_style(&p.mode);
            let (v, a, w) = if p.mode != ConnectionMode::NotConnected {
                (
                    format!("{:.3} V", p.volts),
                    format!("{:.3} A", p.amps),
                    format!("{:.2} W", p.watts),
                )
            } else {
                (String::new(), String::new(), String::new())
            };
            Row::new(vec![
                Cell::from(p.name),
                Cell::from(p.mode.as_str()),
                Cell::from(v),
                Cell::from(a),
                Cell::from(w),
            ])
            .style(style)
        })
        .collect();

    let port_table = Table::new(
        std::iter::once(port_header).chain(port_rows),
        [
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" USB Ports ")
            .title_style(header_style),
    );
    frame.render_widget(port_table, chunks[3]);

    // ── Power Channels table ──────────────────────────────────────────────────
    let ch_header = Row::new(vec![
        Cell::from("Channel").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Mode").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Voltage").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Current").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Max V").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Max A").style(Style::default().add_modifier(Modifier::UNDERLINED)),
        Cell::from("Max W").style(Style::default().add_modifier(Modifier::UNDERLINED)),
    ]);

    let ch_rows: Vec<Row> = state
        .channels
        .iter()
        .map(|ch| {
            let style = mode_style(&ch.mode);
            let (v, a, mv, ma, mw) = if ch.mode != ConnectionMode::NotConnected {
                (
                    format!("{:.2} V", ch.volts),
                    format!("{:.2} A", ch.amps),
                    format!("{:.2}", ch.max_volts),
                    format!("{:.2}", ch.max_amps),
                    format!("{:.1}", ch.max_watts),
                )
            } else {
                (
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            };
            Row::new(vec![
                Cell::from(ch.name),
                Cell::from(ch.mode.as_str()),
                Cell::from(v),
                Cell::from(a),
                Cell::from(mv),
                Cell::from(ma),
                Cell::from(mw),
            ])
            .style(style)
        })
        .collect();

    let ch_table = Table::new(
        std::iter::once(ch_header).chain(ch_rows),
        [
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(8),
        ],
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Power Channels ")
            .title_style(header_style),
    );
    frame.render_widget(ch_table, chunks[5]);

    // ── Footer ────────────────────────────────────────────────────────────────
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().fg(Color::Cyan)),
        Span::raw(": quit"),
    ]));
    frame.render_widget(footer, chunks[6]);
}

fn mode_style(mode: &ConnectionMode) -> Style {
    match mode {
        ConnectionMode::Output => Style::default().fg(Color::Green),
        ConnectionMode::Input => Style::default().fg(Color::Yellow),
        ConnectionMode::NotConnected => Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::DIM),
    }
}
