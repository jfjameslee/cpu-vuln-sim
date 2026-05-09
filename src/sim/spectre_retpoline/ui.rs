use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::sim::{CacheSlotState, InstructionState, NarrativeStyle};
use super::sim::{
    RetpolinePhase, SpectreRetpolineSim, BTB_POISON_ADDR, CACHE_MISS_CYCLES, CAPTURE_LOOP_ADDR,
};

pub(super) fn draw(frame: &mut Frame, state: &SpectreRetpolineSim) {
    let vertical = Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]);
    let [header_area, main_area] = vertical.areas(frame.area());

    let horizontal = Layout::horizontal([Constraint::Percentage(44), Constraint::Fill(1)]);
    let [left_area, right_area] = horizontal.areas(main_area);

    let right_vertical = Layout::vertical([
        Constraint::Length(8),
        Constraint::Percentage(45),
        Constraint::Fill(1),
    ]);
    let [rsb_btb_area, cache_area, log_area] = right_vertical.areas(right_area);

    render_header(frame, state, header_area);
    render_assembly(frame, state, left_area);
    render_rsb_btb(frame, state, rsb_btb_area);
    render_cache(frame, state, cache_area);
    render_log(frame, state, log_area);
}

fn render_header(frame: &mut Frame, state: &SpectreRetpolineSim, area: Rect) {
    let phase_color = match &state.phase {
        RetpolinePhase::BTBPoisoning { .. } => Color::Red,
        RetpolinePhase::ThunkEntry => Color::Yellow,
        RetpolinePhase::SafeSpeculation { .. } | RetpolinePhase::ArchResolution => Color::Cyan,
        RetpolinePhase::Blocked => Color::Green,
        _ => Color::DarkGray,
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                "  SPECTRE + RETPOLINE SIMULATOR",
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  (CVE-2017-5715)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  Phase: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                state.phase.to_string(),
                Style::default().fg(phase_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(
            "  [SPACE] step  [F] fast-forward  [R] restart  [B] back  [Q] quit",
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let block = Block::new()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn instruction_style(state: InstructionState) -> Style {
    match state {
        InstructionState::Upcoming => Style::default().fg(Color::White),
        InstructionState::SpeculativelyExecuting => {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        }
        InstructionState::Retired => Style::default().fg(Color::Green),
        InstructionState::Faulted => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        InstructionState::Squashed => Style::default().fg(Color::Red).add_modifier(Modifier::DIM),
    }
}

fn render_assembly(frame: &mut Frame, state: &SpectreRetpolineSim, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled("\u{25a0} upcoming  ", Style::default().fg(Color::White)),
        Span::styled("\u{25a0} speculative  ", Style::default().fg(Color::Yellow)),
        Span::styled("\u{25a0} retired  ", Style::default().fg(Color::Green)),
        Span::styled(
            "\u{25a0} squashed",
            Style::default().fg(Color::Red).add_modifier(Modifier::DIM),
        ),
    ]));
    lines.push(Line::from(""));

    for (idx, instr) in state.gadget.iter().enumerate() {
        if instr.mnemonic == ";;" {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!("  {:#018x}  {}", instr.address, instr.operands),
                    Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
                ),
            ]));
            continue;
        }

        let is_current = idx == state.current_pc
            && instr.state == InstructionState::SpeculativelyExecuting;

        let pc_marker = if is_current {
            Span::styled(
                "\u{2192} ",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("  ")
        };

        let style = instruction_style(instr.state);
        let addr_span = Span::styled(format!("{:#018x}", instr.address), style.fg(Color::DarkGray));
        let mnem_span = Span::styled(format!("  {:<6}", instr.mnemonic), style);
        let ops_span = Span::styled(format!("{:<28}", instr.operands), style);
        let comment_span =
            Span::styled(format!("; {}", instr.comment), Style::default().fg(Color::DarkGray));

        lines.push(Line::from(vec![
            pc_marker,
            addr_span,
            mnem_span,
            ops_span,
            comment_span,
        ]));
    }

    lines.push(Line::from(""));

    match &state.phase {
        RetpolinePhase::BTBPoisoning { .. } => {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    " \u{26a1} BTB being poisoned \u{2014} attacker spraying {BTB_POISON_ADDR:#018x}"
                ),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )]));
        }
        RetpolinePhase::SafeSpeculation { .. } => {
            lines.push(Line::from(vec![Span::styled(
                format!(
                    " \u{2713} Speculation trapped in capture_loop ({CAPTURE_LOOP_ADDR:#018x}) \u{2014} attacker gadget unreachable"
                ),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )]));
        }
        RetpolinePhase::ArchResolution | RetpolinePhase::TimingProbe { .. } => {
            lines.push(Line::from(vec![Span::styled(
                " \u{2713} Speculative path squashed \u{2014} no secret access occurred",
                Style::default().fg(Color::Cyan),
            )]));
        }
        RetpolinePhase::Blocked => {
            lines.push(Line::from(vec![Span::styled(
                " \u{2713} RETPOLINE blocked the attack \u{2014} cache timing shows zero leakage",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )]));
        }
        _ => {}
    }

    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Assembly (RETPOLINE Thunk) ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_rsb_btb(frame: &mut Frame, state: &SpectreRetpolineSim, area: Rect) {
    let rsb_color = if state.speculation_blocked { Color::Green } else { Color::DarkGray };
    let rsb_label = if state.rsb_top == 0 {
        "(not yet loaded)".into()
    } else {
        format!("{:#018x}  (capture_loop)", state.rsb_top)
    };

    let summary_line = if state.speculation_blocked {
        Line::from(vec![Span::styled(
            "  CPU speculates to RSB top, NOT BTB entry \u{2014} attack blocked",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )])
    } else {
        Line::from(vec![Span::styled(
            "  BTB poisoned \u{2014} awaiting thunk entry...",
            Style::default().fg(Color::Yellow),
        )])
    };

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  BTB entry:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:#018x}", state.btb_poisoned_addr),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  \u{2190} attacker-controlled", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  RSB top:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(rsb_label, Style::default().fg(rsb_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        summary_line,
    ];

    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " RSB vs BTB \u{2014} Branch Predictor State ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn cache_slot_char(slot: CacheSlotState) -> (&'static str, Color) {
    match slot {
        CacheSlotState::Cached => ("\u{2588}", Color::Blue),
        CacheSlotState::Evicted => ("\u{2591}", Color::DarkGray),
        CacheSlotState::Hit => ("\u{2588}", Color::Green),
    }
}

fn render_cache(frame: &mut Frame, state: &SpectreRetpolineSim, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("\u{2591} evicted", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "   (all slots expected cold \u{2014} no speculative access)",
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    let mut header_spans = vec![Span::raw("     ")];
    for col in (0..32usize).step_by(4) {
        header_spans.push(Span::styled(
            format!("{col:02X}  "),
            Style::default().fg(Color::DarkGray),
        ));
    }
    lines.push(Line::from(header_spans));

    for row in 0..8usize {
        let mut spans = vec![Span::styled(
            format!(" {:02X}  ", row * 32),
            Style::default().fg(Color::DarkGray),
        )];
        for col in 0..32usize {
            let idx = row * 32 + col;
            let (ch, color) = cache_slot_char(state.cache[idx]);
            spans.push(Span::styled(ch, Style::default().fg(color)));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));

    let probed = state.reload_timings.iter().filter(|t| t.is_some()).count();
    let all_miss = state.reload_timings.iter().filter(|t| **t == Some(CACHE_MISS_CYCLES)).count();

    if probed == 256 {
        lines.push(Line::from(vec![Span::styled(
            format!(" All {all_miss}/256 slots: CACHE MISS \u{2014} RETPOLINE prevented cache side-channel"),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )]));
    } else if probed > 0 {
        lines.push(Line::from(vec![Span::styled(
            format!(" Scanning: {probed}/256 slots probed \u{2014} all cold so far"),
            Style::default().fg(Color::Cyan),
        )]));
    } else {
        lines.push(Line::from(vec![Span::styled(
            " Waiting to begin Flush+Reload timing probe...",
            Style::default().fg(Color::DarkGray),
        )]));
    }

    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " L3 Cache State \u{2014} Probe Array (256 slots \u{d7} 512 B) ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_log(frame: &mut Frame, state: &SpectreRetpolineSim, area: Rect) {
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Event Log ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));

    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let log_height = inner_area.height as usize;
    let skip = state.narrative.len().saturating_sub(log_height);
    let log_lines: Vec<Line> = state
        .narrative
        .iter()
        .skip(skip)
        .map(|entry| {
            let style = match entry.style {
                NarrativeStyle::Info => Style::default().fg(Color::Gray),
                NarrativeStyle::Warning => Style::default().fg(Color::Yellow),
                NarrativeStyle::Success => {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                }
                NarrativeStyle::Critical => {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                }
            };
            Line::from(Span::styled(format!(" {}", entry.text), style))
        })
        .collect();

    frame.render_widget(
        Paragraph::new(log_lines).wrap(Wrap { trim: false }),
        inner_area,
    );
}
