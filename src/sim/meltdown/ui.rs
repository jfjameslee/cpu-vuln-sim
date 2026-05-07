use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::sim::{CacheSlotState, InstructionState, NarrativeStyle, RegisterValue};
use super::sim::{
    MeltdownSim, SimPhase, CACHE_HIT_CYCLES, CACHE_MISS_CYCLES, KERNEL_SECRET_ADDR,
    PROBE_ARRAY_BASE,
};

pub(super) fn draw(frame: &mut Frame, state: &MeltdownSim) {
    let vertical = Layout::vertical([Constraint::Length(4), Constraint::Fill(1)]);
    let [header_area, main_area] = vertical.areas(frame.area());

    let horizontal = Layout::horizontal([Constraint::Percentage(42), Constraint::Fill(1)]);
    let [left_area, right_area] = horizontal.areas(main_area);

    let right_vertical = Layout::vertical([Constraint::Percentage(48), Constraint::Fill(1)]);
    let [cache_area, status_area] = right_vertical.areas(right_area);

    render_header(frame, state, header_area);
    render_assembly(frame, state, left_area);
    render_cache(frame, state, cache_area);
    render_status(frame, state, status_area);
}

fn render_header(frame: &mut Frame, state: &MeltdownSim, area: ratatui::layout::Rect) {
    let phase_color = match &state.phase {
        SimPhase::Speculative { .. } => Color::Yellow,
        SimPhase::Revealed => Color::Green,
        _ => Color::Cyan,
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                "  MELTDOWN VULNERABILITY SIMULATOR",
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  (CVE-2017-5754)", Style::default().fg(Color::DarkGray)),
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

fn render_assembly(frame: &mut Frame, state: &MeltdownSim, area: ratatui::layout::Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled("\u{25a0} upcoming  ", Style::default().fg(Color::White)),
        Span::styled("\u{25a0} speculative  ", Style::default().fg(Color::Yellow)),
        Span::styled("\u{25a0} retired  ", Style::default().fg(Color::Green)),
        Span::styled(
            "\u{25a0} faulted  ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "\u{25a0} squashed",
            Style::default().fg(Color::Red).add_modifier(Modifier::DIM),
        ),
    ]));
    lines.push(Line::from(""));

    for (idx, instr) in state.gadget.iter().enumerate() {
        let is_current = idx == state.registers.current_pc
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

        if instr.mnemonic == ";;" {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!(
                        "  {:#018x}  {} {}",
                        instr.address, instr.mnemonic, instr.operands
                    ),
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD | Modifier::ITALIC),
                ),
            ]));
            continue;
        }

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
        SimPhase::Speculative { step } if *step > 0 => {
            lines.push(Line::from(vec![Span::styled(
                " \u{26a1} Speculative window active \u{2014} CPU executing past #PF fault",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )]));
        }
        SimPhase::Reload { .. } | SimPhase::Revealed => {
            lines.push(Line::from(vec![Span::styled(
                " \u{2717} ROB squashed \u{2014} registers rolled back, cache persists",
                Style::default().fg(Color::Red),
            )]));
        }
        _ => {}
    }

    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Assembly ",
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

fn render_cache(frame: &mut Frame, state: &MeltdownSim, area: ratatui::layout::Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::raw(" "),
        Span::styled("\u{2588} cached", Style::default().fg(Color::Blue)),
        Span::raw("   "),
        Span::styled("\u{2591} evicted", Style::default().fg(Color::DarkGray)),
        Span::raw("   "),
        Span::styled(
            "\u{2588} HIT",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  (probe_array[secret\u{d7}4096])",
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
        let secret = state.secret_byte as usize;
        if secret / 32 == row {
            let col = secret % 32;
            spans.push(Span::styled(
                format!("  \u{2190} slot 0x{secret:02X} (col {col})"),
                Style::default().fg(if state.cache[secret] == CacheSlotState::Hit {
                    Color::Green
                } else {
                    Color::DarkGray
                }),
            ));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));

    let hit_count = state
        .reload_timings
        .iter()
        .filter(|t| **t == Some(CACHE_HIT_CYCLES))
        .count();
    if hit_count > 0 {
        lines.push(Line::from(vec![Span::styled(
            format!(
                " CACHE HIT at slot 0x{:02X} ('{}')  \u{2014} {} cycles vs ~{} cycles for misses",
                state.secret_byte,
                char::from_u32(state.secret_byte as u32).unwrap_or('?'),
                CACHE_HIT_CYCLES,
                CACHE_MISS_CYCLES,
            ),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )]));
    } else {
        let probed: usize = state.reload_timings.iter().filter(|t| t.is_some()).count();
        if probed > 0 {
            lines.push(Line::from(vec![Span::styled(
                format!(" Probed {probed}/256 slots... measuring access times"),
                Style::default().fg(Color::DarkGray),
            )]));
        } else {
            lines.push(Line::from(vec![Span::styled(
                " Waiting to begin Reload+Timing phase...",
                Style::default().fg(Color::DarkGray),
            )]));
        }
    }

    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " L3 Cache State \u{2014} Probe Array (256 slots) ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn register_spans(label: &'static str, value: &RegisterValue) -> Line<'static> {
    let (val_str, val_color) = match value {
        RegisterValue::Known(v) => (format!("0x{v:016x}"), Color::Cyan),
        RegisterValue::Speculative(s) => (s.clone(), Color::Yellow),
        RegisterValue::Cleared => ("\u{2014}".into(), Color::DarkGray),
    };
    let suffix = match value {
        RegisterValue::Speculative(_) => Span::styled(
            "  (speculative)",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::DIM),
        ),
        RegisterValue::Cleared => {
            Span::styled("  (rolled back)", Style::default().fg(Color::DarkGray))
        }
        _ => Span::raw(""),
    };
    Line::from(vec![
        Span::styled(format!("  {label}: "), Style::default().fg(Color::DarkGray)),
        Span::styled(val_str, Style::default().fg(val_color).add_modifier(Modifier::BOLD)),
        suffix,
    ])
}

fn render_status(frame: &mut Frame, state: &MeltdownSim, area: ratatui::layout::Rect) {
    let inner = Layout::vertical([Constraint::Length(12), Constraint::Fill(1)]);
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            " Memory Map & Status ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));

    let inner_area = block.inner(area);
    frame.render_widget(block, area);

    let [map_area, log_area] = inner.areas(inner_area);

    let secret_val_spans: Vec<Span> = if state.secret_revealed {
        vec![
            Span::styled(
                format!(
                    "0x{:02X} ('{}')",
                    state.secret_byte,
                    char::from_u32(state.secret_byte as u32).unwrap_or('?')
                ),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  \u{2190} RECOVERED!", Style::default().fg(Color::Green)),
        ]
    } else {
        vec![Span::styled(
            "???",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )]
    };

    let mut map_lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                " KERNEL SPACE",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  0xFFFF800000000000", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(
            vec![
                Span::styled("   [secret_byte]  ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{KERNEL_SECRET_ADDR:#018x}"),
                    Style::default().fg(Color::Red),
                ),
                Span::raw("  =  "),
            ]
            .into_iter()
            .chain(secret_val_spans)
            .collect::<Vec<_>>(),
        ),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " USER SPACE   ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  0x0000000000000000", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("   probe_array     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{PROBE_ARRAY_BASE:#018x}"),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled("  (256 \u{d7} 4096 B)", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            " Registers:",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        register_spans("RAX", &state.registers.rax),
        register_spans("RBX", &state.registers.rbx),
        Line::from(vec![
            Span::styled("  RIP: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:#018x}", state.gadget[state.registers.current_pc].address),
                Style::default().fg(Color::Cyan),
            ),
        ]),
    ];

    if let SimPhase::Reload { step } = &state.phase {
        let probed = state.reload_timings.iter().filter(|t| t.is_some()).count();
        map_lines.push(Line::from(vec![Span::styled(
            format!(" Timing: probed {probed}/256 slots (at 0x{step:02X})"),
            Style::default().fg(Color::DarkGray),
        )]));
    }

    frame.render_widget(
        Paragraph::new(map_lines).wrap(Wrap { trim: false }),
        map_area,
    );

    let log_height = log_area.height.saturating_sub(2) as usize;
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

    let log_block = Block::new()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(" Event Log ", Style::default().fg(Color::DarkGray)));

    frame.render_widget(
        Paragraph::new(log_lines).block(log_block).wrap(Wrap { trim: false }),
        log_area,
    );
}
