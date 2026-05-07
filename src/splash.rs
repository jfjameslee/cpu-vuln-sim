use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::sim::{Simulation, meltdown::MeltdownSim, spectre::SpectreSim};

pub struct SimDescriptor {
    pub name: &'static str,
    pub cve: &'static str,
    pub description: &'static str,
    pub constructor: fn() -> Box<dyn Simulation>,
}

static SIMULATION_CATALOG: &[SimDescriptor] = &[
    SimDescriptor {
        name: "Meltdown",
        cve: "CVE-2017-5754",
        description: "Exploits out-of-order execution past a page fault to read kernel memory from user space. Affects most pre-2018 Intel CPUs.",
        constructor: || Box::new(MeltdownSim::new()),
    },
    SimDescriptor {
        name: "Spectre Variant 1",
        cve: "CVE-2017-5753",
        description: "Exploits speculative execution past a mispredicted bounds check to leak memory across security boundaries. Affects nearly all modern CPUs.",
        constructor: || Box::new(SpectreSim::new()),
    },
];

pub struct SplashState {
    pub selected: usize,
}

impl SplashState {
    pub fn new() -> Self {
        SplashState { selected: 0 }
    }

    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn move_down(&mut self) {
        if self.selected < SIMULATION_CATALOG.len() - 1 {
            self.selected += 1;
        }
    }

    pub fn launch(&self) -> Box<dyn Simulation> {
        (SIMULATION_CATALOG[self.selected].constructor)()
    }
}

pub fn render_splash(frame: &mut Frame, state: &SplashState) {
    let area = frame.area();

    let panel_h = 20u16.min(area.height.saturating_sub(4));
    let panel_w = 74u16.min(area.width.saturating_sub(4));

    let v_pad = area.height.saturating_sub(panel_h) / 2;
    let h_pad = area.width.saturating_sub(panel_w) / 2;

    let vertical = Layout::vertical([
        Constraint::Length(v_pad),
        Constraint::Length(panel_h),
        Constraint::Fill(1),
    ]);
    let [_, center_v, _] = vertical.areas(area);

    let horizontal = Layout::horizontal([
        Constraint::Length(h_pad),
        Constraint::Length(panel_w),
        Constraint::Fill(1),
    ]);
    let [_, center, _] = horizontal.areas(center_v);

    render_panel(frame, state, center);
}

fn render_panel(frame: &mut Frame, state: &SplashState, area: Rect) {
    let mut lines: Vec<Line> = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  CPU VULNERABILITY SIMULATOR",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            "  Hardware Security Education Tool",
            Style::default().fg(Color::DarkGray),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Select a simulation:",
            Style::default().fg(Color::Gray),
        )]),
        Line::from(""),
    ];

    for (i, desc) in SIMULATION_CATALOG.iter().enumerate() {
        let selected = i == state.selected;

        let cursor = if selected {
            Span::styled(
                "  > ",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("    ")
        };

        let name_style = if selected {
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        lines.push(Line::from(vec![
            cursor,
            Span::styled(format!("{:<24}", desc.name), name_style),
            Span::styled(desc.cve, Style::default().fg(Color::DarkGray)),
        ]));

        let desc_style = if selected {
            Style::default().fg(Color::Gray)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        lines.push(Line::from(vec![
            Span::raw("      "),
            Span::styled(desc.description, desc_style),
        ]));
        lines.push(Line::from(""));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "  [\u{2191}\u{2193}] navigate   [ENTER] launch   [Q] quit",
        Style::default().fg(Color::DarkGray),
    )]));

    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}
