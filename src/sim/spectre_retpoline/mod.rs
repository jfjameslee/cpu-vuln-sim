mod sim;
mod ui;

pub use sim::SpectreRetpolineSim;

use ratatui::{Frame, style::Color};

use crate::sim::Simulation;
use sim::RetpolinePhase;

impl Simulation for SpectreRetpolineSim {
    fn name(&self) -> &'static str {
        "Spectre + RETPOLINE"
    }

    fn cve(&self) -> &'static str {
        "CVE-2017-5715"
    }

    fn description(&self) -> &'static str {
        "Branch Target Injection blocked by RETPOLINE \u{2014} speculation diverted to safe pause/lfence loop"
    }

    fn phase_label(&self) -> String {
        self.phase.to_string()
    }

    fn phase_color(&self) -> Color {
        match &self.phase {
            RetpolinePhase::BTBPoisoning { .. } => Color::Red,
            RetpolinePhase::ThunkEntry => Color::Yellow,
            RetpolinePhase::SafeSpeculation { .. } => Color::Cyan,
            RetpolinePhase::ArchResolution => Color::Cyan,
            RetpolinePhase::Blocked => Color::Green,
            _ => Color::DarkGray,
        }
    }

    fn advance(&mut self) {
        self.step();
    }

    fn fast_forward(&mut self) {
        self.step_phase();
    }

    fn reset(&mut self) {
        *self = SpectreRetpolineSim::new();
    }

    fn wants_quit(&self) -> bool {
        self.quit
    }

    fn draw(&self, frame: &mut Frame) {
        ui::draw(frame, self);
    }
}
