mod sim;
mod ui;

pub use sim::SpectreSim;

use ratatui::{Frame, style::Color};

use crate::sim::Simulation;
use sim::SpectrePhase;

impl Simulation for SpectreSim {
    fn name(&self) -> &'static str {
        "Spectre Variant 1"
    }

    fn cve(&self) -> &'static str {
        "CVE-2017-5753"
    }

    fn description(&self) -> &'static str {
        "Exploits speculative execution past a mispredicted branch to leak memory across security boundaries"
    }

    fn phase_label(&self) -> String {
        self.phase.to_string()
    }

    fn phase_color(&self) -> Color {
        match &self.phase {
            SpectrePhase::Train { .. } => Color::Yellow,
            SpectrePhase::Speculative { .. } => Color::Yellow,
            SpectrePhase::Revealed => Color::Green,
            _ => Color::Cyan,
        }
    }

    fn advance(&mut self) {
        self.step();
    }

    fn fast_forward(&mut self) {
        self.step_phase();
    }

    fn reset(&mut self) {
        *self = SpectreSim::new();
    }

    fn wants_quit(&self) -> bool {
        self.quit
    }

    fn draw(&self, frame: &mut Frame) {
        ui::draw(frame, self);
    }
}
