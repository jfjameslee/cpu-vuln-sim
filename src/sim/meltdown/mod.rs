mod sim;
mod ui;

pub use sim::MeltdownSim;

use ratatui::{Frame, style::Color};

use crate::sim::Simulation;
use sim::SimPhase;

impl Simulation for MeltdownSim {
    fn name(&self) -> &'static str {
        "Meltdown"
    }

    fn cve(&self) -> &'static str {
        "CVE-2017-5754"
    }

    fn description(&self) -> &'static str {
        "Exploits out-of-order execution past a page fault to read kernel memory from user space"
    }

    fn phase_label(&self) -> String {
        self.phase.to_string()
    }

    fn phase_color(&self) -> Color {
        match &self.phase {
            SimPhase::Speculative { .. } => Color::Yellow,
            SimPhase::Revealed => Color::Green,
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
        *self = MeltdownSim::new();
    }

    fn wants_quit(&self) -> bool {
        self.quit
    }

    fn draw(&self, frame: &mut Frame) {
        ui::draw(frame, self);
    }
}
