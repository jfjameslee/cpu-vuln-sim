use std::fmt;

pub mod meltdown;
pub mod spectre;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSlotState {
    Cached,
    Evicted,
    Hit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionState {
    Upcoming,
    SpeculativelyExecuting,
    Retired,
    Faulted,
    Squashed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RegisterValue {
    Known(u64),
    Speculative(String),
    Cleared,
}

impl fmt::Display for RegisterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterValue::Known(v) => write!(f, "0x{v:016x}"),
            RegisterValue::Speculative(s) => write!(f, "{s}"),
            RegisterValue::Cleared => write!(f, "\u{2014}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrativeStyle {
    Info,
    Warning,
    Success,
    Critical,
}

pub struct NarrativeEntry {
    pub text: String,
    pub style: NarrativeStyle,
}

pub struct GadgetInstruction {
    pub address: u64,
    pub mnemonic: &'static str,
    pub operands: &'static str,
    pub comment: &'static str,
    pub state: InstructionState,
}

#[allow(dead_code)]
pub trait Simulation {
    fn name(&self) -> &'static str;
    fn cve(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn phase_label(&self) -> String;
    fn phase_color(&self) -> ratatui::style::Color;
    fn advance(&mut self);
    fn fast_forward(&mut self);
    fn reset(&mut self);
    fn wants_quit(&self) -> bool;
    fn draw(&self, frame: &mut ratatui::Frame);
}
