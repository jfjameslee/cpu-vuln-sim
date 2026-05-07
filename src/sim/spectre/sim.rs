use std::collections::VecDeque;
use std::fmt;

use crate::sim::{
    CacheSlotState, GadgetInstruction, InstructionState, NarrativeEntry, NarrativeStyle,
    RegisterValue,
};

pub const SECRET_BYTE: u8 = b'S'; // 0x53
pub const SECRET_OFFSET: usize = 256;
pub const ARRAY1_BASE: u64 = 0x0000_7FFF_0001_FF00;
pub const SECRET_ADDR: u64 = 0x0000_7FFF_0002_0000;
pub const PROBE_ARRAY_BASE: u64 = 0x0000_7FFF_0003_0000;
pub const CACHE_HIT_CYCLES: u32 = 4;
pub const CACHE_MISS_CYCLES: u32 = 200;
pub const TRAIN_ROUNDS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpectrePhase {
    Setup,
    Train { round: usize },
    Speculative { step: usize },
    Reload { step: usize },
    Revealed,
}

impl fmt::Display for SpectrePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpectrePhase::Setup => write!(f, "SETUP"),
            SpectrePhase::Train { round } => {
                write!(f, "TRAIN  (branch predictor training \u{2014} {}/{} rounds)", round, TRAIN_ROUNDS)
            }
            SpectrePhase::Speculative { step } => {
                write!(f, "SPECULATIVE EXECUTION  (step {}/5)", step)
            }
            SpectrePhase::Reload { step } => write!(f, "RELOAD + TIMING  ({}/256)", step),
            SpectrePhase::Revealed => write!(f, "ATTACK COMPLETE \u{2014} SECRET RECOVERED"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchPredictorState {
    Untrained,
    Training,
    Trained,
    Mispredicting,
}

pub struct SpectreRegisters {
    pub rdi: RegisterValue,
    pub rax: RegisterValue,
    pub rbx: RegisterValue,
    pub current_pc: usize,
}

pub struct SpectreSim {
    pub phase: SpectrePhase,
    pub cache: [CacheSlotState; 256],
    pub registers: SpectreRegisters,
    pub gadget: Vec<GadgetInstruction>,
    pub reload_timings: [Option<u32>; 256],
    pub secret_byte: u8,
    pub secret_revealed: bool,
    pub branch_predictor: BranchPredictorState,
    pub train_round: usize,
    pub narrative: VecDeque<NarrativeEntry>,
    pub quit: bool,
}

fn make_gadget() -> Vec<GadgetInstruction> {
    vec![
        GadgetInstruction {
            address: 0x0000_7fff_0001_0000,
            mnemonic: "push",
            operands: "rbp",
            comment: "function prologue",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_0001,
            mnemonic: "mov",
            operands: "rbp, rsp",
            comment: "save frame pointer",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_0003,
            mnemonic: "cmp",
            operands: "rdi, [array1_size]",
            comment: "bounds check: x < 16?",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_000a,
            mnemonic: "jae",
            operands: ".bounds_fail",
            comment: "MISPREDICT: predictor guesses NOT taken",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_000c,
            mnemonic: "movzx",
            operands: "rax, [array1+rdi]",
            comment: "SPECULATION: load secret byte out-of-bounds!",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_0014,
            mnemonic: "imul",
            operands: "rax, 512",
            comment: "SPECULATION: scale index by stride",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_001b,
            mnemonic: "mov",
            operands: "rbx, [array2+rax]",
            comment: "SIDE EFFECT: cache line installed!",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_0023,
            mnemonic: ";;",
            operands: "#BR misprediction \u{2014} pipeline flushed",
            comment: "microarch side effects persist",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_0025,
            mnemonic: "xor",
            operands: "rax, rax",
            comment: "architectural rollback: rax = 0",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0x0000_7fff_0001_0027,
            mnemonic: "xor",
            operands: "rbx, rbx",
            comment: "architectural rollback: rbx = 0",
            state: InstructionState::Upcoming,
        },
    ]
}

impl SpectreSim {
    pub fn new() -> Self {
        let mut narrative = VecDeque::new();
        narrative.push_back(NarrativeEntry {
            text: "Spectre Variant 1 simulator initialized.".into(),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: format!("Victim array (array1) at {ARRAY1_BASE:#018x}  (16 bytes, bounds-checked)"),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: format!("Secret string at {SECRET_ADDR:#018x}  (offset 256 past array1 end)"),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: format!("Probe array (array2) at {PROBE_ARRAY_BASE:#018x}  (256 \u{d7} 512 B)"),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: "Press SPACE to step  |  F = fast-forward phase  |  R = restart  |  B = back  |  Q = quit".into(),
            style: NarrativeStyle::Warning,
        });

        SpectreSim {
            phase: SpectrePhase::Setup,
            cache: [CacheSlotState::Evicted; 256],
            registers: SpectreRegisters {
                rdi: RegisterValue::Cleared,
                rax: RegisterValue::Cleared,
                rbx: RegisterValue::Cleared,
                current_pc: 0,
            },
            gadget: make_gadget(),
            reload_timings: [None; 256],
            secret_byte: SECRET_BYTE,
            secret_revealed: false,
            branch_predictor: BranchPredictorState::Untrained,
            train_round: 0,
            narrative,
            quit: false,
        }
    }

    fn push(&mut self, text: impl Into<String>, style: NarrativeStyle) {
        self.narrative.push_back(NarrativeEntry { text: text.into(), style });
        if self.narrative.len() > 60 {
            self.narrative.pop_front();
        }
    }

    pub fn step(&mut self) {
        match self.phase.clone() {
            SpectrePhase::Setup => {
                self.gadget[0].state = InstructionState::Retired;
                self.gadget[1].state = InstructionState::Retired;
                self.registers.current_pc = 2;
                self.push(
                    "array1 has 16 elements. The gadget performs a bounds check before accessing it.",
                    NarrativeStyle::Info,
                );
                self.push(
                    "array2 is the attacker's probe array: 256 slots \u{d7} 512 bytes = 128 KB. All slots cold.",
                    NarrativeStyle::Info,
                );
                self.push(
                    format!(
                        "Secret string starts at offset 256 past array1 end ({SECRET_ADDR:#018x})."
                    ),
                    NarrativeStyle::Warning,
                );
                self.push(
                    "Starting branch predictor training: call gadget with in-bounds values 8 times.",
                    NarrativeStyle::Warning,
                );
                self.phase = SpectrePhase::Train { round: 0 };
            }

            SpectrePhase::Train { round } => {
                let train_x = round % 4;
                self.registers.rdi = RegisterValue::Known(train_x as u64);
                self.gadget[2].state = InstructionState::Retired;
                self.gadget[3].state = InstructionState::Retired;
                self.train_round = round + 1;

                let next_round = round + 1;
                self.branch_predictor = if next_round >= TRAIN_ROUNDS {
                    BranchPredictorState::Trained
                } else {
                    BranchPredictorState::Training
                };

                self.push(
                    format!(
                        "TRAIN {}/{}: x={} (in-bounds). cmp: {} < 16 = TRUE. jae NOT taken. Predictor records: NOT taken.",
                        round + 1,
                        TRAIN_ROUNDS,
                        train_x,
                        train_x
                    ),
                    NarrativeStyle::Info,
                );

                if next_round >= TRAIN_ROUNDS {
                    self.push(
                        "Branch predictor fully trained! Next call will predict NOT taken even for x=256.",
                        NarrativeStyle::Warning,
                    );
                    self.phase = SpectrePhase::Speculative { step: 0 };
                } else {
                    self.phase = SpectrePhase::Train { round: next_round };
                }
            }

            SpectrePhase::Speculative { step } => match step {
                0 => {
                    self.registers.rdi = RegisterValue::Known(SECRET_OFFSET as u64);
                    self.gadget[2].state = InstructionState::SpeculativelyExecuting;
                    self.registers.current_pc = 2;
                    self.branch_predictor = BranchPredictorState::Mispredicting;
                    self.push(
                        "ATTACK: gadget called with x=256 (out-of-bounds, points past array1 to secret).",
                        NarrativeStyle::Critical,
                    );
                    self.push(
                        "CPU evaluates cmp: 256 < 16? FALSE \u{2014} but branch predictor says NOT taken! Speculating...",
                        NarrativeStyle::Warning,
                    );
                    self.phase = SpectrePhase::Speculative { step: 1 };
                }
                1 => {
                    self.gadget[2].state = InstructionState::Retired;
                    self.gadget[3].state = InstructionState::SpeculativelyExecuting;
                    self.registers.current_pc = 3;
                    self.push(
                        "SPECULATION: jae .bounds_fail \u{2014} CPU predicts NOT taken (wrong!). Body executes speculatively.",
                        NarrativeStyle::Warning,
                    );
                    self.phase = SpectrePhase::Speculative { step: 2 };
                }
                2 => {
                    self.gadget[3].state = InstructionState::Retired;
                    self.gadget[4].state = InstructionState::SpeculativelyExecuting;
                    self.registers.rax = RegisterValue::Speculative(format!(
                        "array1[256] = 0x{:02X} '{}'",
                        self.secret_byte, self.secret_byte as char
                    ));
                    self.registers.current_pc = 4;
                    self.push(
                        format!(
                            "SPECULATION: movzx rax, [array1+256] \u{2014} reads SECRET 0x{:02X} '{}' (out-of-bounds access!)",
                            self.secret_byte, self.secret_byte as char
                        ),
                        NarrativeStyle::Critical,
                    );
                    self.phase = SpectrePhase::Speculative { step: 3 };
                }
                3 => {
                    self.gadget[4].state = InstructionState::Retired;
                    self.gadget[5].state = InstructionState::SpeculativelyExecuting;
                    self.registers.rax = RegisterValue::Speculative(format!(
                        "0x{:02X} \u{d7} 512 = 0x{:04X}",
                        self.secret_byte,
                        (self.secret_byte as u32) * 512
                    ));
                    self.registers.current_pc = 5;
                    self.push(
                        "SPECULATION: imul rax, 512 \u{2014} scale secret byte to probe array offset",
                        NarrativeStyle::Warning,
                    );
                    self.phase = SpectrePhase::Speculative { step: 4 };
                }
                4 => {
                    self.gadget[5].state = InstructionState::Retired;
                    self.gadget[6].state = InstructionState::SpeculativelyExecuting;
                    self.registers.rbx = RegisterValue::Speculative(format!(
                        "mem[array2 + 0x{:04X}]",
                        (self.secret_byte as u32) * 512
                    ));
                    self.registers.current_pc = 6;
                    // The key side effect: secret byte's cache slot is loaded
                    self.cache[self.secret_byte as usize] = CacheSlotState::Cached;
                    self.push(
                        "SPECULATION: mov rbx, [array2+rax] \u{2014} CACHE LINE INSTALLED as microarch side effect!",
                        NarrativeStyle::Critical,
                    );
                    self.phase = SpectrePhase::Speculative { step: 5 };
                }
                _ => {
                    // step 5: misprediction detected, pipeline flushed
                    self.gadget[6].state = InstructionState::Faulted;
                    self.gadget[7].state = InstructionState::Faulted;
                    self.gadget[8].state = InstructionState::Squashed;
                    self.gadget[9].state = InstructionState::Squashed;
                    self.registers.rax = RegisterValue::Cleared;
                    self.registers.rbx = RegisterValue::Cleared;
                    self.registers.current_pc = 7;
                    self.push(
                        "MISPREDICTION DETECTED: Pipeline flushed. Architectural state rolled back.",
                        NarrativeStyle::Critical,
                    );
                    self.push(
                        "Cache state is NOT rolled back \u{2014} microarchitectural side effect persists!",
                        NarrativeStyle::Warning,
                    );
                    self.push(
                        "Starting Reload+Timing phase to identify which cache slot was touched...",
                        NarrativeStyle::Info,
                    );
                    self.phase = SpectrePhase::Reload { step: 0 };
                }
            },

            SpectrePhase::Reload { step } => {
                let end = (step + 16).min(256);
                for i in step..end {
                    let cycles = if i == self.secret_byte as usize {
                        CACHE_HIT_CYCLES
                    } else {
                        CACHE_MISS_CYCLES
                    };
                    self.reload_timings[i] = Some(cycles);
                    if i == self.secret_byte as usize {
                        self.cache[i] = CacheSlotState::Hit;
                        self.push(
                            format!(
                                "TIMING: array2[0x{i:02X}\u{d7}512] = {cycles} cycles  \u{2190} CACHE HIT! Secret = 0x{i:02X} ('{}')",
                                char::from_u32(i as u32).unwrap_or('?')
                            ),
                            NarrativeStyle::Success,
                        );
                    }
                }
                if end >= 256 {
                    self.secret_revealed = true;
                    self.push(
                        format!(
                            "Attack complete! Secret byte recovered: 0x{:02X} ('{}')",
                            self.secret_byte,
                            char::from_u32(self.secret_byte as u32).unwrap_or('?')
                        ),
                        NarrativeStyle::Success,
                    );
                    self.push(
                        "Press SPACE to exit, R to restart, B to return to menu.",
                        NarrativeStyle::Info,
                    );
                    self.phase = SpectrePhase::Revealed;
                } else {
                    self.phase = SpectrePhase::Reload { step: end };
                }
            }

            SpectrePhase::Revealed => {
                self.quit = true;
            }
        }
    }

    pub fn step_phase(&mut self) {
        let start_discriminant = std::mem::discriminant(&self.phase);
        loop {
            if self.phase == SpectrePhase::Revealed || self.quit {
                break;
            }
            self.step();
            if std::mem::discriminant(&self.phase) != start_discriminant {
                break;
            }
        }
    }
}
