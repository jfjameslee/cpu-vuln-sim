use std::collections::VecDeque;
use std::fmt;

use crate::sim::{
    CacheSlotState, GadgetInstruction, InstructionState, NarrativeEntry, NarrativeStyle,
    RegisterValue,
};

pub const SECRET_BYTE: u8 = 0x41; // 'A'
pub const KERNEL_SECRET_ADDR: u64 = 0xFFFF_8001_1234_0020;
pub const PROBE_ARRAY_BASE: u64 = 0x0000_7FFF_0001_0000;
pub const CACHE_HIT_CYCLES: u32 = 4;
pub const CACHE_MISS_CYCLES: u32 = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimPhase {
    Setup,
    Flush { step: usize },
    Speculative { step: usize },
    Reload { step: usize },
    Revealed,
}

impl fmt::Display for SimPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimPhase::Setup => write!(f, "SETUP"),
            SimPhase::Flush { step } => write!(f, "FLUSH  (evicting probe_array... {}/256)", step),
            SimPhase::Speculative { step } => {
                write!(f, "SPECULATIVE EXECUTION  (step {}/4)", step)
            }
            SimPhase::Reload { step } => write!(f, "RELOAD + TIMING  ({}/256)", step),
            SimPhase::Revealed => write!(f, "ATTACK COMPLETE \u{2014} SECRET RECOVERED"),
        }
    }
}

pub struct CpuRegisters {
    pub rax: RegisterValue,
    pub rbx: RegisterValue,
    pub current_pc: usize,
}

pub struct MeltdownSim {
    pub phase: SimPhase,
    pub cache: [CacheSlotState; 256],
    pub registers: CpuRegisters,
    pub gadget: Vec<GadgetInstruction>,
    pub reload_timings: [Option<u32>; 256],
    pub secret_byte: u8,
    pub secret_revealed: bool,
    pub narrative: VecDeque<NarrativeEntry>,
    pub quit: bool,
}

fn make_gadget() -> Vec<GadgetInstruction> {
    vec![
        GadgetInstruction {
            address: 0xffff_8001_1234_0000,
            mnemonic: "push",
            operands: "rbp",
            comment: "function prologue",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0xffff_8001_1234_0001,
            mnemonic: "mov",
            operands: "rbp, rsp",
            comment: "save stack pointer",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0xffff_8001_1234_0003,
            mnemonic: "mov",
            operands: "rax, [kernel_secret]",
            comment: "FAULT: ring-0 access from user mode",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0xffff_8001_1234_000a,
            mnemonic: "shl",
            operands: "rax, 12",
            comment: "encode as 4096-byte page offset",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0xffff_8001_1234_000d,
            mnemonic: "mov",
            operands: "rbx, [probe_array+rax]",
            comment: "SIDE EFFECT: cache line installed!",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0xffff_8001_1234_0010,
            mnemonic: ";;",
            operands: "#PF fault raised \u{2014} ROB squashed",
            comment: "microarch side effects persist",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0xffff_8001_1234_0012,
            mnemonic: "xor",
            operands: "rax, rax",
            comment: "architectural rollback: rax = 0",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: 0xffff_8001_1234_0014,
            mnemonic: "xor",
            operands: "rbx, rbx",
            comment: "architectural rollback: rbx = 0",
            state: InstructionState::Upcoming,
        },
    ]
}

impl MeltdownSim {
    pub fn new() -> Self {
        let mut narrative = VecDeque::new();
        narrative.push_back(NarrativeEntry {
            text: "Meltdown vulnerability simulator initialized.".into(),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: format!("Kernel secret at {KERNEL_SECRET_ADDR:#018x} (value hidden)"),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: format!("Probe array at {PROBE_ARRAY_BASE:#018x}  (256 \u{d7} 4096-byte pages)"),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: "Press SPACE to step  |  F = fast-forward phase  |  R = restart  |  B = back  |  Q = quit".into(),
            style: NarrativeStyle::Warning,
        });

        MeltdownSim {
            phase: SimPhase::Setup,
            cache: [CacheSlotState::Cached; 256],
            registers: CpuRegisters {
                rax: RegisterValue::Cleared,
                rbx: RegisterValue::Cleared,
                current_pc: 0,
            },
            gadget: make_gadget(),
            reload_timings: [None; 256],
            secret_byte: SECRET_BYTE,
            secret_revealed: false,
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
            SimPhase::Setup => {
                self.gadget[0].state = InstructionState::Retired;
                self.gadget[1].state = InstructionState::Retired;
                self.registers.current_pc = 2;
                self.push(
                    "Probe array loaded into cache (all 256 slots cached).",
                    NarrativeStyle::Info,
                );
                self.push(
                    "Beginning Flush phase: CLFLUSH evicts probe array from cache.",
                    NarrativeStyle::Warning,
                );
                self.phase = SimPhase::Flush { step: 0 };
            }

            SimPhase::Flush { step } => {
                let end = (step + 16).min(256);
                for i in step..end {
                    self.cache[i] = CacheSlotState::Evicted;
                }
                self.push(
                    format!("CLFLUSH: evicted probe_array[0x{step:02X}\u{2013}0x{:02X}]", end - 1),
                    NarrativeStyle::Info,
                );
                if end >= 256 {
                    self.push("All 256 probe slots flushed from cache.", NarrativeStyle::Warning);
                    self.push(
                        "Starting speculative execution gadget...",
                        NarrativeStyle::Warning,
                    );
                    self.phase = SimPhase::Speculative { step: 0 };
                } else {
                    self.phase = SimPhase::Flush { step: end };
                }
            }

            SimPhase::Speculative { step: 0 } => {
                self.gadget[2].state = InstructionState::SpeculativelyExecuting;
                self.registers.rax = RegisterValue::Speculative("???".into());
                self.registers.current_pc = 2;
                self.push(
                    "FAULT: mov rax, [kernel_secret] \u{2014} #PF raised (ring-0 access from user mode)",
                    NarrativeStyle::Critical,
                );
                self.push(
                    "Out-of-order engine continues executing PAST the fault!",
                    NarrativeStyle::Warning,
                );
                self.phase = SimPhase::Speculative { step: 1 };
            }

            SimPhase::Speculative { step: 1 } => {
                self.gadget[2].state = InstructionState::Retired;
                self.gadget[3].state = InstructionState::SpeculativelyExecuting;
                self.registers.rax = RegisterValue::Speculative("??? \u{d7} 4096".into());
                self.registers.current_pc = 3;
                self.push(
                    "SPECULATION: rax = secret_byte << 12  (index into probe array by page)",
                    NarrativeStyle::Warning,
                );
                self.phase = SimPhase::Speculative { step: 2 };
            }

            SimPhase::Speculative { step: 2 } => {
                self.gadget[3].state = InstructionState::Retired;
                self.gadget[4].state = InstructionState::SpeculativelyExecuting;
                self.registers.rbx =
                    RegisterValue::Speculative("mem[probe_array + ???\u{d7}4096]".into());
                self.registers.current_pc = 4;
                self.cache[self.secret_byte as usize] = CacheSlotState::Cached;
                self.push(
                    "SPECULATION: CPU loads probe_array[secret\u{d7}4096] \u{2014} CACHE LINE INSTALLED!",
                    NarrativeStyle::Critical,
                );
                self.phase = SimPhase::Speculative { step: 3 };
            }

            SimPhase::Speculative { step: 3 } => {
                self.gadget[4].state = InstructionState::Faulted;
                self.gadget[5].state = InstructionState::Faulted;
                self.gadget[6].state = InstructionState::Squashed;
                self.gadget[7].state = InstructionState::Squashed;
                self.registers.rax = RegisterValue::Cleared;
                self.registers.rbx = RegisterValue::Cleared;
                self.registers.current_pc = 5;
                self.push(
                    "FAULT RAISED: Reorder Buffer squashed. Architectural registers rolled back.",
                    NarrativeStyle::Critical,
                );
                self.push(
                    "Cache state is NOT rolled back \u{2014} microarchitectural side effect persists!",
                    NarrativeStyle::Warning,
                );
                self.push(
                    "Beginning Reload+Timing phase to measure which cache slot was touched...",
                    NarrativeStyle::Info,
                );
                self.phase = SimPhase::Reload { step: 0 };
            }

            SimPhase::Speculative { step: _ } => {}

            SimPhase::Reload { step } => {
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
                                "TIMING: probe_array[0x{i:02X}] = {cycles} cycles  \u{2190} CACHE HIT! Secret = 0x{i:02X} ('{}')",
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
                    self.phase = SimPhase::Revealed;
                } else {
                    self.phase = SimPhase::Reload { step: end };
                }
            }

            SimPhase::Revealed => {
                self.quit = true;
            }
        }
    }

    pub fn step_phase(&mut self) {
        let start_discriminant = std::mem::discriminant(&self.phase);
        loop {
            if self.phase == SimPhase::Revealed || self.quit {
                break;
            }
            self.step();
            if std::mem::discriminant(&self.phase) != start_discriminant {
                break;
            }
        }
    }
}
