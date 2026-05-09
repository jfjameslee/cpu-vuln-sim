use std::collections::VecDeque;
use std::fmt;

use crate::sim::{CacheSlotState, GadgetInstruction, InstructionState, NarrativeEntry, NarrativeStyle};

pub const DISPATCH_TABLE_BASE: u64 = 0x0000_7FFF_0004_0000;
pub const BTB_POISON_ADDR: u64 = 0x0000_DEAD_BEEF_0000;
pub const THUNK_BASE: u64 = 0x0000_7FFF_1000_0000;
pub const REAL_TARGET_ADDR: u64 = 0x0000_7FFF_2000_0000;
pub const CAPTURE_LOOP_ADDR: u64 = THUNK_BASE + 0x0005;
pub const SETUP_RSP_ADDR: u64 = THUNK_BASE + 0x000C;
pub const BTB_POISON_ROUNDS: usize = 4;
pub const CACHE_MISS_CYCLES: u32 = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetpolinePhase {
    Setup,
    BTBPoisoning { step: usize },
    ThunkEntry,
    SafeSpeculation { step: usize },
    ArchResolution,
    TimingProbe { step: usize },
    Blocked,
}

impl fmt::Display for RetpolinePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetpolinePhase::Setup => write!(f, "SETUP"),
            RetpolinePhase::BTBPoisoning { step } => {
                write!(f, "BTB POISONING  ({}/{} rounds)", step, BTB_POISON_ROUNDS)
            }
            RetpolinePhase::ThunkEntry => {
                write!(f, "THUNK ENTRY \u{2014} call setup_rsp pushes capture_loop to RSB")
            }
            RetpolinePhase::SafeSpeculation { step } => write!(
                f,
                "SAFE SPECULATION  (step {}/3) \u{2014} CPU trapped in pause/lfence loop",
                step + 1
            ),
            RetpolinePhase::ArchResolution => {
                write!(f, "ARCHITECTURAL RESOLUTION \u{2014} ret \u{2192} real target")
            }
            RetpolinePhase::TimingProbe { step } => write!(f, "TIMING PROBE  ({}/256)", step),
            RetpolinePhase::Blocked => {
                write!(f, "ATTACK BLOCKED \u{2014} RETPOLINE held the line")
            }
        }
    }
}

fn make_gadget() -> Vec<GadgetInstruction> {
    vec![
        // Victim dispatch code
        GadgetInstruction {
            address: DISPATCH_TABLE_BASE,
            mnemonic: "mov",
            operands: "rdi, [dispatch_table+rbx*8]",
            comment: "load fn ptr (user-controlled index)",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: DISPATCH_TABLE_BASE + 0x08,
            mnemonic: "call",
            operands: "retpoline_thunk_rdi",
            comment: "RETPOLINE: safe indirect call \u{2014} not 'jmp [rdi]'!",
            state: InstructionState::Upcoming,
        },
        // Section divider
        GadgetInstruction {
            address: DISPATCH_TABLE_BASE + 0x10,
            mnemonic: ";;",
            operands: "--- RETPOLINE THUNK (retpoline_thunk_rdi) ---",
            comment: "",
            state: InstructionState::Upcoming,
        },
        // Retpoline thunk: call setup_rsp (pushes capture_loop to RSB)
        GadgetInstruction {
            address: THUNK_BASE,
            mnemonic: "call",
            operands: "setup_rsp",
            comment: "push capture_loop addr onto RSB",
            state: InstructionState::Upcoming,
        },
        // capture_loop: pause; lfence; jmp capture_loop
        GadgetInstruction {
            address: CAPTURE_LOOP_ADDR,
            mnemonic: "pause",
            operands: "",
            comment: "stall pipeline; prevents speculative forward progress",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: CAPTURE_LOOP_ADDR + 0x02,
            mnemonic: "lfence",
            operands: "",
            comment: "serializing fence \u{2014} no speculative loads past here",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: CAPTURE_LOOP_ADDR + 0x05,
            mnemonic: "jmp",
            operands: "capture_loop",
            comment: "RSB predicts here \u{2014} speculation safely trapped",
            state: InstructionState::Upcoming,
        },
        // Section divider
        GadgetInstruction {
            address: THUNK_BASE + 0x000B,
            mnemonic: ";;",
            operands: "--- setup_rsp subroutine ---",
            comment: "",
            state: InstructionState::Upcoming,
        },
        // setup_rsp: patch return address, then ret
        GadgetInstruction {
            address: SETUP_RSP_ADDR,
            mnemonic: "mov",
            operands: "[rsp], rdi",
            comment: "overwrite ret addr with real dispatch target",
            state: InstructionState::Upcoming,
        },
        GadgetInstruction {
            address: SETUP_RSP_ADDR + 0x04,
            mnemonic: "ret",
            operands: "",
            comment: "RSB \u{2192} capture_loop (speculative); arch \u{2192} real fn",
            state: InstructionState::Upcoming,
        },
        // Section divider
        GadgetInstruction {
            address: THUNK_BASE + 0x0011,
            mnemonic: ";;",
            operands: "--- result ---",
            comment: "",
            state: InstructionState::Upcoming,
        },
        // Real target (only reached architecturally)
        GadgetInstruction {
            address: REAL_TARGET_ADDR,
            mnemonic: "nop",
            operands: "",
            comment: "real_target: legitimate fn \u{2014} only executed architecturally",
            state: InstructionState::Upcoming,
        },
    ]
}

pub struct SpectreRetpolineSim {
    pub phase: RetpolinePhase,
    pub cache: [CacheSlotState; 256],
    pub gadget: Vec<GadgetInstruction>,
    pub reload_timings: [Option<u32>; 256],
    pub narrative: VecDeque<NarrativeEntry>,
    pub btb_poisoned_addr: u64,
    pub rsb_top: u64,
    pub speculation_blocked: bool,
    pub current_pc: usize,
    pub poison_round: usize,
    pub quit: bool,
}

impl SpectreRetpolineSim {
    pub fn new() -> Self {
        let mut narrative = VecDeque::new();
        narrative.push_back(NarrativeEntry {
            text: "Spectre + RETPOLINE simulator initialized.".into(),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: format!("Victim dispatch table at {DISPATCH_TABLE_BASE:#018x}. Attacker controls the index into this table."),
            style: NarrativeStyle::Info,
        });
        narrative.push_back(NarrativeEntry {
            text: "Attacker goal: poison the BTB (Branch Target Buffer) so the CPU speculatively jumps to a secret-reading gadget during an indirect dispatch.".into(),
            style: NarrativeStyle::Warning,
        });
        narrative.push_back(NarrativeEntry {
            text: "RETPOLINE replaces 'jmp [rdi]' with a return trampoline: RSB (Return Stack Buffer) is loaded with capture_loop — a safe pause/lfence spin — so the CPU can never speculate to the attacker's BTB target.".into(),
            style: NarrativeStyle::Warning,
        });
        narrative.push_back(NarrativeEntry {
            text: "Press SPACE to step  |  F = fast-forward phase  |  R = restart  |  B = back  |  Q = quit".into(),
            style: NarrativeStyle::Info,
        });

        SpectreRetpolineSim {
            phase: RetpolinePhase::Setup,
            cache: [CacheSlotState::Evicted; 256],
            gadget: make_gadget(),
            reload_timings: [None; 256],
            narrative,
            btb_poisoned_addr: BTB_POISON_ADDR,
            rsb_top: 0,
            speculation_blocked: false,
            current_pc: 0,
            poison_round: 0,
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
            RetpolinePhase::Setup => {
                self.gadget[0].state = InstructionState::Retired;
                self.gadget[1].state = InstructionState::Retired;
                self.push(
                    "Victim code runs: loads fn ptr from dispatch table, calls via RETPOLINE thunk instead of a raw 'jmp [rdi]'.",
                    NarrativeStyle::Info,
                );
                self.push(
                    format!("Attacker's malicious gadget at {BTB_POISON_ADDR:#018x}. Will attempt to inject this address into the CPU's BTB."),
                    NarrativeStyle::Critical,
                );
                self.push(
                    "Starting BTB poisoning phase: attacker repeatedly executes an indirect jump to the malicious gadget.",
                    NarrativeStyle::Warning,
                );
                self.phase = RetpolinePhase::BTBPoisoning { step: 0 };
            }

            RetpolinePhase::BTBPoisoning { step } => {
                self.poison_round = step + 1;
                self.push(
                    format!(
                        "BTB POISON {}/{}: attacker executes jmp [rax] with rax={BTB_POISON_ADDR:#018x}. BTB records: indirect dispatch \u{2192} {BTB_POISON_ADDR:#018x}.",
                        step + 1,
                        BTB_POISON_ROUNDS
                    ),
                    NarrativeStyle::Critical,
                );
                if step + 1 >= BTB_POISON_ROUNDS {
                    self.push(
                        "BTB fully poisoned! CPU branch predictor believes the victim's next indirect dispatch will jump to attacker's gadget.",
                        NarrativeStyle::Critical,
                    );
                    self.push(
                        "But victim uses RETPOLINE \u{2014} no 'jmp [rdi]' instruction exists. The RSB will override the BTB for 'ret' speculation.",
                        NarrativeStyle::Warning,
                    );
                    self.phase = RetpolinePhase::ThunkEntry;
                } else {
                    self.phase = RetpolinePhase::BTBPoisoning { step: step + 1 };
                }
            }

            RetpolinePhase::ThunkEntry => {
                self.gadget[3].state = InstructionState::SpeculativelyExecuting;
                self.current_pc = 3;
                self.rsb_top = CAPTURE_LOOP_ADDR;
                self.push(
                    format!("Victim calls retpoline_thunk_rdi. 'call setup_rsp' executes \u{2014} pushes {CAPTURE_LOOP_ADDR:#018x} (capture_loop) onto the RSB."),
                    NarrativeStyle::Info,
                );
                self.push(
                    format!("BTB says: jump to {BTB_POISON_ADDR:#018x}. But for a 'ret', the RSB takes priority over the BTB \u{2014} CPU must speculate to capture_loop!"),
                    NarrativeStyle::Warning,
                );
                self.phase = RetpolinePhase::SafeSpeculation { step: 0 };
            }

            RetpolinePhase::SafeSpeculation { step } => match step {
                0 => {
                    self.gadget[3].state = InstructionState::Retired;
                    self.gadget[4].state = InstructionState::SpeculativelyExecuting;
                    self.current_pc = 4;
                    self.speculation_blocked = true;
                    self.push(
                        "SPECULATION: CPU speculatively fetches capture_loop (RSB-predicted). Executes 'pause' \u{2014} pipeline stall, halts speculative progress.",
                        NarrativeStyle::Warning,
                    );
                    self.push(
                        format!("Attacker's gadget at {BTB_POISON_ADDR:#018x} is NOT reached. RSB overrides BTB for 'ret' speculation."),
                        NarrativeStyle::Info,
                    );
                    self.phase = RetpolinePhase::SafeSpeculation { step: 1 };
                }
                1 => {
                    self.gadget[4].state = InstructionState::Retired;
                    self.gadget[5].state = InstructionState::SpeculativelyExecuting;
                    self.current_pc = 5;
                    self.push(
                        "SPECULATION: 'lfence' \u{2014} serializing instruction. No loads or stores can speculatively pass this point.",
                        NarrativeStyle::Warning,
                    );
                    self.push(
                        "No secret data can be speculatively read. Cache remains completely cold.",
                        NarrativeStyle::Info,
                    );
                    self.phase = RetpolinePhase::SafeSpeculation { step: 2 };
                }
                _ => {
                    self.gadget[5].state = InstructionState::Retired;
                    self.gadget[6].state = InstructionState::SpeculativelyExecuting;
                    self.current_pc = 6;
                    self.push(
                        "SPECULATION: 'jmp capture_loop' \u{2014} CPU loops back speculatively. Trapped in pause/lfence/jmp until 'ret' resolves architecturally.",
                        NarrativeStyle::Warning,
                    );
                    self.phase = RetpolinePhase::ArchResolution;
                }
            },

            RetpolinePhase::ArchResolution => {
                self.gadget[6].state = InstructionState::Squashed;
                self.gadget[8].state = InstructionState::Retired;
                self.gadget[9].state = InstructionState::Retired;
                self.gadget[11].state = InstructionState::Retired;
                self.current_pc = 11;
                self.push(
                    "ARCHITECTURAL: setup_rsp runs \u{2014} patches [rsp] with the real target address. 'ret' resolves architecturally to real_target.",
                    NarrativeStyle::Info,
                );
                self.push(
                    "Speculative capture_loop path is squashed. No secret was ever read speculatively. Cache is still completely clean.",
                    NarrativeStyle::Info,
                );
                self.push(
                    "Starting Flush+Reload timing probe to confirm no cache side-channel occurred...",
                    NarrativeStyle::Info,
                );
                self.phase = RetpolinePhase::TimingProbe { step: 0 };
            }

            RetpolinePhase::TimingProbe { step } => {
                let end = (step + 16).min(256);
                for i in step..end {
                    self.reload_timings[i] = Some(CACHE_MISS_CYCLES);
                }
                if end >= 256 {
                    self.push(
                        "Timing probe complete: 256/256 slots \u{2014} ALL CACHE MISS. No speculative access occurred.",
                        NarrativeStyle::Success,
                    );
                    self.push(
                        "RETPOLINE successfully blocked the Branch Target Injection attack. Zero information leaked via cache timing.",
                        NarrativeStyle::Success,
                    );
                    self.push(
                        "Press SPACE to exit, R to restart, B to return to menu.",
                        NarrativeStyle::Info,
                    );
                    self.phase = RetpolinePhase::Blocked;
                } else {
                    self.phase = RetpolinePhase::TimingProbe { step: end };
                }
            }

            RetpolinePhase::Blocked => {
                self.quit = true;
            }
        }
    }

    pub fn step_phase(&mut self) {
        let start = std::mem::discriminant(&self.phase);
        loop {
            if self.phase == RetpolinePhase::Blocked || self.quit {
                break;
            }
            self.step();
            if std::mem::discriminant(&self.phase) != start {
                break;
            }
        }
    }
}
