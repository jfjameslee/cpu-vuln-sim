# CPU Vulnerability Simulator

A terminal-based, interactive simulator for CPU hardware security vulnerabilities. Step through each phase of a real-world speculative execution attack, instruction by instruction. This has been designed as an educational illustration, not a tool.

Built with Rust + [Ratatui](https://github.com/ratatui/ratatui).

---

## Simulations

| Name                  | CVE           | Technique                                                                                                 |
| --------------------- | ------------- | --------------------------------------------------------------------------------------------------------- |
| **Meltdown**          | CVE-2017-5754 | Out-of-order execution past a page fault leaks kernel memory to user space                                |
| **Spectre Variant 1** | CVE-2017-5753 | Bounds Check Bypass — a mispredicted branch causes speculative reads that leave cache-timing side effects |

Each simulation walks through the real gadget instructions, showing the CPU's internal state (pipeline, cache, registers, branch predictor) at every step.

---

## Demo

<img width="1470" height="923" alt="Screenshot 2026-05-07 at 11 39 03" src="https://github.com/user-attachments/assets/3de1945d-a9b3-4432-ab1c-8578c3db1f42" />

↑ Splash screen with simulation selections | Completed Spectre attack simulation ↓ 

<img width="1470" height="923" alt="Screenshot 2026-05-07 at 11 39 19" src="https://github.com/user-attachments/assets/bf40d506-034f-46a1-9072-109f95df35c1" />


---

## Installation

**Prerequisites:** Rust toolchain ([rustup.rs](https://rustup.rs))

```bash
git clone https://github.com/<your-username>/cpu-vuln-sim.git
cd cpu-vuln-sim
cargo run --release
```

---

## Controls

| Key         | Action                                                    |
| ----------- | --------------------------------------------------------- |
| `↑` / `↓`   | Navigate simulation list (splash screen)                  |
| `ENTER`     | Launch selected simulation / step forward one instruction |
| `SPACE`     | Step forward one instruction                              |
| `F`         | Fast-forward to end of current phase                      |
| `R`         | Reset simulation to beginning                             |
| `B` / `ESC` | Return to splash screen                                   |
| `Q`         | Quit                                                      |

---

## Project Structure

```
src/
  main.rs           — Entry point; event loop
  app.rs            — AppState (Splash | Running), key dispatch
  splash.rs         — Splash screen, simulation catalog
  sim/
    mod.rs          — Simulation trait + shared types
    meltdown/       — CVE-2017-5754 implementation
    spectre/        — CVE-2017-5753 V1 implementation
```

Each simulation module follows the same pattern: `sim.rs` (state machine), `ui.rs` (rendering), `mod.rs` (trait impl).

---

## Adding a New Simulation

1. Create `src/sim/<name>/sim.rs`, `ui.rs`, `mod.rs`
2. Implement the `Simulation` trait in `mod.rs`
3. Declare `pub mod <name>` in `src/sim/mod.rs`
4. Add an entry to `SIMULATION_CATALOG` in `src/splash.rs`

The `Simulation` trait requires:

```rust
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
```

Good candidates for future simulations: Spectre Variant 2 (CVE-2017-5715), Rowhammer, MDS/Fallout, Retbleed.

---

## Contributing

Contributions are welcome — bug fixes, new simulations, UI improvements, or documentation.

**Guidelines:**

- Open an issue before starting significant work so we can align on approach
- Keep simulation accuracy as the primary goal; educational clarity second
- Follow the existing module pattern for new simulations (see above)
- Run `cargo clippy` and `cargo fmt` before submitting a PR; the build must be warning-free
- PR descriptions should explain the vulnerability being simulated and link to the relevant paper or CVE
- This project is educational — avoid any real exploit code or working shellcode

**Submitting a PR:**

1. Fork the repo and create a branch from `main`
2. Make your changes and ensure `cargo build` is clean
3. Open a pull request with a clear description of what was changed and why

---

## References

- [Meltdown paper — Lipp et al., 2018](https://meltdownattack.com/meltdown.pdf)
- [Spectre paper — Kocher et al., 2019](https://spectreattack.com/spectre.pdf)
- [CVE-2017-5754](https://nvd.nist.gov/vuln/detail/CVE-2017-5754)
- [CVE-2017-5753](https://nvd.nist.gov/vuln/detail/CVE-2017-5753)

---

## Generative AI Use Declaration

Portions of this project were developed with the assistance of **Claude** by [Anthropic](https://www.anthropic.com). AI-generated code was reviewed, tested, and integrated by the project author.

This declaration is made in the interest of transparency around generative AI use in open source software.

---

## License

MIT License

Copyright (c) 2026 jfjameslee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
