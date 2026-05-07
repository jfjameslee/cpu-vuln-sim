mod app;
mod sim;
mod splash;

use app::App;
use crossterm::event::{Event, KeyEventKind};
use ratatui::DefaultTerminal;

fn main() -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let result = run(&mut terminal);
    ratatui::restore();
    result
}

fn run(terminal: &mut DefaultTerminal) -> std::io::Result<()> {
    let mut app = App::new();
    loop {
        terminal.draw(|frame| app.draw(frame))?;

        if let Event::Key(key) = crossterm::event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if app.handle_key(key.code) {
                break;
            }
        }

        if app.wants_quit() {
            break;
        }
    }
    Ok(())
}
