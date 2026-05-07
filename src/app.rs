use crossterm::event::KeyCode;
use ratatui::Frame;

use crate::sim::Simulation;
use crate::splash::{SplashState, render_splash};

pub enum AppState {
    Splash(SplashState),
    Running(Box<dyn Simulation>),
}

pub struct App {
    pub state: AppState,
}

impl App {
    pub fn new() -> Self {
        App { state: AppState::Splash(SplashState::new()) }
    }

    pub fn draw(&self, frame: &mut Frame) {
        match &self.state {
            AppState::Splash(s) => render_splash(frame, s),
            AppState::Running(sim) => sim.draw(frame),
        }
    }

    /// Returns true if the app should exit.
    pub fn handle_key(&mut self, key: KeyCode) -> bool {
        match &mut self.state {
            AppState::Splash(splash) => match key {
                KeyCode::Up => {
                    splash.move_up();
                    false
                }
                KeyCode::Down => {
                    splash.move_down();
                    false
                }
                KeyCode::Enter => {
                    let sim = splash.launch();
                    self.state = AppState::Running(sim);
                    false
                }
                KeyCode::Char('q') | KeyCode::Esc => true,
                _ => false,
            },
            AppState::Running(sim) => match key {
                KeyCode::Char('q') => true,
                KeyCode::Char('b') | KeyCode::Char('B') | KeyCode::Esc => {
                    self.state = AppState::Splash(SplashState::new());
                    false
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    sim.advance();
                    false
                }
                KeyCode::Char('f') | KeyCode::Char('F') => {
                    sim.fast_forward();
                    false
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    sim.reset();
                    false
                }
                _ => false,
            },
        }
    }

    pub fn wants_quit(&self) -> bool {
        match &self.state {
            AppState::Running(sim) => sim.wants_quit(),
            _ => false,
        }
    }
}
