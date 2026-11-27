//! Glue between the pure [`App`] and the outside world: terminal loop, side effects, snapshots.

use std::{
    io,
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant},
};

use ratatui::{
    Terminal,
    backend::TestBackend,
    crossterm::event::{self, Event, KeyEventKind},
};
use tokenscope_core::{
    Engine,
    corpus::{Corpus, replay_case},
};
use tokenscope_report::write_artifacts;

use crate::{
    app::{App, CaseOutcome, Command, Options, Screen},
    runner::{RunEvent, build_engine, spawn},
    ui,
};

fn engine(opts: &Options) -> Engine {
    build_engine(opts.program_dir.as_deref(), opts.extended)
}

fn start(opts: &Options) -> Receiver<RunEvent> {
    spawn(
        opts.target.clone(),
        opts.seed,
        opts.count,
        opts.suite,
        opts.extended,
        opts.program_dir.clone(),
    )
}

/// Load the corpus directory into the app (errors are shown in the status line).
pub fn load_corpus(app: &mut App) {
    match Corpus::open(app.opts.corpus_dir.clone()).list() {
        Ok(cases) => app.corpus_cases = cases,
        Err(e) => app.status = format!("corpus: {e}"),
    }
}

/// Carry out a side effect requested by the UI. Returns a new event stream for [`Command::Rerun`].
pub fn execute(app: &mut App, cmd: Command) -> Option<Receiver<RunEvent>> {
    match cmd {
        Command::Rerun => {
            app.reset_run();
            Some(start(&app.opts))
        }
        Command::Export => {
            if let Some(c) = &app.campaign {
                match write_artifacts(c, &app.opts.out_dir) {
                    Ok(a) => {
                        app.status = format!("exported to {}", a.dir.display());
                        app.artifacts = Some(a);
                    }
                    Err(e) => app.status = format!("export failed: {e}"),
                }
            }
            None
        }
        Command::ReplayCase(id) => {
            if let Some(case) = app.corpus_cases.iter().find(|c| c.id == id).cloned() {
                let r = replay_case(&engine(&app.opts), &case);
                app.status = format!("replayed {id}: {}", if r.ok { "PASS" } else { "FAIL" });
                app.corpus_results.insert(
                    id,
                    CaseOutcome {
                        ok: r.ok,
                        actual: r.actual,
                    },
                );
            }
            None
        }
    }
}

fn drain(app: &mut App, rx: &Receiver<RunEvent>) {
    loop {
        match rx.try_recv() {
            Ok(ev) => app.apply(ev),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                if app.running {
                    app.running = false;
                    app.status = "runner stopped unexpectedly".into();
                }
                break;
            }
        }
    }
}

/// Render `app` at `width` x `height` into plain text (used for tests and `--snapshot`).
pub fn render_to_string(app: &App, width: u16, height: u16) -> String {
    // TestBackend's error type is `Infallible`, so these irrefutable patterns cannot fail.
    let Ok(mut terminal) = Terminal::new(TestBackend::new(width, height));
    let Ok(_) = terminal.draw(|f| ui::draw(f, app));
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        let mut line = String::new();
        for x in 0..width {
            line.push_str(buf[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Run the campaign to completion without a terminal and render one screen.
pub fn snapshot(opts: Options, screen: Screen, width: u16, height: u16) -> String {
    let mut app = App::new(opts);
    load_corpus(&mut app);
    let rx = start(&app.opts);
    let t0 = Instant::now();
    while app.running {
        match rx.recv() {
            Ok(ev) => app.apply(ev),
            Err(_) => {
                app.running = false;
                app.status = "runner stopped unexpectedly".into();
            }
        }
    }
    app.elapsed = t0.elapsed();
    app.screen = screen;
    render_to_string(&app, width, height)
}

/// Run the interactive TUI until the user quits. The terminal is always restored, including on
/// panic (ratatui installs a restoring panic hook) and on I/O errors.
pub fn run_interactive(opts: Options) -> io::Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, opts);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, opts: Options) -> io::Result<()> {
    let terminate = termination_flag();
    let mut app = App::new(opts);
    load_corpus(&mut app);
    let mut rx = start(&app.opts);
    let mut t0 = Instant::now();
    #[cfg(feature = "fault-injection")]
    let mut frames = 0u32;
    loop {
        if terminate.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(()); // SIGTERM/SIGHUP: leave the loop so the terminal is restored
        }
        drain(&mut app, &rx);
        if app.running {
            app.elapsed = t0.elapsed();
        }
        terminal.draw(|f| ui::draw(f, &app))?;
        #[cfg(feature = "fault-injection")]
        {
            frames += 1;
            inject_fault(frames)?;
        }
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => app.handle_key(k),
                // Resizes need no handling: the next draw lays out for the new size.
                _ => {}
            }
        }
        if let Some(cmd) = app.pending.take() {
            let rerun = matches!(cmd, Command::Rerun);
            if let Some(new_rx) = execute(&mut app, cmd) {
                rx = new_rx;
            }
            if rerun {
                t0 = Instant::now();
            }
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

/// Test-only fault injection (feature `fault-injection`): fail on the third frame.
#[cfg(feature = "fault-injection")]
fn inject_fault(frames: u32) -> io::Result<()> {
    match std::env::var("TOKENSCOPE_TUI_FAULT").as_deref() {
        Ok("panic") if frames == 3 => panic!("injected panic"),
        Ok("error") if frames == 3 => Err(io::Error::other("injected error")),
        _ => Ok(()),
    }
}

/// A flag set when the process receives SIGTERM or SIGHUP (unix only). Registering uses
/// `signal-hook`'s safe API; the TUI polls the flag every 50 ms.
fn termination_flag() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(unix)]
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP] {
        // A registration failure only means the signal keeps its default behavior.
        let _ = signal_hook::flag::register(signal, std::sync::Arc::clone(&flag));
    }
    flag
}
