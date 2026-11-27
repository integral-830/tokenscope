//! TUI tests: key handling on the pure state machine, rendering of every screen from real engine
//! results (via ratatui's TestBackend), and consistency with the engine and report outputs.

use std::path::{Path, PathBuf};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokenscope_core::Engine;
use tokenscope_model::OutcomeClass;
use tokenscope_report::{Report, render_json};
use tokenscope_tui::{
    App, Command, Options, Screen,
    driver::{execute, load_corpus},
    render_to_string,
    runner::{RunEvent, build_scenarios, spawn},
};

const VULN: &str = "demo-escrow-vulnerable";
const FIXED: &str = "demo-escrow-corrected";

fn opts(target: &str, out: PathBuf) -> Options {
    Options {
        target: target.into(),
        seed: 0,
        count: 0,
        suite: tokenscope_scenarios::SuiteSelection::Core,
        extended: false,
        out_dir: out,
        corpus_dir: Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus"),
        program_dir: None,
    }
}

fn finish(app: &mut App, rx: std::sync::mpsc::Receiver<RunEvent>) {
    while app.running {
        app.apply(rx.recv().expect("runner event"));
    }
}

fn finished_app(target: &str, out: PathBuf) -> App {
    let mut app = App::new(opts(target, out));
    load_corpus(&mut app);
    let rx = spawn(
        app.opts.target.clone(),
        0,
        0,
        tokenscope_scenarios::SuiteSelection::Core,
        false,
        None,
    );
    finish(&mut app, rx);
    app
}

fn key(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn press(app: &mut App, code: KeyCode) {
    app.handle_key(key(code));
}

fn fresh() -> App {
    App::new(opts(VULN, PathBuf::from("unused")))
}

#[test]
fn digits_tab_and_backtab_switch_screens() {
    let mut app = fresh();
    for (i, s) in Screen::ALL.iter().enumerate() {
        press(
            &mut app,
            KeyCode::Char(char::from_digit(i as u32 + 1, 10).unwrap()),
        );
        assert_eq!(app.screen, *s);
    }
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.screen, Screen::Dashboard, "tab wraps around");
    press(&mut app, KeyCode::BackTab);
    assert_eq!(app.screen, Screen::Help, "backtab wraps around");
    press(&mut app, KeyCode::Char('2'));
    press(&mut app, KeyCode::Char('?'));
    assert_eq!(app.screen, Screen::Help);
    assert_eq!(Screen::parse("findings"), Some(Screen::Findings));
    assert_eq!(Screen::parse("7"), Some(Screen::Corpus));
    assert_eq!(Screen::parse("nope"), None);
}

#[test]
fn quit_keys() {
    let mut a = fresh();
    press(&mut a, KeyCode::Char('q'));
    assert!(a.should_quit);
    let mut b = fresh();
    b.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(b.should_quit);
}

#[test]
fn filter_mode_captures_text_and_does_not_quit() {
    let mut app = fresh();
    press(&mut app, KeyCode::Char('2'));
    press(&mut app, KeyCode::Char('/'));
    assert!(app.filtering);
    for c in "q2fee".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    assert_eq!(app.filter, "q2fee");
    assert!(!app.should_quit && app.screen == Screen::Scenarios);
    press(&mut app, KeyCode::Backspace);
    assert_eq!(app.filter, "q2fe");
    press(&mut app, KeyCode::Enter);
    assert!(
        !app.filtering && app.filter == "q2fe",
        "enter keeps the filter"
    );
    press(&mut app, KeyCode::Char('/'));
    press(&mut app, KeyCode::Esc);
    assert!(
        !app.filtering && app.filter.is_empty(),
        "esc clears the filter"
    );
    // Ctrl-C quits even while filtering.
    press(&mut app, KeyCode::Char('/'));
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.should_quit);
}

#[test]
fn target_toggle_and_rerun_request_side_effects_without_executing() {
    let mut app = fresh();
    press(&mut app, KeyCode::Char('t'));
    assert_eq!(app.opts.target, FIXED);
    assert_eq!(app.pending, Some(Command::Rerun));
    app.pending = None;
    press(&mut app, KeyCode::Char('t'));
    assert_eq!(app.opts.target, VULN);
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.pending, Some(Command::Rerun));
}

#[test]
fn export_is_refused_until_the_campaign_finishes() {
    let mut app = fresh();
    press(&mut app, KeyCode::Char('e'));
    assert_eq!(app.pending, None);
    assert!(app.status.contains("still running"));
}

#[test]
fn selection_is_clamped_and_empty_lists_are_safe() {
    let mut app = fresh();
    press(&mut app, KeyCode::Char('2'));
    for _ in 0..5 {
        press(&mut app, KeyCode::Down);
    }
    assert_eq!(app.selected, 0, "no rows yet");
    assert!(app.selected_run().is_none() && app.selected_finding().is_none());
    // Every screen renders safely with no data at all, at awkward sizes too.
    for s in Screen::ALL {
        app.screen = s;
        for (w, h) in [(1, 1), (10, 3), (40, 10), (80, 24), (200, 60)] {
            let _ = render_to_string(&app, w, h);
        }
    }
}

#[test]
fn live_state_matches_engine_and_report_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let app = finished_app(VULN, dir.path().to_path_buf());
    let campaign = app.campaign.clone().expect("finished");

    // The TUI shows exactly what the engine produces for the same scenarios.
    let expected = Engine::new().run_campaign(
        VULN,
        0,
        &build_scenarios(VULN, 0, 0, tokenscope_scenarios::SuiteSelection::Core),
    );
    assert_eq!(campaign, expected);
    assert_eq!(app.runs, expected.runs);

    // Findings in the TUI equal findings in the JSON report.
    let report: Report = serde_json::from_str(&render_json(&campaign)).unwrap();
    let tui: Vec<_> = app.findings().into_iter().cloned().collect();
    assert_eq!(tui, report.findings);
    assert!(!tui.is_empty());
}

fn text(app: &App, screen: Screen) -> String {
    let mut a = App::new(app.opts.clone());
    a.runs = app.runs.clone();
    a.total = app.total;
    a.campaign = app.campaign.clone();
    a.running = false;
    a.corpus_cases = app.corpus_cases.clone();
    a.filter = app.filter.clone();
    a.selected = app.selected;
    a.screen = screen;
    render_to_string(&a, 160, 60)
}

#[test]
fn every_screen_renders_real_results() {
    let dir = tempfile::tempdir().unwrap();
    let app = finished_app(VULN, dir.path().to_path_buf());
    let campaign = app.campaign.clone().unwrap();
    let t = campaign.totals();

    let d = text(&app, Screen::Dashboard);
    assert!(d.contains(&campaign.id) && d.contains(VULN));
    assert!(d.contains(&format!("invariant violations: {}", t.invariant_violations)));
    assert!(d.contains(&format!("findings: {}", t.findings)));
    assert!(d.contains(&format!("{0}/{0} scenarios (finished)", app.runs.len())));

    let s = text(&app, Screen::Scenarios);
    for r in &app.runs {
        assert!(s.contains(&r.scenario.name), "missing {}", r.scenario.name);
    }
    assert!(
        s.contains("invariant-violation") && s.contains("pass") && s.contains("execution-failure")
    );

    // Execution inspector for the first scenario with a fee deposit.
    let e = text(&app.with_state("fee-2pct-deposit", 0), Screen::Execution);
    assert!(
        e.contains("fee-2pct-deposit") && e.contains("step 0: Deposit { amount: 1000 }"),
        "{e}"
    );
    assert!(e.contains("vault=980 withheld=20 recorded=1000"), "{e}");
    assert!(
        e.contains("Program log: Instruction: TransferChecked") || e.contains("log:"),
        "{e}"
    );

    let f = text(&app, Screen::Findings);
    assert!(f.contains("INV-ACCT-001") && f.contains("INV-SOLV-001"));
    let first = campaign.findings().next().unwrap();
    assert!(f.contains(&first.id));

    let tk = text(&app.with_state("fee-2pct-deposit", 0), Screen::TokenConfig);
    assert!(
        tk.contains("TransferFeeConfig: 200 bp") && tk.contains("vault owner: escrow PDA"),
        "{tk}"
    );

    let iv = text(&app.with_state("fee-2pct-deposit", 0), Screen::Invariants);
    assert!(
        iv.contains("INV-ACCT-001") && iv.contains("preconditions"),
        "{iv}"
    );

    let c = text(&app, Screen::Corpus);
    assert!(
        c.contains("Regression corpus (2)") && c.contains("rc_"),
        "{c}"
    );

    let r = text(&app, Screen::Reports);
    assert!(r.contains(&campaign.id) && r.contains("Press e to export"));

    let h = text(&app, Screen::Help);
    assert!(
        h.contains("Shortcuts")
            && h.contains("Limitations")
            && h.contains("not proof of exploitability")
    );
}

trait WithState {
    fn with_state(&self, filter: &str, selected: usize) -> App;
}

impl WithState for App {
    fn with_state(&self, filter: &str, selected: usize) -> App {
        let mut a = App::new(self.opts.clone());
        a.runs = self.runs.clone();
        a.campaign = self.campaign.clone();
        a.running = false;
        a.filter = filter.into();
        a.selected = selected;
        a
    }
}

#[test]
fn filter_narrows_the_scenario_list() {
    let dir = tempfile::tempdir().unwrap();
    let base = finished_app(FIXED, dir.path().to_path_buf());
    let mut app = base.with_state("zero-amount", 0);
    app.screen = Screen::Scenarios;
    let out = render_to_string(&app, 140, 30);
    assert!(
        out.contains("zero-amount-deposit") && !out.contains("large-amount"),
        "{out}"
    );
    assert_eq!(app.visible_runs().len(), 1);
    app.filter = "pass".into(); // matches on outcome label too
    assert!(app.visible_runs().len() >= 5);
}

#[test]
fn export_and_corpus_replay_perform_real_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = finished_app(VULN, dir.path().join("out"));
    press(&mut app, KeyCode::Char('e'));
    assert_eq!(app.pending, Some(Command::Export));
    let cmd = app.pending.take().unwrap();
    assert!(execute(&mut app, cmd).is_none());
    let a = app.artifacts.clone().expect("artifacts");
    assert!(a.campaign.exists() && a.report_json.exists() && !a.findings.is_empty());
    assert!(app.status.starts_with("exported to"));
    app.screen = Screen::Reports;
    assert!(render_to_string(&app, 160, 40).contains(&a.report_json.display().to_string()));

    app.screen = Screen::Corpus;
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    let Some(Command::ReplayCase(id)) = app.pending.take() else {
        panic!("expected replay request")
    };
    execute(&mut app, Command::ReplayCase(id.clone()));
    assert!(app.corpus_results[&id].ok, "{:?}", app.corpus_results[&id]);
    assert!(render_to_string(&app, 160, 40).contains("PASS"));
}

#[test]
fn rerun_with_toggled_target_produces_the_corrected_campaign() {
    let dir = tempfile::tempdir().unwrap();
    let mut app = finished_app(VULN, dir.path().to_path_buf());
    assert!(app.campaign.as_ref().unwrap().totals().invariant_violations > 0);
    press(&mut app, KeyCode::Char('t'));
    let cmd = app.pending.take().unwrap();
    let rx = execute(&mut app, cmd).expect("new runner");
    assert!(app.running && app.runs.is_empty() && app.campaign.is_none());
    finish(&mut app, rx);
    let c = app.campaign.unwrap();
    assert_eq!(c.target, FIXED);
    assert_eq!(c.totals().invariant_violations, 0);
    assert!(c.runs.iter().any(|r| r.outcome == OutcomeClass::Pass));
}

#[test]
fn extended_mode_and_profiles_suite_render_13_invariants_and_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(FIXED, dir.path().join("out"));
    o.suite = tokenscope_scenarios::SuiteSelection::Profiles;
    o.extended = true;

    let mut app = App::new(o.clone());
    load_corpus(&mut app);
    let rx = spawn(
        o.target.clone(),
        o.seed,
        o.count,
        o.suite,
        o.extended,
        o.program_dir.clone(),
    );
    finish(&mut app, rx);

    // Dashboard displays suite & extended invariant count.
    let dash = text(&app, Screen::Dashboard);
    assert!(
        dash.contains("suite: Profiles") && dash.contains("invariants: extended (13)"),
        "{dash}"
    );

    // Scenarios list displays mint extensions for profile scenarios.
    let sc = text(&app, Screen::Scenarios);
    assert!(
        sc.contains("profile-rwa-regulated-mint")
            && sc.contains("[pausable,default_account_state,permanent_delegate]"),
        "{sc}"
    );

    // TokenConfig displays all configured extensions for the RWA regulated mint profile.
    let tk = text(
        &app.with_state("profile-rwa-regulated-mint", 0),
        Screen::TokenConfig,
    );
    assert!(
        tk.contains("DefaultAccountState: frozen=true")
            && tk.contains("Pausable")
            && tk.contains("PermanentDelegate"),
        "{tk}"
    );

    // Findings include extended invariants (INV-ZERO-001 alongside INV-CUST-001).
    let fd = text(&app, Screen::Findings);
    assert!(
        fd.contains("INV-ZERO-001") && fd.contains("INV-CUST-001"),
        "{fd}"
    );

    // Invariants screen lists all 13 invariants and evaluates extended verdicts on traces.
    let mut inv_app = app.with_state("profile-micro-fee-dust-truncation", 0);
    inv_app.screen = Screen::Invariants;
    inv_app.invariant_sel = 6; // ZERO_001 (index 6 in extended_catalog)
    let iv = render_to_string(&inv_app, 160, 60);
    assert!(
        iv.contains("Invariants (13 extended)")
            && iv.contains("INV-ZERO-001")
            && iv.contains("INV-HOOK-001")
            && iv.contains("VIOLATED - observed:"),
        "{iv}"
    );

    // Help displays extended settings, all 13 invariant IDs, and the `x` shortcut.
    let hp = text(&app, Screen::Help);
    assert!(
        hp.contains("invariants: extended (13)")
            && hp.contains("INV-HOOK-001")
            && hp.contains("toggle 6/13 invariants"),
        "{hp}"
    );

    // Reports show Markdown & SARIF exports alongside JSON/text.
    press(&mut app, KeyCode::Char('e'));
    let cmd = app.pending.take().unwrap();
    assert!(execute(&mut app, cmd).is_none());
    app.screen = Screen::Reports;
    let rp = render_to_string(&app, 160, 40);
    assert!(rp.contains("MD report:") && rp.contains("SARIF:"), "{rp}");

    // Toggling `x` switches back to core (6) and clamps invariant_sel safely.
    inv_app.invariant_sel = 12;
    press(&mut inv_app, KeyCode::Char('x'));
    assert!(!inv_app.opts.extended);
    assert!(inv_app.invariant_sel < 6);
    assert_eq!(inv_app.pending, Some(Command::Rerun));
}
