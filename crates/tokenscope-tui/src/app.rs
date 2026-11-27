//! Pure TUI state and key handling. No terminal I/O and no execution happens here: side effects
//! are requested through [`Command`] and carried out by the driver.

use std::{collections::HashMap, path::PathBuf, time::Duration};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokenscope_invariants::{InvariantDef, InvariantRegistry, catalog, extended_catalog};
use tokenscope_model::{Campaign, CorpusCase, Expectation, Finding, RunRecord};
use tokenscope_report::Artifacts;
use tokenscope_scenarios::SuiteSelection;

use crate::runner::RunEvent;

/// The nine screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Campaign state and progress.
    Dashboard,
    /// Scenario list with filtering.
    Scenarios,
    /// Steps, snapshots and logs of one scenario.
    Execution,
    /// All findings.
    Findings,
    /// Mint configuration, accounts and authorities.
    TokenConfig,
    /// Invariant definitions and verdicts.
    Invariants,
    /// Regression corpus.
    Corpus,
    /// Exports and reproduction details.
    Reports,
    /// Settings, capabilities and shortcuts.
    Help,
}

impl Screen {
    /// All screens in tab order (digit keys 1..=9).
    pub const ALL: [Screen; 9] = [
        Screen::Dashboard,
        Screen::Scenarios,
        Screen::Execution,
        Screen::Findings,
        Screen::TokenConfig,
        Screen::Invariants,
        Screen::Corpus,
        Screen::Reports,
        Screen::Help,
    ];

    /// Short title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Scenarios => "Scenarios",
            Self::Execution => "Execution",
            Self::Findings => "Findings",
            Self::TokenConfig => "Token",
            Self::Invariants => "Invariants",
            Self::Corpus => "Corpus",
            Self::Reports => "Reports",
            Self::Help => "Help",
        }
    }

    /// Parse a screen from its name (case-insensitive) or digit.
    pub fn parse(s: &str) -> Option<Screen> {
        let s = s.to_ascii_lowercase();
        Screen::ALL.iter().copied().enumerate().find_map(|(i, sc)| {
            (sc.title().eq_ignore_ascii_case(&s) || s == (i + 1).to_string()).then_some(sc)
        })
    }

    fn index(self) -> usize {
        Screen::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }
}

/// Settings shown on the help screen and used when (re)running.
#[derive(Debug, Clone)]
pub struct Options {
    /// Target identifier.
    pub target: String,
    /// Seed for generated scenarios.
    pub seed: u64,
    /// Number of generated scenarios.
    pub count: usize,
    /// Which built-in scenarios run.
    pub suite: SuiteSelection,
    /// Whether to evaluate the 13-invariant extended set instead of only the 6 core checks.
    pub extended: bool,
    /// Artifact output directory.
    pub out_dir: PathBuf,
    /// Corpus directory.
    pub corpus_dir: PathBuf,
    /// Program directory override.
    pub program_dir: Option<PathBuf>,
}

/// A side effect the driver must perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Re-run the campaign (possibly with a different target).
    Rerun,
    /// Export the finished campaign's artifacts.
    Export,
    /// Replay the corpus case with this id.
    ReplayCase(String),
}

/// Result of a corpus replay shown in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseOutcome {
    /// Whether the replay matched the expectation.
    pub ok: bool,
    /// What replay produced.
    pub actual: Expectation,
}

/// Full UI state.
#[derive(Debug)]
pub struct App {
    /// Settings.
    pub opts: Options,
    /// Active screen.
    pub screen: Screen,
    /// Completed runs so far (live during a campaign).
    pub runs: Vec<RunRecord>,
    /// Total scenarios in the current campaign.
    pub total: usize,
    /// Finished campaign.
    pub campaign: Option<Campaign>,
    /// Whether a campaign is running.
    pub running: bool,
    /// Wall time since the campaign started (set by the driver).
    pub elapsed: Duration,
    /// Selected row in the (filtered) scenario list.
    pub selected: usize,
    /// Selected finding.
    pub finding_sel: usize,
    /// Selected invariant.
    pub invariant_sel: usize,
    /// Selected corpus case.
    pub corpus_sel: usize,
    /// Scenario filter text.
    pub filter: String,
    /// Whether keystrokes edit the filter.
    pub filtering: bool,
    /// Scroll offset for detail panes.
    pub scroll: u16,
    /// Recent activity lines.
    pub activity: Vec<String>,
    /// Corpus cases loaded from disk.
    pub corpus_cases: Vec<CorpusCase>,
    /// Replay results by case id.
    pub corpus_results: HashMap<String, CaseOutcome>,
    /// Last exported artifacts.
    pub artifacts: Option<Artifacts>,
    /// Status line message.
    pub status: String,
    /// Set when the user asked to quit.
    pub should_quit: bool,
    /// Side effect requested by the last key press.
    pub pending: Option<Command>,
}

impl App {
    /// New app in the "running" state for `opts`.
    pub fn new(opts: Options) -> Self {
        Self {
            opts,
            screen: Screen::Dashboard,
            runs: vec![],
            total: 0,
            campaign: None,
            running: true,
            elapsed: Duration::ZERO,
            selected: 0,
            finding_sel: 0,
            invariant_sel: 0,
            corpus_sel: 0,
            filter: String::new(),
            filtering: false,
            scroll: 0,
            activity: vec![],
            corpus_cases: vec![],
            corpus_results: HashMap::new(),
            artifacts: None,
            status: "running campaign...".into(),
            should_quit: false,
            pending: None,
        }
    }

    /// Reset run state before a re-run (keeps screen, filter and settings).
    pub fn reset_run(&mut self) {
        self.runs.clear();
        self.total = 0;
        self.campaign = None;
        self.running = true;
        self.elapsed = Duration::ZERO;
        self.selected = 0;
        self.finding_sel = 0;
        self.artifacts = None;
        self.scroll = 0;
        self.activity.clear();
        self.status = "running campaign...".into();
    }

    /// Apply an event from the runner.
    pub fn apply(&mut self, ev: RunEvent) {
        match ev {
            RunEvent::Started { total } => {
                self.total = total;
                self.push_activity(format!("started {total} scenarios on {}", self.opts.target));
            }
            RunEvent::Run(rec) => {
                self.push_activity(format!("{:?} {}", rec.outcome, rec.scenario.name));
                self.runs.push(*rec);
            }
            RunEvent::Finished(c) => {
                self.running = false;
                let t = c.totals();
                self.status = format!("finished: {} findings", t.findings);
                self.push_activity(format!("finished campaign {}", c.id));
                self.campaign = Some(*c);
            }
        }
    }

    fn push_activity(&mut self, line: String) {
        self.activity.push(line);
        let overflow = self.activity.len().saturating_sub(200);
        self.activity.drain(..overflow);
    }

    /// Indices into `runs` that match the filter.
    pub fn visible_runs(&self) -> Vec<usize> {
        let f = self.filter.to_lowercase();
        self.runs
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                f.is_empty()
                    || r.scenario.name.to_lowercase().contains(&f)
                    || r.scenario_id.to_lowercase().contains(&f)
                    || format!("{:?}", r.outcome).to_lowercase().contains(&f)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Currently selected run.
    pub fn selected_run(&self) -> Option<&RunRecord> {
        let v = self.visible_runs();
        v.get(self.selected.min(v.len().saturating_sub(1)))
            .map(|&i| &self.runs[i])
    }

    /// All findings in run order.
    pub fn findings(&self) -> Vec<&Finding> {
        self.runs.iter().flat_map(|r| r.findings.iter()).collect()
    }

    /// Currently selected finding.
    pub fn selected_finding(&self) -> Option<&Finding> {
        let f = self.findings();
        f.get(self.finding_sel.min(f.len().saturating_sub(1)))
            .copied()
    }

    /// Invariant registry matching [`Options::extended`].
    pub fn invariant_registry(&self) -> InvariantRegistry {
        if self.opts.extended {
            InvariantRegistry::with_extended_invariants()
        } else {
            InvariantRegistry::default()
        }
    }

    /// Invariant definitions active under [`Options::extended`].
    pub fn invariant_catalog(&self) -> Vec<InvariantDef> {
        if self.opts.extended {
            extended_catalog().to_vec()
        } else {
            catalog().to_vec()
        }
    }

    fn list_len(&self) -> usize {
        match self.screen {
            Screen::Scenarios | Screen::Execution | Screen::TokenConfig => {
                self.visible_runs().len()
            }
            Screen::Findings => self.findings().len(),
            Screen::Invariants => self.invariant_catalog().len(),
            Screen::Corpus => self.corpus_cases.len(),
            _ => 0,
        }
    }

    fn selection_mut(&mut self) -> Option<&mut usize> {
        match self.screen {
            Screen::Scenarios | Screen::Execution | Screen::TokenConfig => Some(&mut self.selected),
            Screen::Findings => Some(&mut self.finding_sel),
            Screen::Invariants => Some(&mut self.invariant_sel),
            Screen::Corpus => Some(&mut self.corpus_sel),
            _ => None,
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.list_len();
        let screen_has_sel = self.selection_mut().is_some();
        if let Some(sel) = self.selection_mut() {
            let max = len.saturating_sub(1) as isize;
            *sel = (*sel as isize + delta).clamp(0, max) as usize;
        }
        if screen_has_sel {
            self.scroll = 0;
        }
    }

    fn goto(&mut self, screen: Screen) {
        self.screen = screen;
        self.scroll = 0;
    }

    /// Handle one key press.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filtering = false;
                    self.selected = 0;
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.selected = 0;
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.filter.push(c);
                    self.selected = 0;
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char(d @ '1'..='9') => self.goto(Screen::ALL[d as usize - '1' as usize]),
            KeyCode::Char('?') => self.goto(Screen::Help),
            KeyCode::Tab => self.goto(Screen::ALL[(self.screen.index() + 1) % Screen::ALL.len()]),
            KeyCode::BackTab => {
                let n = Screen::ALL.len();
                self.goto(Screen::ALL[(self.screen.index() + n - 1) % n]);
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => {
                if self.selection_mut().is_some()
                    && matches!(self.screen, Screen::Scenarios | Screen::Corpus)
                {
                    self.move_selection(10);
                } else {
                    self.scroll = self.scroll.saturating_add(5);
                }
            }
            KeyCode::PageUp => {
                if self.selection_mut().is_some()
                    && matches!(self.screen, Screen::Scenarios | Screen::Corpus)
                {
                    self.move_selection(-10);
                } else {
                    self.scroll = self.scroll.saturating_sub(5);
                }
            }
            KeyCode::Home => self.move_selection(isize::MIN / 2),
            KeyCode::End => self.move_selection(isize::MAX / 2),
            KeyCode::Char('/') if self.screen == Screen::Scenarios => self.filtering = true,
            KeyCode::Char('t') => {
                self.opts.target = if self.opts.target == "demo-escrow-vulnerable" {
                    "demo-escrow-corrected".into()
                } else {
                    "demo-escrow-vulnerable".into()
                };
                self.pending = Some(Command::Rerun);
            }
            KeyCode::Char('x') => {
                self.opts.extended = !self.opts.extended;
                let max_idx = self.invariant_catalog().len().saturating_sub(1);
                self.invariant_sel = self.invariant_sel.min(max_idx);
                self.pending = Some(Command::Rerun);
            }
            KeyCode::Char('r') => self.pending = Some(Command::Rerun),
            KeyCode::Char('e') => {
                if self.campaign.is_some() {
                    self.pending = Some(Command::Export);
                } else {
                    self.status =
                        "campaign still running; export is available when it finishes".into();
                }
            }
            KeyCode::Char('p') | KeyCode::Enter if self.screen == Screen::Corpus => {
                if let Some(c) = self.corpus_cases.get(self.corpus_sel) {
                    self.pending = Some(Command::ReplayCase(c.id.clone()));
                }
            }
            _ => {}
        }
    }
}
