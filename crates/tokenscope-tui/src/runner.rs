//! Background campaign runner. Execution happens on a worker thread; the UI only receives events.

use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};

use tokenscope_core::{Engine, InvariantRegistry};
use tokenscope_model::{Campaign, RunRecord, Scenario};
use tokenscope_scenarios::{SuiteSelection, generate};

/// Progress events from the worker.
#[derive(Debug)]
pub enum RunEvent {
    /// A campaign with `total` scenarios started.
    Started {
        /// Number of scenarios.
        total: usize,
    },
    /// One scenario finished.
    Run(Box<RunRecord>),
    /// The whole campaign finished.
    Finished(Box<Campaign>),
}

/// Construct an [`Engine`] matching the configured program directory and invariant mode.
pub(crate) fn build_engine(program_dir: Option<&Path>, extended: bool) -> Engine {
    let registry = if extended {
        InvariantRegistry::with_extended_invariants()
    } else {
        InvariantRegistry::default()
    };
    match program_dir {
        Some(d) => Engine::with_program_dir_and_invariants(d.to_path_buf(), registry),
        None => Engine::with_invariants(registry),
    }
}

/// Scenarios a campaign runs: the built-in suite (optional) plus seeded ones.
pub fn build_scenarios(
    target: &str,
    seed: u64,
    count: usize,
    suite: SuiteSelection,
) -> Vec<Scenario> {
    let mut s = suite.scenarios(target);
    s.extend(generate(seed, count, target));
    s
}

/// Start a campaign on a worker thread and return the event stream. Dropping the receiver stops
/// the worker after the current scenario.
pub fn spawn(
    target: String,
    seed: u64,
    count: usize,
    suite: SuiteSelection,
    extended: bool,
    program_dir: Option<PathBuf>,
) -> mpsc::Receiver<RunEvent> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let engine = build_engine(program_dir.as_deref(), extended);
        let scenarios = build_scenarios(&target, seed, count, suite);
        if tx
            .send(RunEvent::Started {
                total: scenarios.len(),
            })
            .is_err()
        {
            return;
        }
        let mut runs = Vec::with_capacity(scenarios.len());
        for s in &scenarios {
            let record = engine.run_scenario(s);
            runs.push(record.clone());
            if tx.send(RunEvent::Run(Box::new(record))).is_err() {
                return;
            }
        }
        let _ = tx.send(RunEvent::Finished(Box::new(Campaign::new(
            target, seed, runs,
        ))));
    });
    rx
}
