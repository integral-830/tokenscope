//! Orchestration of the TokenScope pipeline:
//! `scenario -> real SVM execution -> invariant checking -> findings`.

use std::{
    io,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

pub use tokenscope_adapter::TargetAdapter;
use tokenscope_adapter::{EscrowAdapter, EscrowFlavor};
use tokenscope_invariants::classify;
pub use tokenscope_invariants::{FnInvariant, Invariant, InvariantDef, InvariantRegistry};
use tokenscope_model::{Campaign, Finding, OutcomeClass, RunRecord, Scenario};
use tokenscope_shrinker::{ShrinkConfig, ShrinkError, ShrinkReport, shrink};

pub mod corpus;

/// Largest JSON document (scenario, finding, campaign, trace, corpus case, run config) the tool
/// will read: 32 MiB. Larger inputs are rejected before parsing to bound memory use.
pub const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

/// Read a UTF-8 document, refusing files larger than [`MAX_DOCUMENT_BYTES`] (checked both from
/// metadata and while reading, so a growing or non-regular file cannot bypass the limit).
pub fn read_document(path: &Path) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_DOCUMENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {MAX_DOCUMENT_BYTES}-byte document limit"),
        ));
    }
    let mut text = String::new();
    file.take(MAX_DOCUMENT_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {MAX_DOCUMENT_BYTES}-byte document limit"),
        ));
    }
    Ok(text)
}

/// Target identifiers this build can run.
pub const TARGETS: [&str; 2] = ["demo-escrow-vulnerable", "demo-escrow-corrected"];

/// Result of replaying a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// Whether the finding's invariant was violated again.
    pub reproduced: bool,
    /// The replayed run.
    pub run: RunRecord,
}

/// Runs scenarios and campaigns.
#[derive(Clone)]
pub struct Engine {
    program_dir: Option<PathBuf>,
    registry: Arc<InvariantRegistry>,
}

impl Default for Engine {
    fn default() -> Self {
        Self {
            program_dir: None,
            registry: Arc::new(InvariantRegistry::default()),
        }
    }
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("program_dir", &self.program_dir)
            .field("invariants", &self.registry.len())
            .finish()
    }
}

impl Engine {
    /// Engine that locates built programs automatically and checks the 6 core invariants.
    pub fn new() -> Self {
        Self::default()
    }

    /// Engine configured with all 13 extended invariants (core 6 + ZERO/DILUT/SYMM + PAUSE/FREEZE/CPI/HOOK).
    pub fn with_extended_invariants() -> Self {
        Self {
            program_dir: None,
            registry: Arc::new(InvariantRegistry::with_extended_invariants()),
        }
    }

    /// Engine using a caller-supplied [`InvariantRegistry`].
    pub fn with_invariants(registry: InvariantRegistry) -> Self {
        Self {
            program_dir: None,
            registry: Arc::new(registry),
        }
    }

    /// Engine that reads built programs from `dir`.
    pub fn with_program_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            program_dir: Some(dir.into()),
            registry: Arc::new(InvariantRegistry::default()),
        }
    }

    /// Engine that reads built programs from `dir` and uses `registry`.
    pub fn with_program_dir_and_invariants(
        dir: impl Into<PathBuf>,
        registry: InvariantRegistry,
    ) -> Self {
        Self {
            program_dir: Some(dir.into()),
            registry: Arc::new(registry),
        }
    }

    /// Definitions of invariants currently enforced by this engine.
    pub fn catalog(&self) -> Vec<InvariantDef> {
        self.registry.catalog()
    }

    /// Borrow the underlying invariant registry.
    pub fn registry(&self) -> &InvariantRegistry {
        &self.registry
    }

    fn adapter(&self, flavor: EscrowFlavor) -> EscrowAdapter {
        match &self.program_dir {
            Some(d) => EscrowAdapter::with_program_dir(flavor, d.clone()),
            None => EscrowAdapter::new(flavor),
        }
    }

    /// Run one scenario using a custom target adapter.
    pub fn run_scenario_with_adapter(
        &self,
        scenario: &Scenario,
        adapter: &dyn TargetAdapter,
    ) -> RunRecord {
        let scenario_id = scenario.id();
        let setup_error = |detail: String| RunRecord {
            scenario: scenario.clone(),
            scenario_id: scenario_id.clone(),
            outcome: OutcomeClass::SetupError,
            setup_error: Some(detail),
            trace: None,
            findings: vec![],
        };
        match adapter.run(scenario) {
            Err(e) => setup_error(e.to_string()),
            Ok(trace) => {
                let evaluations = self.registry.evaluate(&trace);
                RunRecord {
                    scenario: scenario.clone(),
                    scenario_id,
                    outcome: classify(&trace, &evaluations),
                    setup_error: None,
                    findings: self.registry.findings(scenario, &trace, &evaluations),
                    trace: Some(trace),
                }
            }
        }
    }

    /// Run one scenario. Setup problems (unknown target, missing program, invalid scenario) are
    /// classified as [`OutcomeClass::SetupError`] and never produce findings.
    pub fn run_scenario(&self, scenario: &Scenario) -> RunRecord {
        let Some(flavor) = EscrowFlavor::from_target_id(&scenario.target) else {
            return RunRecord {
                scenario: scenario.clone(),
                scenario_id: scenario.id(),
                outcome: OutcomeClass::SetupError,
                setup_error: Some(format!(
                    "unknown target `{}` (known: {})",
                    scenario.target,
                    TARGETS.join(", ")
                )),
                trace: None,
                findings: vec![],
            };
        };
        let adapter = self.adapter(flavor);
        self.run_scenario_with_adapter(scenario, &adapter)
    }

    /// Re-run a finding's reproduction scenario and report whether the same invariant is still
    /// violated. Replay is deterministic: identical inputs give identical runs.
    pub fn replay_finding(&self, finding: &Finding) -> Replay {
        let run = self.run_scenario(&finding.reproduction.scenario);
        let reproduced = run
            .findings
            .iter()
            .any(|f| f.invariant_id == finding.invariant_id);
        Replay { reproduced, run }
    }

    /// Minimize a finding's scenario while the same invariant stays violated, validating every
    /// accepted reduction by real execution. Returns the finding with `minimized` populated plus
    /// shrink statistics.
    pub fn minimize(
        &self,
        finding: &Finding,
        config: ShrinkConfig,
    ) -> Result<(Finding, ShrinkReport), ShrinkError> {
        let invariant = finding.invariant_id.clone();
        let report = shrink(&finding.reproduction.scenario, config, |candidate| {
            self.run_scenario(candidate)
                .findings
                .iter()
                .any(|f| f.invariant_id == invariant)
        })?;
        let mut out = finding.clone();
        out.minimized = Some(report.minimized.clone());
        Ok((out, report))
    }

    /// Run every scenario in order using a custom target adapter and bundle the results.
    pub fn run_campaign_with_adapter(
        &self,
        target: &str,
        seed: u64,
        scenarios: &[Scenario],
        adapter: &dyn TargetAdapter,
    ) -> Campaign {
        let runs = scenarios
            .iter()
            .map(|s| self.run_scenario_with_adapter(s, adapter))
            .collect();
        Campaign::new(target.to_string(), seed, runs)
    }

    /// Run every scenario in order and bundle the results.
    pub fn run_campaign(&self, target: &str, seed: u64, scenarios: &[Scenario]) -> Campaign {
        let runs = scenarios.iter().map(|s| self.run_scenario(s)).collect();
        Campaign::new(target.to_string(), seed, runs)
    }
}
