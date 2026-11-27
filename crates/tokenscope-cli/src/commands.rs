//! Command implementations.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use tokenscope_adapter::{EscrowFlavor, default_program_dir};
use tokenscope_core::{
    Engine, TARGETS,
    corpus::{Corpus, CorpusError, replay_case},
};
use tokenscope_executor::{sha256_hex, token_2022_elf_sha256};
use tokenscope_invariants::{catalog, extended_catalog};
use tokenscope_model::{
    Campaign, CorpusCase, Expectation, Finding, ModelError, OutcomeClass, Scenario,
};
use tokenscope_report::{render_json, render_markdown, render_sarif, render_text, write_artifacts};
use tokenscope_scenarios::{
    SuiteSelection, builtin_suite, extension_suite, generate, generate_extended, generate_guided,
    generate_stateful, mint_profile_suite,
};
use tokenscope_shrinker::{ShrinkConfig, ShrinkError};

use crate::{
    Command, CorpusCommand, EXIT_NOT_REPRODUCED, EXIT_OK, EXIT_SETUP, EXIT_USAGE, EXIT_VIOLATIONS,
    Format,
};

const DEFAULT_CORPUS: &str = "fixtures/corpus";
const MAX_GENERATED: usize = 10_000;
const MAX_SHRINK_ATTEMPTS: usize = 100_000;

/// CLI failures, each mapped to an exit code.
#[derive(Debug, Error)]
pub enum CliError {
    /// Invalid usage or input.
    #[error("{0}")]
    Usage(String),
    /// Setup or environment problem.
    #[error("{0}")]
    Setup(String),
    /// Expected behavior did not reproduce.
    #[error("{0}")]
    NotReproduced(String),
    /// Failure writing output.
    #[error("output error: {0}")]
    Io(#[from] std::io::Error),
}

impl CliError {
    /// Exit code for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EXIT_USAGE,
            Self::Setup(_) | Self::Io(_) => EXIT_SETUP,
            Self::NotReproduced(_) => EXIT_NOT_REPRODUCED,
        }
    }
}

type Result<T> = std::result::Result<T, CliError>;

fn usage(e: impl ToString) -> CliError {
    CliError::Usage(e.to_string())
}

fn read_file(path: &Path) -> Result<String> {
    tokenscope_core::read_document(path)
        .map_err(|e| CliError::Usage(format!("cannot read {}: {e}", path.display())))
}

fn model_err(path: &Path, e: ModelError) -> CliError {
    CliError::Usage(format!("{}: {e}", path.display()))
}

fn corpus_err(e: CorpusError) -> CliError {
    match e {
        CorpusError::NotFound(_) | CorpusError::Invalid { .. } => CliError::Usage(e.to_string()),
        CorpusError::Io { .. } => CliError::Setup(e.to_string()),
    }
}

fn out_dir(out: Option<PathBuf>) -> PathBuf {
    out.or_else(|| std::env::var_os("TOKENSCOPE_OUT").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("tokenscope-out"))
}

fn corpus_dir(c: Option<PathBuf>) -> PathBuf {
    c.unwrap_or_else(|| PathBuf::from(DEFAULT_CORPUS))
}

fn parse_suite(name: &str) -> Result<SuiteSelection> {
    SuiteSelection::parse(name).ok_or_else(|| {
        usage(format!(
            "unknown suite `{name}`; expected none, core, extensions, profiles, all or full"
        ))
    })
}

fn suite_arg(suite: &str, no_suite: bool) -> Result<SuiteSelection> {
    if no_suite {
        Ok(SuiteSelection::None)
    } else {
        parse_suite(suite)
    }
}

fn resolve_targets(target: &str) -> Result<Vec<String>> {
    if target == "demo-escrow" {
        return Ok(TARGETS.iter().map(|t| (*t).to_string()).collect());
    }
    if TARGETS.contains(&target) {
        return Ok(vec![target.to_string()]);
    }
    Err(CliError::Usage(format!(
        "unknown target `{target}`; known targets: demo-escrow, {}",
        TARGETS.join(", ")
    )))
}

/// JSON run configuration (`tokenscope run --config`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConfig {
    schema_version: u32,
    target: String,
    #[serde(default)]
    seed: u64,
    #[serde(default)]
    generated: usize,
    #[serde(default = "yes")]
    builtin_suite: bool,
    /// `none | core | extensions | profiles | all | full`; when present it overrides `builtin_suite`.
    #[serde(default)]
    suite: Option<String>,
    /// `random | extended | guided` (default `random`).
    #[serde(default)]
    strategy: Option<String>,
    /// Enable the 13-invariant extended set.
    #[serde(default)]
    extended: bool,
}

fn yes() -> bool {
    true
}

pub(crate) fn dispatch(cmd: Command, out: &mut dyn Write) -> Result<i32> {
    match cmd {
        Command::Doctor => doctor(out),
        Command::Inspect { target, extended } => inspect(target, extended, out),
        Command::Run {
            target,
            seed,
            count,
            strategy,
            corpus,
            suite,
            no_suite,
            extended,
            config,
            out: out_path,
        } => {
            let (target, seed, count, suite, strategy, extended) = match config {
                Some(path) => {
                    let text = read_file(&path)?;
                    let c: RunConfig = serde_json::from_str(&text)
                        .map_err(|e| usage(format!("{}: {e}", path.display())))?;
                    if c.schema_version != tokenscope_model::SCHEMA_VERSION {
                        return Err(usage(format!(
                            "{}: unsupported schema_version {}",
                            path.display(),
                            c.schema_version
                        )));
                    }
                    let sel = match &c.suite {
                        Some(name) => parse_suite(name)?,
                        None if c.builtin_suite => SuiteSelection::Core,
                        None => SuiteSelection::None,
                    };
                    let strategy = parse_strategy(c.strategy.as_deref().unwrap_or("random"))?;
                    (
                        c.target,
                        c.seed,
                        c.generated,
                        sel,
                        strategy,
                        c.extended || extended,
                    )
                }
                None => {
                    let t = target.ok_or_else(|| usage("`run` needs --target or --config"))?;
                    (
                        t,
                        seed,
                        count,
                        suite_arg(&suite, no_suite)?,
                        parse_strategy(&strategy)?,
                        extended,
                    )
                }
            };
            let spec = RunSpec {
                target,
                seed,
                count,
                suite,
                strategy,
                corpus: corpus_dir(corpus),
                extended,
            };
            run_campaigns(&spec, out_dir(out_path), out)
        }
        Command::Replay {
            scenario_file,
            extended,
        } => replay(&scenario_file, extended, out),
        Command::Minimize {
            finding_file,
            out: out_path,
            max_attempts,
            extended,
        } => minimize(&finding_file, out_path, max_attempts, extended, out),
        Command::Report {
            campaign_id,
            format,
            out: out_path,
        } => report(&campaign_id, format, out_dir(out_path), out),
        Command::Tui {
            target,
            seed,
            count,
            suite,
            no_suite,
            extended,
            out: out_path,
            corpus,
            snapshot,
        } => {
            let opts = tokenscope_tui::Options {
                target,
                seed,
                count,
                suite: suite_arg(&suite, no_suite)?,
                extended,
                out_dir: out_dir(out_path),
                corpus_dir: corpus_dir(corpus),
                program_dir: None,
            };
            tui(opts, snapshot, out)
        }
        Command::Corpus { command } => corpus(command, out),
        Command::Completion { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(shell, &mut crate::Cli::command(), "tokenscope", out);
            Ok(EXIT_OK)
        }
    }
}

/// A built program file as seen by `doctor`.
struct ProgramFile {
    name: &'static str,
    path: PathBuf,
    /// `Ok((size, sha256))` or the read error.
    status: std::result::Result<(usize, String), String>,
}

fn programs_status() -> Vec<ProgramFile> {
    let dir = default_program_dir();
    ["demo_escrow_vulnerable.so", "demo_escrow_corrected.so"]
        .into_iter()
        .map(|name| {
            let path = dir.join(name);
            let status = fs::read(&path)
                .map(|b| (b.len(), sha256_hex(&b)))
                .map_err(|e| format!("{}: {e}", path.display()));
            ProgramFile { name, path, status }
        })
        .collect()
}

fn on_path(binary: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join(binary).is_file()))
}

fn doctor(out: &mut dyn Write) -> Result<i32> {
    let mut failed = false;
    writeln!(
        out,
        "TokenScope doctor (version {})",
        env!("CARGO_PKG_VERSION")
    )?;
    for p in programs_status() {
        match p.status {
            Ok((size, hash)) => writeln!(
                out,
                "[ok]   program {}: {size} bytes, sha256 {hash} ({})",
                p.name,
                p.path.display()
            )?,
            Err(e) => {
                failed = true;
                writeln!(
                    out,
                    "[FAIL] program {}: {e}\n       build with scripts/build-programs.sh",
                    p.name
                )?;
            }
        }
    }
    writeln!(
        out,
        "[ok]   bundled Token-2022 ELF sha256 {}",
        token_2022_elf_sha256()
    )?;
    match tokenscope_executor::self_check() {
        Ok(m) => writeln!(out, "[ok]   real Token-2022 execution: {m}")?,
        Err(e) => {
            failed = true;
            writeln!(out, "[FAIL] real Token-2022 execution: {e}")?;
        }
    }
    for tool in ["cargo-build-sbf", "rtk"] {
        writeln!(
            out,
            "[info] {tool}: {}",
            if on_path(tool) {
                "found on PATH"
            } else {
                "not found on PATH (only needed for development)"
            }
        )?;
    }
    writeln!(
        out,
        "{}",
        if failed {
            "doctor: problems found"
        } else {
            "doctor: environment OK"
        }
    )?;
    Ok(if failed { EXIT_SETUP } else { EXIT_OK })
}

fn inspect(target: Option<String>, extended: bool, out: &mut dyn Write) -> Result<i32> {
    let targets = match target {
        Some(t) => resolve_targets(&t)?,
        None => TARGETS.iter().map(|t| (*t).to_string()).collect(),
    };
    for t in &targets {
        let Some(flavor) = EscrowFlavor::from_target_id(t) else {
            continue;
        };
        writeln!(out, "target: {t}")?;
        writeln!(
            out,
            "  behavior: {}",
            match flavor {
                EscrowFlavor::Vulnerable =>
                    "Deposit credits the nominal amount (assumes amount received == amount sent)",
                EscrowFlavor::Corrected =>
                    "Deposit credits the vault balance delta measured around the transfer",
            }
        )?;
        writeln!(out, "  program dir: {}", default_program_dir().display())?;
        writeln!(
            out,
            "  accounts: escrow_state (program-owned, 105 bytes), escrow_authority (PDA seeds [\"escrow\", state]), vault (Token-2022 account owned by the PDA), depositor_source, withdraw_destination, mint"
        )?;
        writeln!(
            out,
            "  instructions: init [0]; deposit [1, amount:u64 LE]; withdraw [2]"
        )?;
        writeln!(
            out,
            "  core suite: {}",
            builtin_suite(t)
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "  extensions suite: {}",
            extension_suite(t)
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(
            out,
            "  profiles suite: {}",
            mint_profile_suite(t)
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    writeln!(out, "\ninvariants:")?;
    let defs: Vec<_> = if extended {
        extended_catalog().to_vec()
    } else {
        catalog().to_vec()
    };
    for d in defs {
        writeln!(
            out,
            "  {} {}\n    expected: {}\n    preconditions: {}\n    exceptions: {}",
            d.id,
            d.name,
            d.expected,
            d.preconditions.join("; "),
            d.exceptions.join("; ")
        )?;
    }
    writeln!(
        out,
        "\nToken-2022 program: bundled mainnet-dump ELF, sha256 {}",
        token_2022_elf_sha256()
    )?;
    Ok(EXIT_OK)
}

fn exit_for(c: &Campaign) -> i32 {
    let t = c.totals();
    if t.setup_errors > 0 {
        EXIT_SETUP
    } else if t.invariant_violations > 0 {
        EXIT_VIOLATIONS
    } else {
        EXIT_OK
    }
}

/// How generated scenarios are produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strategy {
    Random,
    Extended,
    Guided,
    Stateful,
}

fn parse_strategy(name: &str) -> Result<Strategy> {
    match name {
        "random" => Ok(Strategy::Random),
        "extended" => Ok(Strategy::Extended),
        "guided" => Ok(Strategy::Guided),
        "stateful" => Ok(Strategy::Stateful),
        other => Err(usage(format!(
            "unknown strategy `{other}`; expected random, extended, guided or stateful"
        ))),
    }
}

/// Everything that defines a `run` campaign.
struct RunSpec {
    target: String,
    seed: u64,
    count: usize,
    suite: SuiteSelection,
    strategy: Strategy,
    corpus: PathBuf,
    extended: bool,
}

fn run_campaigns(spec: &RunSpec, out_path: PathBuf, out: &mut dyn Write) -> Result<i32> {
    if spec.count > MAX_GENERATED {
        return Err(usage(format!(
            "generated scenario count {} exceeds the limit of {MAX_GENERATED}",
            spec.count
        )));
    }
    let targets = resolve_targets(&spec.target)?;
    if spec.suite == SuiteSelection::None && spec.count == 0 {
        return Err(usage(
            "nothing to run: enable the built-in suite or request generated scenarios",
        ));
    }
    let corpus_cases = if spec.strategy == Strategy::Guided {
        Corpus::open(spec.corpus.clone())
            .list()
            .map_err(corpus_err)?
    } else {
        vec![]
    };
    let engine = if spec.extended {
        Engine::with_extended_invariants()
    } else {
        Engine::new()
    };
    let mut code = EXIT_OK;
    for t in targets {
        let mut scenarios: Vec<Scenario> = spec.suite.scenarios(&t);
        match spec.strategy {
            Strategy::Random => scenarios.extend(generate(spec.seed, spec.count, &t)),
            Strategy::Extended => scenarios.extend(generate_extended(spec.seed, spec.count, &t)),
            Strategy::Stateful => scenarios.extend(generate_stateful(spec.seed, spec.count, &t)),
            Strategy::Guided => {
                // Seeds: both built-in suites and the corpus, so the batch complements them.
                let mut seeds = SuiteSelection::All.scenarios(&t);
                seeds.extend(corpus_cases.iter().map(|c| c.scenario.clone()));
                let batch = generate_guided(spec.seed, spec.count, &t, &seeds);
                writeln!(
                    out,
                    "guided generation: selected {} of {} candidates ({} redundant skipped); input-space coverage {}/{} cells (not code coverage)",
                    batch.scenarios.len(),
                    batch.candidates,
                    batch.redundant,
                    batch.coverage.universe_hit(),
                    tokenscope_scenarios::universe().len()
                )?;
                scenarios.extend(batch.scenarios);
            }
        }
        let campaign = engine.run_campaign(&t, spec.seed, &scenarios);
        let artifacts =
            write_artifacts(&campaign, &out_path).map_err(|e| CliError::Setup(e.to_string()))?;
        write!(out, "{}", render_text(&campaign))?;
        writeln!(out, "artifacts: {}\n", artifacts.dir.display())?;
        code = code.max(exit_for(&campaign).max(0));
    }
    // 3 (setup) outranks 1 (violations) outranks 0; max() on these codes preserves that order.
    Ok(code)
}

fn replay(path: &Path, extended: bool, out: &mut dyn Write) -> Result<i32> {
    let scenario = Scenario::from_json(&read_file(path)?).map_err(|e| model_err(path, e))?;
    let engine = if extended {
        Engine::with_extended_invariants()
    } else {
        Engine::new()
    };
    let run = engine.run_scenario(&scenario);
    let campaign = Campaign::new(scenario.target.clone(), scenario.seed, vec![run]);
    write!(out, "{}", render_text(&campaign))?;
    Ok(exit_for(&campaign))
}

fn minimize(
    path: &Path,
    out_path: Option<PathBuf>,
    max_attempts: usize,
    extended: bool,
    out: &mut dyn Write,
) -> Result<i32> {
    if max_attempts > MAX_SHRINK_ATTEMPTS {
        return Err(usage(format!(
            "--max-attempts {max_attempts} exceeds the limit of {MAX_SHRINK_ATTEMPTS}"
        )));
    }
    let finding = Finding::from_json(&read_file(path)?).map_err(|e| model_err(path, e))?;
    let engine = if extended {
        Engine::with_extended_invariants()
    } else {
        Engine::new()
    };
    let (minimized, report) = engine
        .minimize(&finding, ShrinkConfig { max_attempts })
        .map_err(|e| match e {
            ShrinkError::InvalidInput(m) => usage(m),
            other => CliError::NotReproduced(other.to_string()),
        })?;
    let dest = out_path.unwrap_or_else(|| PathBuf::from(format!("{}.min.json", path.display())));
    fs::write(&dest, minimized.to_json() + "\n")
        .map_err(|e| CliError::Setup(format!("cannot write {}: {e}", dest.display())))?;
    let m = report.minimized;
    writeln!(
        out,
        "minimized finding {} ({})",
        minimized.id, minimized.invariant_id
    )?;
    writeln!(
        out,
        "  original: {} action(s)  ->  minimized: {} action(s)",
        finding.reproduction.scenario.actions.len(),
        m.actions.len()
    )?;
    writeln!(
        out,
        "  executions: {} ({} accepted){}",
        report.attempts,
        report.accepted,
        if report.budget_exhausted {
            "  [budget exhausted: result may not be minimal]"
        } else {
            ""
        }
    )?;
    writeln!(out, "  minimized scenario {}:\n{}", m.id(), m.to_json())?;
    writeln!(out, "written: {}", dest.display())?;
    Ok(EXIT_OK)
}

fn valid_campaign_id(id: &str) -> bool {
    id.strip_prefix("cp_")
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn report(id: &str, format: Format, dir: PathBuf, out: &mut dyn Write) -> Result<i32> {
    if !valid_campaign_id(id) {
        return Err(usage(format!(
            "`{id}` is not a campaign id (expected cp_ followed by 16 hex digits)"
        )));
    }
    let path = dir.join(id).join("campaign.json");
    let text = tokenscope_core::read_document(&path).map_err(|e| {
        usage(format!(
            "campaign {id} not found at {}: {e}",
            path.display()
        ))
    })?;
    let campaign = Campaign::from_json(&text).map_err(|e| model_err(&path, e))?;
    match format {
        Format::Json => write!(out, "{}", render_json(&campaign))?,
        Format::Text => write!(out, "{}", render_text(&campaign))?,
        Format::Markdown => write!(out, "{}", render_markdown(&campaign))?,
        Format::Sarif => write!(out, "{}", render_sarif(&campaign))?,
    }
    Ok(EXIT_OK)
}

fn corpus(cmd: CorpusCommand, out: &mut dyn Write) -> Result<i32> {
    match cmd {
        CorpusCommand::List { corpus } => {
            let cases = Corpus::open(corpus_dir(corpus))
                .list()
                .map_err(corpus_err)?;
            if cases.is_empty() {
                writeln!(out, "corpus is empty")?;
            }
            for c in cases {
                writeln!(
                    out,
                    "{}  {}  {:?}  violated={:?}  {}",
                    c.id, c.scenario.target, c.expect.outcome, c.expect.violated, c.description
                )?;
            }
            Ok(EXIT_OK)
        }
        CorpusCommand::Replay {
            case_id,
            all,
            corpus,
        } => {
            let corpus = Corpus::open(corpus_dir(corpus));
            let cases = match (case_id, all) {
                (Some(id), false) => vec![corpus.get(&id).map_err(corpus_err)?],
                (None, true) => corpus.list().map_err(corpus_err)?,
                _ => return Err(usage("give a case id or --all")),
            };
            if cases.is_empty() {
                return Err(usage("corpus is empty; nothing to replay"));
            }
            let engine = Engine::new();
            let (mut mismatches, mut setup) = (0, 0);
            for case in &cases {
                let r = replay_case(&engine, case);
                if r.actual.outcome == OutcomeClass::SetupError {
                    setup += 1;
                }
                if !r.ok {
                    mismatches += 1;
                }
                writeln!(
                    out,
                    "{} {}  expected {:?}/{:?}  actual {:?}/{:?}",
                    if r.ok { "PASS" } else { "FAIL" },
                    r.case_id,
                    case.expect.outcome,
                    case.expect.violated,
                    r.actual.outcome,
                    r.actual.violated
                )?;
            }
            writeln!(out, "{} case(s), {} mismatch(es)", cases.len(), mismatches)?;
            Ok(if setup > 0 {
                EXIT_SETUP
            } else if mismatches > 0 {
                EXIT_NOT_REPRODUCED
            } else {
                EXIT_OK
            })
        }
        CorpusCommand::Add {
            scenario_file,
            description,
            corpus,
        } => {
            let scenario = Scenario::from_json(&read_file(&scenario_file)?)
                .map_err(|e| model_err(&scenario_file, e))?;
            let run = Engine::new().run_scenario(&scenario);
            if run.outcome == OutcomeClass::SetupError {
                return Err(CliError::Setup(format!(
                    "refusing to save a case whose setup failed: {}",
                    run.setup_error.unwrap_or_default()
                )));
            }
            let case = CorpusCase::new(description, scenario, Expectation::from_run(&run));
            let path = Corpus::open(corpus_dir(corpus))
                .add(&case)
                .map_err(corpus_err)?;
            writeln!(
                out,
                "saved {} ({:?}, violated={:?}) -> {}",
                case.id,
                case.expect.outcome,
                case.expect.violated,
                path.display()
            )?;
            Ok(EXIT_OK)
        }
    }
}

fn tui(
    opts: tokenscope_tui::Options,
    snapshot: Option<String>,
    out: &mut dyn Write,
) -> Result<i32> {
    use tokenscope_tui::Screen;
    if opts.count > MAX_GENERATED {
        return Err(usage(format!(
            "generated scenario count {} exceeds the limit of {MAX_GENERATED}",
            opts.count
        )));
    }
    if opts.suite == SuiteSelection::None && opts.count == 0 {
        return Err(usage(
            "nothing to run: enable the built-in suite or request generated scenarios",
        ));
    }
    if resolve_targets(&opts.target)?.len() != 1 {
        return Err(usage(
            "the TUI runs one target at a time; press `t` inside it to toggle",
        ));
    }
    match snapshot {
        Some(name) => {
            let screen =
                Screen::parse(&name).ok_or_else(|| usage(format!("unknown screen `{name}`")))?;
            write!(out, "{}", tokenscope_tui::snapshot(opts, screen, 140, 40))?;
            Ok(EXIT_OK)
        }
        None => {
            tokenscope_tui::run_interactive(opts)
                .map_err(|e| CliError::Setup(format!("terminal error: {e}")))?;
            Ok(EXIT_OK)
        }
    }
}
