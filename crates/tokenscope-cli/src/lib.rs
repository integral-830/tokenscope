//! Command-line interface. All behavior lives here (not in `main`) so it is testable and the CLI
//! works independently of the TUI.
//!
//! Exit codes: `0` success / no invariant violations; `1` invariant violations found;
//! `2` invalid usage or input; `3` setup or environment error; `4` a failure or corpus case did
//! not reproduce as expected.

mod commands;

use std::{ffi::OsString, io::Write, path::PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

/// Exit code: success.
pub const EXIT_OK: i32 = 0;
/// Exit code: invariant violations found.
pub const EXIT_VIOLATIONS: i32 = 1;
/// Exit code: invalid usage or input.
pub const EXIT_USAGE: i32 = 2;
/// Exit code: setup or environment error.
pub const EXIT_SETUP: i32 = 3;
/// Exit code: expected behavior did not reproduce.
pub const EXIT_NOT_REPRODUCED: i32 = 4;

/// Top-level arguments.
#[derive(Debug, Parser)]
#[command(
    name = "tokenscope",
    version,
    about = "Adversarial testing for Solana Token-2022 integrations"
)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Report output format.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Format {
    /// Versioned JSON report.
    Json,
    /// Human-readable text.
    Text,
    /// Markdown security audit report.
    Markdown,
    /// SARIF 2.1.0 report for code scanning and CI integrations.
    Sarif,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify the environment (programs, bundled Token-2022, real execution).
    Doctor,
    /// Show target configuration, accounts, instructions and invariants.
    Inspect {
        /// Target (`demo-escrow-vulnerable`, `demo-escrow-corrected`); default: all.
        #[arg(long)]
        target: Option<String>,
        /// Also list the extended DeFi and Token-2022 policy invariants (13 total).
        #[arg(long)]
        extended: bool,
    },
    /// Run a campaign (built-in suite plus seeded scenarios).
    Run {
        /// Target, or `demo-escrow` for both flavors.
        #[arg(long, conflicts_with = "config")]
        target: Option<String>,
        /// Seed for generated scenarios.
        #[arg(long, default_value_t = 0, conflicts_with = "config")]
        seed: u64,
        /// Number of generated scenarios.
        #[arg(long, default_value_t = 20, conflicts_with = "config")]
        count: usize,
        /// How scenarios are generated: `random` (fee scenarios), `extended` (extension and
        /// adversarial templates), `guided` (dimension-guided selection seeded by the built-in
        /// suites and the regression corpus; not code-coverage-guided), or `stateful` (model-based
        /// sequence generation using TokenReferenceModel).
        #[arg(long, default_value = "random", conflicts_with = "config")]
        strategy: String,
        /// Corpus directory whose scenarios seed `--strategy guided` (default: `fixtures/corpus`).
        #[arg(long, conflicts_with = "config")]
        corpus: Option<PathBuf>,
        /// Built-in scenarios: `core` (fee accounting), `extensions`, `profiles`, `all`, `full`, or `none`.
        #[arg(long, default_value = "core", conflicts_with = "config")]
        suite: String,
        /// Shorthand for `--suite none`.
        #[arg(long, conflicts_with = "config")]
        no_suite: bool,
        /// Enable the 13-invariant extended set (core 6 + ZERO/DILUT/SYMM + PAUSE/FREEZE/CPI/HOOK).
        #[arg(long)]
        extended: bool,
        /// JSON run configuration (see FORMAT.md).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output directory for artifacts (default: `tokenscope-out` or `$TOKENSCOPE_OUT`).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Re-run one scenario file.
    Replay {
        /// Scenario JSON file.
        scenario_file: PathBuf,
        /// Evaluate the 13-invariant extended set instead of only the core 6.
        #[arg(long)]
        extended: bool,
    },
    /// Minimize a finding's scenario while its invariant stays violated.
    Minimize {
        /// Finding JSON file.
        finding_file: PathBuf,
        /// Where to write the minimized finding (default: `<finding-file>.min.json`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Maximum number of executions spent shrinking.
        #[arg(long, default_value_t = 300)]
        max_attempts: usize,
        /// Evaluate the 13-invariant extended set while shrinking (needed for INV-ZERO/DILUT/SYMM/PAUSE/FREEZE/CPI/HOOK findings).
        #[arg(long)]
        extended: bool,
    },
    /// Print a stored campaign's report.
    Report {
        /// Campaign identifier (`cp_...`).
        campaign_id: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "json")]
        format: Format,
        /// Artifact directory the campaign was written to.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Open the interactive terminal UI over a live campaign.
    Tui {
        /// Target to run (`demo-escrow-vulnerable` or `demo-escrow-corrected`).
        #[arg(long, default_value = "demo-escrow-vulnerable")]
        target: String,
        /// Seed for generated scenarios.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Number of generated scenarios.
        #[arg(long, default_value_t = 0)]
        count: usize,
        /// Built-in scenarios: `core` (fee accounting), `extensions`, `profiles`, `all`, `full`, or `none`.
        #[arg(long, default_value = "core")]
        suite: String,
        /// Shorthand for `--suite none`.
        #[arg(long)]
        no_suite: bool,
        /// Enable the 13-invariant extended set (core 6 + ZERO/DILUT/SYMM + PAUSE/FREEZE/CPI/HOOK).
        #[arg(long)]
        extended: bool,
        /// Artifact directory used by the export key (default: `tokenscope-out`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Corpus directory (default: `fixtures/corpus`).
        #[arg(long)]
        corpus: Option<PathBuf>,
        /// Run the campaign headlessly and print one screen as text (dashboard, scenarios,
        /// execution, findings, token, invariants, corpus, reports, help) instead of opening the UI.
        #[arg(long)]
        snapshot: Option<String>,
    },
    /// Manage the regression corpus.
    Corpus {
        /// Corpus operation.
        #[command(subcommand)]
        command: CorpusCommand,
    },
    /// Run a target-agnostic SBF batch spec JSON via `GenericSbfAdapter`.
    SbfRun {
        /// Generic SBF batch spec JSON file.
        #[arg(long)]
        spec: PathBuf,
        /// Output format: `json` (full observations and findings) or `text` (summary).
        #[arg(long, default_value = "json")]
        format: String,
        /// Also write the spec's check findings as a SARIF 2.1.0 file.
        #[arg(long)]
        sarif: Option<PathBuf>,
    },
    /// Run a persistent newline-delimited JSON-RPC `GenericSbfSession` worker over stdio.
    SbfSession,
    /// Generate shell autocompletion script.
    Completion {
        /// Shell to generate completions for (`bash`, `zsh`, `fish`, `powershell`, `elvish`).
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// Corpus subcommands.
#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    /// List saved cases.
    List {
        /// Corpus directory (default: `fixtures/corpus`).
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
    /// Replay one case (or all) and compare with its expectation.
    Replay {
        /// Case identifier; omit with `--all`.
        case_id: Option<String>,
        /// Replay every case.
        #[arg(long, conflicts_with = "case_id")]
        all: bool,
        /// Corpus directory (default: `fixtures/corpus`).
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
    /// Run a scenario now and save it with the observed outcome as its expectation.
    Add {
        /// Scenario JSON file.
        scenario_file: PathBuf,
        /// Why this case exists.
        #[arg(long)]
        description: String,
        /// Corpus directory (default: `fixtures/corpus`).
        #[arg(long)]
        corpus: Option<PathBuf>,
    },
}

/// Run the CLI with `args`, writing to `out`/`err`, and return the process exit code.
pub fn run<I, T>(args: I, out: &mut dyn Write, err: &mut dyn Write) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { EXIT_USAGE } else { EXIT_OK };
            let _ = if e.use_stderr() {
                write!(err, "{e}")
            } else {
                write!(out, "{e}")
            };
            return code;
        }
    };
    match commands::dispatch(cli.command, out) {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(err, "error: {e}");
            e.exit_code()
        }
    }
}
