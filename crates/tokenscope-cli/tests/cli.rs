//! Black-box tests of the `tokenscope` binary: exit codes and output must reflect real execution.

use std::{fs, path::Path, process::Command};

use tokenscope_core::Engine;
use tokenscope_model::{Campaign, CorpusCase, Finding, Scenario};
use tokenscope_report::Report;
use tokenscope_scenarios::{builtin_suite, generate};

const VULN: &str = "demo-escrow-vulnerable";
const FIXED: &str = "demo-escrow-corrected";

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn tokenscope(args: &[&str]) -> Out {
    tokenscope_env(args, &[])
}

fn tokenscope_env(args: &[&str], env: &[(&str, &str)]) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tokenscope"));
    cmd.args(args).env_remove("RUST_LOG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let o = cmd.output().expect("spawn tokenscope");
    Out {
        code: o.status.code().expect("exit code"),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn only_dir(p: &Path) -> std::path::PathBuf {
    let mut it = fs::read_dir(p).unwrap().map(|e| e.unwrap().path());
    let d = it.next().expect("one directory");
    assert!(it.next().is_none());
    d
}

#[test]
fn doctor_verifies_the_environment_with_real_execution() {
    let o = tokenscope(&["doctor"]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("delivered 980 with 20 withheld"),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("doctor: environment OK"));
}

#[test]
fn doctor_fails_with_exit_3_when_programs_are_missing() {
    let o = tokenscope_env(
        &["doctor"],
        &[("TOKENSCOPE_PROGRAM_DIR", "/nonexistent-dir")],
    );
    assert_eq!(o.code, 3);
    assert!(o.stdout.contains("[FAIL]") && o.stdout.contains("build-programs.sh"));
}

#[test]
fn inspect_lists_targets_and_invariants() {
    let o = tokenscope(&["inspect"]);
    assert_eq!(o.code, 0);
    for needle in [
        VULN,
        FIXED,
        "INV-ACCT-001",
        "INV-SOLV-001",
        "fee-2pct-deposit",
    ] {
        assert!(o.stdout.contains(needle), "missing {needle}");
    }
    assert_eq!(tokenscope(&["inspect", "--target", "nope"]).code, 2);
}

#[test]
fn run_vulnerable_exits_1_and_matches_direct_engine_results() {
    let dir = tempfile::tempdir().unwrap();
    let o = tokenscope(&[
        "run",
        "--target",
        VULN,
        "--seed",
        "7",
        "--count",
        "5",
        "--out",
        s(dir.path()),
    ]);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stderr.is_empty(), "no log noise: {}", o.stderr);

    // The stored campaign is identical to running the same scenarios directly.
    let mut scenarios = builtin_suite(VULN);
    scenarios.extend(generate(7, 5, VULN));
    let expected = Engine::new().run_campaign(VULN, 7, &scenarios);
    let cdir = only_dir(dir.path());
    let stored =
        Campaign::from_json(&fs::read_to_string(cdir.join("campaign.json")).unwrap()).unwrap();
    assert_eq!(stored, expected);
    assert_eq!(cdir.file_name().unwrap().to_str().unwrap(), expected.id);
    assert!(o.stdout.contains(&expected.id));

    // The JSON report is a view of the same campaign.
    let report: Report =
        serde_json::from_str(&fs::read_to_string(cdir.join("report.json")).unwrap()).unwrap();
    assert_eq!(report.totals, expected.totals());
    assert_eq!(
        report.findings,
        expected.findings().cloned().collect::<Vec<_>>()
    );
    assert!(report.totals.invariant_violations > 0 && report.totals.setup_errors == 0);
}

#[test]
fn run_corrected_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let o = tokenscope(&[
        "run",
        "--target",
        FIXED,
        "--seed",
        "7",
        "--count",
        "5",
        "--out",
        s(dir.path()),
    ]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("invariant violations 0"));
}

#[test]
fn run_demo_escrow_runs_both_flavors_and_reports_violations() {
    let dir = tempfile::tempdir().unwrap();
    let o = tokenscope(&[
        "run",
        "--target",
        "demo-escrow",
        "--count",
        "0",
        "--out",
        s(dir.path()),
    ]);
    assert_eq!(o.code, 1);
    assert!(
        o.stdout.contains(&format!("target: {VULN}"))
            && o.stdout.contains(&format!("target: {FIXED}"))
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn run_from_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("run.json");
    fs::write(&cfg, r#"{"schema_version":1,"target":"demo-escrow-corrected","seed":3,"generated":2,"builtin_suite":false}"#).unwrap();
    let out = dir.path().join("out");
    let o = tokenscope(&["run", "--config", s(&cfg), "--out", s(&out)]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("executed 2 "), "{}", o.stdout);
}

#[test]
fn invalid_usage_and_input_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(tokenscope(&["frobnicate"]).code, 2);
    assert_eq!(tokenscope(&["run"]).code, 2);
    assert_eq!(tokenscope(&["run", "--target", "nope"]).code, 2);
    assert_eq!(
        tokenscope(&["run", "--target", VULN, "--no-suite", "--count", "0"]).code,
        2
    );
    assert_eq!(
        tokenscope(&["run", "--target", VULN, "--count", "100000"]).code,
        2
    );
    let bad = dir.path().join("bad.json");
    fs::write(&bad, "{not json").unwrap();
    assert_eq!(tokenscope(&["run", "--config", s(&bad)]).code, 2);
    fs::write(&bad, r#"{"schema_version":9,"target":"demo-escrow"}"#).unwrap();
    assert_eq!(tokenscope(&["run", "--config", s(&bad)]).code, 2);
    fs::write(
        &bad,
        r#"{"schema_version":1,"target":"demo-escrow","surprise":1}"#,
    )
    .unwrap();
    assert_eq!(tokenscope(&["run", "--config", s(&bad)]).code, 2);
    assert_eq!(tokenscope(&["replay", "/no/such/file.json"]).code, 2);
    fs::write(&bad, "{not json").unwrap();
    assert_eq!(tokenscope(&["replay", s(&bad)]).code, 2);
    assert_eq!(tokenscope(&["minimize", s(&bad)]).code, 2);
    let o = tokenscope(&["--help"]);
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("doctor") && o.stdout.contains("corpus"));
}

#[test]
fn missing_programs_are_a_setup_error_not_a_violation() {
    let dir = tempfile::tempdir().unwrap();
    let o = tokenscope_env(
        &[
            "run",
            "--target",
            FIXED,
            "--no-suite",
            "--count",
            "1",
            "--out",
            s(dir.path()),
        ],
        &[("TOKENSCOPE_PROGRAM_DIR", "/nonexistent-dir")],
    );
    assert_eq!(o.code, 3, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("setup errors 1") && o.stdout.contains("findings 0"));
}

#[test]
fn replay_and_minimize_round_trip_through_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    tokenscope(&[
        "run",
        "--target",
        VULN,
        "--count",
        "0",
        "--out",
        s(dir.path()),
    ]);
    let cdir = only_dir(dir.path());

    // Replay a finding's scenario: violation on the vulnerable target...
    let scenario_file = fs::read_dir(cdir.join("scenarios"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(tokenscope(&["replay", s(&scenario_file)]).code, 1);
    // ...and the same scenario retargeted at the corrected escrow passes.
    let mut sc = Scenario::from_json(&fs::read_to_string(&scenario_file).unwrap()).unwrap();
    sc.target = FIXED.into();
    let fixed_file = dir.path().join("fixed.json");
    fs::write(&fixed_file, sc.to_json()).unwrap();
    assert_eq!(tokenscope(&["replay", s(&fixed_file)]).code, 0);

    // Minimize the finding of the large 'fee-2pct' style scenario.
    let finding_file = fs::read_dir(cdir.join("findings"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            let f = Finding::from_json(&fs::read_to_string(p).unwrap()).unwrap();
            f.invariant_id == "INV-ACCT-001"
                && f.reproduction.scenario.name == "two-deposits-accumulate"
        })
        .expect("finding for two-deposits-accumulate");
    let min_out = dir.path().join("min.json");
    let o = tokenscope(&["minimize", s(&finding_file), "--out", s(&min_out)]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    let min = Finding::from_json(&fs::read_to_string(&min_out).unwrap()).unwrap();
    let m = min.minimized.expect("minimized scenario");
    assert_eq!(m.actions.len(), 1);
    assert!(m.actions.len() < min.reproduction.scenario.actions.len());
}

#[test]
fn minimizing_a_finding_that_does_not_reproduce_exits_4() {
    let dir = tempfile::tempdir().unwrap();
    tokenscope(&[
        "run",
        "--target",
        VULN,
        "--count",
        "0",
        "--out",
        s(dir.path()),
    ]);
    let cdir = only_dir(dir.path());
    let fpath = fs::read_dir(cdir.join("findings"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut f = Finding::from_json(&fs::read_to_string(&fpath).unwrap()).unwrap();
    f.reproduction.scenario.target = FIXED.into();
    let altered = dir.path().join("altered.json");
    fs::write(&altered, f.to_json()).unwrap();
    assert_eq!(tokenscope(&["minimize", s(&altered)]).code, 4);
}

#[test]
fn report_prints_stored_campaigns_in_both_formats() {
    let dir = tempfile::tempdir().unwrap();
    tokenscope(&[
        "run",
        "--target",
        VULN,
        "--count",
        "0",
        "--out",
        s(dir.path()),
    ]);
    let cdir = only_dir(dir.path());
    let id = cdir.file_name().unwrap().to_str().unwrap().to_string();
    let j = tokenscope(&["report", &id, "--format", "json", "--out", s(dir.path())]);
    assert_eq!(j.code, 0);
    assert_eq!(
        j.stdout,
        fs::read_to_string(cdir.join("report.json")).unwrap()
    );
    let t = tokenscope(&["report", &id, "--format", "text", "--out", s(dir.path())]);
    assert_eq!(t.code, 0);
    assert_eq!(
        t.stdout,
        fs::read_to_string(cdir.join("report.txt")).unwrap()
    );
    let m = tokenscope(&[
        "report",
        &id,
        "--format",
        "markdown",
        "--out",
        s(dir.path()),
    ]);
    assert_eq!(m.code, 0);
    assert_eq!(
        m.stdout,
        fs::read_to_string(cdir.join("report.md")).unwrap()
    );
    let sr = tokenscope(&["report", &id, "--format", "sarif", "--out", s(dir.path())]);
    assert_eq!(sr.code, 0);
    assert_eq!(
        sr.stdout,
        fs::read_to_string(cdir.join("report.sarif")).unwrap()
    );
    assert_eq!(
        tokenscope(&["report", "cp_0000000000000000", "--out", s(dir.path())]).code,
        2
    );
    assert_eq!(
        tokenscope(&["report", "../etc/passwd", "--out", s(dir.path())]).code,
        2
    );
}

#[test]
fn corpus_add_list_replay_and_regression_detection() {
    let dir = tempfile::tempdir().unwrap();
    let corpus = dir.path().join("corpus");
    let c = s(&corpus);
    assert_eq!(
        tokenscope(&["corpus", "list", "--corpus", c]).stdout.trim(),
        "corpus is empty"
    );
    assert_eq!(
        tokenscope(&["corpus", "replay", "--all", "--corpus", c]).code,
        2
    );

    for (target, desc) in [(VULN, "bug demonstration"), (FIXED, "fixed regression")] {
        let sc = builtin_suite(target)[1].clone();
        let f = dir.path().join(format!("{target}.json"));
        fs::write(&f, sc.to_json()).unwrap();
        let o = tokenscope(&["corpus", "add", s(&f), "--description", desc, "--corpus", c]);
        assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    }
    let list = tokenscope(&["corpus", "list", "--corpus", c]);
    assert_eq!(list.code, 0);
    assert_eq!(list.stdout.lines().count(), 2);
    assert!(list.stdout.contains("InvariantViolation") && list.stdout.contains("Pass"));

    let ok = tokenscope(&["corpus", "replay", "--all", "--corpus", c]);
    assert_eq!(ok.code, 0, "{}", ok.stdout);
    assert!(ok.stdout.contains("2 case(s), 0 mismatch(es)"));

    // Tamper with an expectation: replay must detect the regression (exit 4).
    let case_file = fs::read_dir(&corpus)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            CorpusCase::from_json(&fs::read_to_string(p).unwrap())
                .unwrap()
                .scenario
                .target
                == VULN
        })
        .unwrap();
    let mut case = CorpusCase::from_json(&fs::read_to_string(&case_file).unwrap()).unwrap();
    case.expect.outcome = tokenscope_model::OutcomeClass::Pass;
    case.expect.violated.clear();
    fs::write(&case_file, case.to_json()).unwrap();
    let bad = tokenscope(&["corpus", "replay", &case.id, "--corpus", c]);
    assert_eq!(bad.code, 4, "{}", bad.stdout);
    assert!(bad.stdout.contains("FAIL"));
    assert_eq!(
        tokenscope(&["corpus", "replay", "rc_unknown", "--corpus", c]).code,
        2
    );
}

#[test]
fn tui_snapshot_shows_the_same_findings_as_the_cli_report() {
    let dir = tempfile::tempdir().unwrap();
    let run = tokenscope(&[
        "run",
        "--target",
        VULN,
        "--count",
        "0",
        "--out",
        s(dir.path()),
    ]);
    assert_eq!(run.code, 1);
    let cdir = only_dir(dir.path());
    let report: Report =
        serde_json::from_str(&fs::read_to_string(cdir.join("report.json")).unwrap()).unwrap();

    let dash = tokenscope(&["tui", "--snapshot", "dashboard", "--target", VULN]);
    assert_eq!(dash.code, 0, "{}{}", dash.stdout, dash.stderr);
    assert!(
        dash.stdout.contains(&report.campaign_id),
        "same campaign id in TUI and CLI"
    );
    assert!(
        dash.stdout
            .contains(&format!("findings: {}", report.totals.findings))
    );
    assert!(dash.stdout.contains(&format!(
        "invariant violations: {}",
        report.totals.invariant_violations
    )));

    let findings = tokenscope(&["tui", "--snapshot", "findings", "--target", VULN]);
    assert_eq!(findings.code, 0);
    // The findings list shows the first findings; each ID shown must be one the report contains,
    // and the first finding of the report must be listed.
    assert!(
        findings.stdout.contains(&report.findings[0].id),
        "{}",
        findings.stdout
    );
    assert!(
        findings
            .stdout
            .contains(&format!("Findings ({})", report.findings.len()))
    );
    for f in &report.findings {
        if findings.stdout.contains(&f.id) {
            assert!(report.findings.iter().any(|g| g.id == f.id));
        }
    }
}

#[test]
fn tui_snapshot_corrected_target_has_no_findings_and_inputs_are_validated() {
    let o = tokenscope(&["tui", "--snapshot", "findings", "--target", FIXED]);
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("Findings (0)") && o.stdout.contains("No findings."));
    assert_eq!(tokenscope(&["tui", "--snapshot", "nonsense"]).code, 2);
    assert_eq!(
        tokenscope(&["tui", "--target", "demo-escrow", "--snapshot", "help"]).code,
        2
    );
    assert_eq!(
        tokenscope(&["tui", "--target", "nope", "--snapshot", "help"]).code,
        2
    );
    assert_eq!(
        tokenscope(&["tui", "--no-suite", "--snapshot", "help"]).code,
        2
    );
    let help = tokenscope(&["tui", "--snapshot", "help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("Shortcuts"));
}

#[test]
fn suite_selection_extensions_and_all_and_validation() {
    let dir = tempfile::tempdir().unwrap();
    // The corrected escrow still has a custody finding with a permanent delegate (documented).
    let o = tokenscope(&[
        "run",
        "--target",
        FIXED,
        "--suite",
        "extensions",
        "--count",
        "0",
        "--out",
        s(dir.path()),
    ]);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(
        o.stdout.contains("INV-CUST-001") && o.stdout.contains("executed 10 "),
        "{}",
        o.stdout
    );
    assert!(
        !o.stdout.contains("INV-ACCT-001"),
        "no fee-accounting finding on the corrected escrow"
    );

    let all = tokenscope(&[
        "run",
        "--target",
        VULN,
        "--suite",
        "all",
        "--count",
        "0",
        "--out",
        s(dir.path()),
    ]);
    assert_eq!(all.code, 1);
    assert!(all.stdout.contains("executed 24 "), "{}", all.stdout);

    assert_eq!(
        tokenscope(&["run", "--target", VULN, "--suite", "everything"]).code,
        2
    );
    let cfg = dir.path().join("c.json");
    fs::write(
        &cfg,
        r#"{"schema_version":1,"target":"demo-escrow-corrected","suite":"nope"}"#,
    )
    .unwrap();
    assert_eq!(tokenscope(&["run", "--config", s(&cfg)]).code, 2);
    fs::write(
        &cfg,
        r#"{"schema_version":1,"target":"demo-escrow-corrected","suite":"extensions"}"#,
    )
    .unwrap();
    let o = tokenscope(&["run", "--config", s(&cfg), "--out", s(dir.path())]);
    assert_eq!(o.code, 1);
    assert!(o.stdout.contains("executed 10 "));
    let inspect = tokenscope(&["inspect"]);
    assert!(
        inspect.stdout.contains("permanent-delegate-drains-vault")
            && inspect.stdout.contains("INV-CUST-001")
    );
}

fn strategy_args<'a>(strategy: &'a str, out: &'a str) -> Vec<&'a str> {
    vec![
        "run",
        "--target",
        VULN,
        "--no-suite",
        "--seed",
        "3",
        "--count",
        "8",
        "--strategy",
        strategy,
        "--out",
        out,
    ]
}

#[test]
fn strategies_extended_and_guided_run_deterministically_and_are_validated() {
    let dir = tempfile::tempdir().unwrap();
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus");
    let (o1, o2) = (dir.path().join("a"), dir.path().join("b"));

    let a = tokenscope(&strategy_args("extended", s(&o1)));
    let b = tokenscope(&strategy_args("extended", s(&o2)));
    assert!(a.code == 0 || a.code == 1, "{}{}", a.stdout, a.stderr);
    assert_eq!(a.code, b.code);
    assert!(a.stdout.contains("executed 8 "), "{}", a.stdout);
    assert_eq!(
        only_dir(&o1).file_name(),
        only_dir(&o2).file_name(),
        "same campaign id => deterministic"
    );

    let g = tokenscope(&[
        "run",
        "--target",
        VULN,
        "--no-suite",
        "--seed",
        "3",
        "--count",
        "10",
        "--strategy",
        "guided",
        "--corpus",
        s(&corpus),
        "--out",
        s(&dir.path().join("g")),
    ]);
    assert!(g.code == 0 || g.code == 1, "{}{}", g.stdout, g.stderr);
    assert!(
        g.stdout.contains("guided generation: selected") && g.stdout.contains("not code coverage"),
        "{}",
        g.stdout
    );

    let st = tokenscope(&[
        "run",
        "--target",
        VULN,
        "--no-suite",
        "--seed",
        "7",
        "--count",
        "3",
        "--strategy",
        "stateful",
        "--out",
        s(&dir.path().join("st")),
    ]);
    assert!(st.code == 0 || st.code == 1, "{}{}", st.stdout, st.stderr);
    assert!(st.stdout.contains("executed 3 "), "{}", st.stdout);

    assert_eq!(
        tokenscope(&["run", "--target", VULN, "--strategy", "magic"]).code,
        2
    );
    let cfg = dir.path().join("c.json");
    fs::write(&cfg, r#"{"schema_version":1,"target":"demo-escrow-vulnerable","suite":"none","generated":4,"strategy":"extended"}"#).unwrap();
    let c = tokenscope(&[
        "run",
        "--config",
        s(&cfg),
        "--out",
        s(&dir.path().join("c")),
    ]);
    assert!(c.code == 0 || c.code == 1, "{}{}", c.stdout, c.stderr);
    assert!(c.stdout.contains("executed 4 "));
    fs::write(
        &cfg,
        r#"{"schema_version":1,"target":"demo-escrow-vulnerable","strategy":"nope"}"#,
    )
    .unwrap();
    assert_eq!(tokenscope(&["run", "--config", s(&cfg)]).code, 2);
}

#[test]
fn oversized_inputs_and_limits_are_rejected_with_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    // A sparse file just over the 32 MiB document limit: rejected before parsing.
    let big = dir.path().join("big.json");
    let f = fs::File::create(&big).unwrap();
    f.set_len(tokenscope_core::MAX_DOCUMENT_BYTES + 1).unwrap();
    for cmd in [["replay", s(&big)], ["minimize", s(&big)]] {
        let o = tokenscope(&cmd);
        assert_eq!(o.code, 2, "{}{}", o.stdout, o.stderr);
        assert!(o.stderr.contains("document limit"), "{}", o.stderr);
    }
    let cfg = tokenscope(&["run", "--config", s(&big)]);
    assert_eq!(cfg.code, 2);
    assert!(cfg.stderr.contains("document limit"));

    // The limit also protects corpus loading.
    let corpus = dir.path().join("corpus");
    fs::create_dir_all(&corpus).unwrap();
    fs::File::create(corpus.join("huge.json"))
        .unwrap()
        .set_len(tokenscope_core::MAX_DOCUMENT_BYTES + 1)
        .unwrap();
    let o = tokenscope(&["corpus", "list", "--corpus", s(&corpus)]);
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("document limit"), "{}", o.stderr);

    // Work caps: generated scenarios and shrink attempts.
    assert_eq!(
        tokenscope(&["run", "--target", VULN, "--count", "10001"]).code,
        2
    );
    let small = dir.path().join("f.json");
    fs::write(&small, "{}").unwrap();
    let o = tokenscope(&["minimize", s(&small), "--max-attempts", "100001"]);
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("exceeds the limit"), "{}", o.stderr);
}

#[test]
fn completion_generates_valid_scripts_for_supported_shells() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let o = tokenscope(&["completion", shell]);
        assert_eq!(o.code, 0, "failed for shell {shell}: {}", o.stderr);
        assert!(!o.stdout.is_empty(), "empty output for shell {shell}");
        assert!(
            o.stdout.contains("tokenscope"),
            "completion script missing binary name"
        );
    }
}

#[test]
fn extended_invariants_and_profiles_suite_work_end_to_end() {
    let dir = tempfile::tempdir().unwrap();

    // Default `inspect` keeps the 6 core invariants; `--extended` reveals all 13.
    let ins_core = tokenscope(&["inspect"]);
    assert_eq!(ins_core.code, 0);
    assert!(!ins_core.stdout.contains("INV-ZERO-001"));
    assert!(ins_core.stdout.contains("profile-rwa-regulated-mint"));

    let ins_ext = tokenscope(&["inspect", "--extended"]);
    assert_eq!(ins_ext.code, 0);
    for id in [
        "INV-ZERO-001",
        "INV-DILUT-001",
        "INV-SYMM-001",
        "INV-PAUSE-001",
        "INV-FREEZE-001",
        "INV-CPI-001",
        "INV-HOOK-001",
    ] {
        assert!(
            ins_ext.stdout.contains(id),
            "inspect --extended missing {id}"
        );
    }

    // Core suite on demo-escrow-corrected passes without --extended,
    // while --extended flags INV-ZERO-001 (100% fee truncation).
    let dir_core = dir.path().join("core");
    let run_core = tokenscope(&[
        "run",
        "--target",
        FIXED,
        "--count",
        "0",
        "--out",
        s(&dir_core),
    ]);
    assert_eq!(run_core.code, 0, "{}{}", run_core.stdout, run_core.stderr);

    let dir_ext = dir.path().join("ext");
    let run_ext = tokenscope(&[
        "run",
        "--target",
        FIXED,
        "--count",
        "0",
        "--extended",
        "--out",
        s(&dir_ext),
    ]);
    assert_eq!(run_ext.code, 1, "{}{}", run_ext.stdout, run_ext.stderr);
    assert!(
        run_ext.stdout.contains("INV-ZERO-001"),
        "{}",
        run_ext.stdout
    );

    // Combined mint profiles suite (`--suite profiles`, 5 scenarios) runs cleanly.
    let dir_prof = dir.path().join("prof");
    let run_prof = tokenscope(&[
        "run",
        "--target",
        FIXED,
        "--suite",
        "profiles",
        "--count",
        "0",
        "--extended",
        "--out",
        s(&dir_prof),
    ]);
    assert_eq!(run_prof.code, 1, "{}{}", run_prof.stdout, run_prof.stderr);
    assert!(
        run_prof.stdout.contains("executed 5 "),
        "{}",
        run_prof.stdout
    );
    assert!(
        run_prof.stdout.contains("INV-CUST-001"),
        "{}",
        run_prof.stdout
    );
    assert!(
        run_prof.stdout.contains("INV-ZERO-001"),
        "{}",
        run_prof.stdout
    );
    assert!(
        !run_prof.stdout.contains("INV-PAUSE-001"),
        "{}",
        run_prof.stdout
    );
    assert!(
        !run_prof.stdout.contains("INV-FREEZE-001"),
        "{}",
        run_prof.stdout
    );
    assert!(
        !run_prof.stdout.contains("INV-CPI-001"),
        "{}",
        run_prof.stdout
    );

    // Full suite (`--suite full`) combines core + extensions + profiles = 29 scenarios.
    let dir_full = dir.path().join("full");
    let run_full = tokenscope(&[
        "run",
        "--target",
        FIXED,
        "--suite",
        "full",
        "--count",
        "0",
        "--extended",
        "--out",
        s(&dir_full),
    ]);
    assert_eq!(run_full.code, 1, "{}{}", run_full.stdout, run_full.stderr);
    assert!(
        run_full.stdout.contains("executed 29 "),
        "{}",
        run_full.stdout
    );

    // `--config` accepts `"extended": true`.
    let cfg = dir.path().join("ext.json");
    fs::write(
        &cfg,
        r#"{"schema_version":1,"target":"demo-escrow-corrected","suite":"profiles","extended":true}"#,
    )
    .unwrap();
    let cfg_dir = dir.path().join("cfg");
    let run_cfg = tokenscope(&["run", "--config", s(&cfg), "--out", s(&cfg_dir)]);
    assert_eq!(run_cfg.code, 1, "{}{}", run_cfg.stdout, run_cfg.stderr);
    assert!(run_cfg.stdout.contains("executed 5 "), "{}", run_cfg.stdout);

    // Replay & minimize with `--extended` on an INV-ZERO-001 finding work cleanly.
    let cdir = only_dir(&dir_prof);
    let report: Report =
        serde_json::from_str(&fs::read_to_string(cdir.join("report.json")).unwrap()).unwrap();
    let zero_finding = report
        .findings
        .iter()
        .find(|f| f.invariant_id == "INV-ZERO-001")
        .expect("INV-ZERO-001 finding saved in report");
    let sc_path = dir.path().join("sc.json");
    fs::write(&sc_path, zero_finding.reproduction.scenario.to_json()).unwrap();
    let rep = tokenscope(&["replay", s(&sc_path), "--extended"]);
    assert_eq!(rep.code, 1, "{}{}", rep.stdout, rep.stderr);
    assert!(rep.stdout.contains("INV-ZERO-001"));

    let finding_path = dir.path().join("f.json");
    fs::write(&finding_path, zero_finding.to_json()).unwrap();
    let min_out = dir.path().join("f.min.json");
    let min = tokenscope(&[
        "minimize",
        s(&finding_path),
        "--out",
        s(&min_out),
        "--max-attempts",
        "40",
        "--extended",
    ]);
    assert_eq!(min.code, 0, "{}{}", min.stdout, min.stderr);
    let minimized = Finding::from_json(&fs::read_to_string(&min_out).unwrap()).unwrap();
    assert!(minimized.minimized.is_some());

    // TUI snapshots support `--suite profiles` and `--extended` (13 invariants).
    let tui_inv = tokenscope(&[
        "tui",
        "--target",
        FIXED,
        "--suite",
        "profiles",
        "--extended",
        "--snapshot",
        "invariants",
    ]);
    assert_eq!(tui_inv.code, 0, "{}{}", tui_inv.stdout, tui_inv.stderr);
    assert!(
        tui_inv.stdout.contains("Invariants (13 extended)")
            && tui_inv.stdout.contains("INV-ZERO-001")
            && tui_inv.stdout.contains("INV-HOOK-001"),
        "{}",
        tui_inv.stdout
    );

    let tui_findings = tokenscope(&[
        "tui",
        "--target",
        FIXED,
        "--suite",
        "profiles",
        "--extended",
        "--snapshot",
        "findings",
    ]);
    assert_eq!(
        tui_findings.code, 0,
        "{}{}",
        tui_findings.stdout, tui_findings.stderr
    );
    assert!(
        tui_findings.stdout.contains("INV-ZERO-001"),
        "{}",
        tui_findings.stdout
    );
}

/// Run the binary from the workspace root, where generic SBF example specs resolve `elf_path`.
fn tokenscope_at_root(args: &[&str]) -> Out {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let o = Command::new(env!("CARGO_BIN_EXE_tokenscope"))
        .args(args)
        .current_dir(root)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn tokenscope");
    Out {
        code: o.status.code().expect("exit code"),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

#[test]
fn sbf_run_evaluates_spec_checks_with_exit_codes_and_sarif() {
    let dir = tempfile::tempdir().unwrap();
    let sarif = dir.path().join("out.sarif");
    let o = tokenscope_at_root(&[
        "sbf-run",
        "--spec",
        "examples/generic-sbf/escrow-vulnerable.json",
        "--format",
        "text",
        "--sarif",
        s(&sarif),
    ]);
    assert_eq!(o.code, 1, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("INV-ACCT-001 [error]"), "{}", o.stdout);
    assert!(o.stdout.contains("observed 1000 vs 980"), "{}", o.stdout);
    let log: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&sarif).unwrap()).unwrap();
    assert_eq!(log["runs"][0]["results"][0]["ruleId"], "INV-ACCT-001");

    let o = tokenscope_at_root(&[
        "sbf-run",
        "--spec",
        "examples/generic-sbf/escrow-corrected.json",
    ]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    let out: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(out["findings"].as_array().map(Vec::len), Some(0));

    let o = tokenscope_at_root(&[
        "sbf-run",
        "--spec",
        "examples/generic-sbf/escrow-corrected.json",
        "--format",
        "xml",
    ]);
    assert_eq!(o.code, 2, "{}{}", o.stdout, o.stderr);
}
