//! Rendering. Pure functions from [`App`] state to widgets; nothing here executes programs.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
use tokenscope_invariants::Verdict;
use tokenscope_model::{
    Action, MintExtension, OutcomeClass, RunRecord, Severity, Snapshot, StepStatus, Totals,
};
use tokenscope_report::render_finding_text;

use crate::app::{App, Screen};

fn outcome(o: OutcomeClass) -> (&'static str, Color) {
    match o {
        OutcomeClass::Pass => ("pass", Color::Green),
        OutcomeClass::SetupError => ("setup-error", Color::Magenta),
        OutcomeClass::ExecutionFailure => ("execution-failure", Color::Yellow),
        OutcomeClass::InvariantViolation => ("invariant-violation", Color::Red),
        OutcomeClass::SuspectedVulnerability => ("suspected-vulnerability", Color::LightRed),
    }
}

fn severity_color(s: Severity) -> Color {
    match s {
        Severity::Info => Color::Gray,
        Severity::Low => Color::Cyan,
        Severity::Medium => Color::Yellow,
        Severity::High => Color::Red,
    }
}

/// Counts over the runs completed so far (live during a campaign).
pub fn live_totals(runs: &[RunRecord]) -> Totals {
    let mut t = Totals {
        executed: runs.len(),
        ..Totals::default()
    };
    for r in runs {
        match r.outcome {
            OutcomeClass::Pass => t.passed += 1,
            OutcomeClass::ExecutionFailure => t.execution_failures += 1,
            OutcomeClass::InvariantViolation | OutcomeClass::SuspectedVulnerability => {
                t.invariant_violations += 1
            }
            OutcomeClass::SetupError => t.setup_errors += 1,
        }
        t.findings += r.findings.len();
    }
    t
}

fn block(title: impl Into<String>) -> Block<'static> {
    Block::bordered().title(title.into())
}

fn selectable(
    items: Vec<ListItem<'static>>,
    sel: usize,
    title: String,
) -> (List<'static>, ListState) {
    let mut st = ListState::default();
    if !items.is_empty() {
        st.select(Some(sel.min(items.len() - 1)));
    }
    let list = List::new(items)
        .block(block(title))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    (list, st)
}

fn fee_label(r: &RunRecord) -> String {
    let fee = match r.scenario.mint.transfer_fee {
        None => "no fee ext".into(),
        Some(f) if f.maximum_fee == u64::MAX => format!("fee {}bp", f.basis_points),
        Some(f) => format!("fee {}bp max {}", f.basis_points, f.maximum_fee),
    };
    if r.scenario.extensions.is_empty() {
        fee
    } else {
        let exts: Vec<_> = r.scenario.extensions.iter().map(|e| e.name()).collect();
        format!("{fee} [{}]", exts.join(","))
    }
}

fn action_label(a: Action) -> String {
    // Debug output (`Deposit { amount: 5 }`, `Pause`, ...) is stable and covers every action.
    format!("{a:?}")
}

fn snap_line(label: &str, s: &Snapshot) -> String {
    let mut line = format!(
        "  {label}: vault={} withheld={} recorded={} depositor={} destination={} frozen={} attacker={}",
        s.vault_amount,
        s.vault_withheld.map_or("-".into(), |w| w.to_string()),
        s.escrow_recorded,
        s.depositor_balance,
        s.destination_balance,
        s.depositor_frozen,
        s.attacker_balance
    );
    // Extension state is shown only when it is in play, to keep baseline output unchanged.
    if s.vault_frozen {
        line.push_str(" vault_frozen=true");
    }
    if let Some(p) = s.mint_paused {
        line.push_str(&format!(" paused={p}"));
    }
    if s.source_cpi_guard {
        line.push_str(" cpi_guard=on");
    }
    if s.delegate_allowance > 0 {
        line.push_str(&format!(" delegate_allowance={}", s.delegate_allowance));
    }
    if let Some(n) = s.hook_invocations {
        line.push_str(&format!(" hook_calls={n}"));
    }
    if s.issuer_balance > 0 {
        line.push_str(&format!(" issuer={}", s.issuer_balance));
    }
    line
}

fn para(lines: Vec<Line<'static>>, title: impl Into<String>, scroll: u16) -> Paragraph<'static> {
    Paragraph::new(Text::from(lines))
        .block(block(title))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
}

fn plain(s: impl Into<String>) -> Line<'static> {
    Line::from(s.into())
}

fn kv(k: &str, v: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{k}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(v.into()),
    ])
}

/// Draw the whole UI.
pub fn draw(frame: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let titles: Vec<String> = Screen::ALL
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{} {}", i + 1, s.title()))
        .collect();
    let selected = Screen::ALL
        .iter()
        .position(|s| *s == app.screen)
        .unwrap_or(0);
    frame.render_widget(
        Tabs::new(titles)
            .select(selected)
            .block(Block::bordered().title(format!("TokenScope - {}", app.opts.target)))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        header,
    );
    match app.screen {
        Screen::Dashboard => dashboard(frame, app, body),
        Screen::Scenarios => scenarios(frame, app, body),
        Screen::Execution => execution(frame, app, body),
        Screen::Findings => findings(frame, app, body),
        Screen::TokenConfig => token_config(frame, app, body),
        Screen::Invariants => invariants(frame, app, body),
        Screen::Corpus => corpus(frame, app, body),
        Screen::Reports => reports(frame, app, body),
        Screen::Help => help(frame, app, body),
    }
    let hint = "1-9/Tab screens  j/k move  / filter  r rerun  t target  x extended  e export  p replay  ? help  q quit";
    frame.render_widget(Paragraph::new(format!("{} | {hint}", app.status)), footer);
}

fn dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let [top, bottom] = Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).areas(area);
    let done = app.runs.len();
    let ratio = if app.total == 0 {
        0.0
    } else {
        (done as f64 / app.total as f64).min(1.0)
    };
    frame.render_widget(
        Gauge::default()
            .block(block("Progress"))
            .gauge_style(Style::default().fg(if app.running {
                Color::Cyan
            } else {
                Color::Green
            }))
            .ratio(ratio)
            .label(format!(
                "{done}/{} scenarios{}",
                app.total,
                if app.running {
                    " (running)"
                } else {
                    " (finished)"
                }
            )),
        top,
    );
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(bottom);
    let t = live_totals(&app.runs);
    let inv_count = app.invariant_catalog().len();
    let mut lines = vec![
        kv("target", app.opts.target.clone()),
        kv("suite", format!("{:?}", app.opts.suite)),
        kv(
            "invariants",
            format!(
                "{} ({inv_count})",
                if app.opts.extended {
                    "extended"
                } else {
                    "core"
                }
            ),
        ),
        kv("seed", app.opts.seed.to_string()),
        kv("duration", format!("{:.1}s", app.elapsed.as_secs_f64())),
        kv("executed", t.executed.to_string()),
        Line::from(vec![Span::styled(
            format!("pass: {}", t.passed),
            Style::default().fg(Color::Green),
        )]),
        Line::from(vec![Span::styled(
            format!("execution failures: {}", t.execution_failures),
            Style::default().fg(Color::Yellow),
        )]),
        Line::from(vec![Span::styled(
            format!("invariant violations: {}", t.invariant_violations),
            Style::default().fg(Color::Red),
        )]),
        Line::from(vec![Span::styled(
            format!("setup errors: {}", t.setup_errors),
            Style::default().fg(Color::Magenta),
        )]),
        kv("findings", t.findings.to_string()),
    ];
    if let Some(c) = &app.campaign {
        lines.push(kv("campaign", c.id.clone()));
    }
    frame.render_widget(para(lines, "Campaign", 0), left);
    let skip = app
        .activity
        .len()
        .saturating_sub(right.height.saturating_sub(2) as usize);
    let items: Vec<ListItem> = app
        .activity
        .iter()
        .skip(skip)
        .map(|l| ListItem::new(l.clone()))
        .collect();
    frame.render_widget(List::new(items).block(block("Activity")), right);
}

fn scenarios(frame: &mut Frame, app: &App, area: Rect) {
    let vis = app.visible_runs();
    let items: Vec<ListItem> = vis
        .iter()
        .map(|&i| {
            let r = &app.runs[i];
            let (label, color) = outcome(r.outcome);
            ListItem::new(Line::from(vec![
                Span::styled(format!("{label:<20}"), Style::default().fg(color)),
                Span::raw(format!(
                    " {:<32} {} seed={} {}",
                    r.scenario.name,
                    r.scenario_id,
                    r.scenario.seed,
                    fee_label(r)
                )),
            ]))
        })
        .collect();
    let title = format!(
        "Scenarios ({}/{}) filter: {}{}",
        vis.len(),
        app.runs.len(),
        if app.filter.is_empty() {
            "(none; press /)"
        } else {
            &app.filter
        },
        if app.filtering { "_" } else { "" }
    );
    let (list, mut st) = selectable(items, app.selected, title);
    frame.render_stateful_widget(list, area, &mut st);
}

fn no_selection(frame: &mut Frame, area: Rect, what: &str) {
    frame.render_widget(
        para(
            vec![plain(format!("No {what} to show yet."))],
            what.to_string(),
            0,
        ),
        area,
    );
}

fn execution(frame: &mut Frame, app: &App, area: Rect) {
    let Some(r) = app.selected_run() else {
        return no_selection(frame, area, "scenario");
    };
    let (label, color) = outcome(r.outcome);
    let mut lines = vec![
        Line::from(vec![
            Span::styled("scenario: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{} ({}) -> ", r.scenario.name, r.scenario_id)),
            Span::styled(label, Style::default().fg(color)),
        ]),
        kv("target", r.scenario.target.clone()),
    ];
    if let Some(e) = &r.setup_error {
        lines.push(kv("setup error", e.clone()));
    }
    if let Some(t) = &r.trace {
        lines.push(plain("accounts:"));
        for a in &t.accounts {
            lines.push(plain(format!("  {:<22} {}", a.label, a.address)));
        }
        lines.push(plain(snap_line("initial", &t.initial)));
        for s in &t.steps {
            let status = match &s.status {
                StepStatus::Ok => "ok".to_string(),
                StepStatus::Failed { error } => format!("FAILED: {error}"),
            };
            lines.push(plain(""));
            lines.push(plain(format!(
                "step {}: {} -> {status} ({} CU)",
                s.index,
                action_label(s.action),
                s.compute_units
            )));
            lines.push(plain(snap_line("before", &s.before)));
            lines.push(plain(snap_line("after ", &s.after)));
            for l in &s.logs {
                lines.push(plain(format!("    log: {l}")));
            }
        }
    }
    frame.render_widget(
        para(
            lines,
            "Execution inspector (PgUp/PgDn scroll, j/k scenario)",
            app.scroll,
        ),
        area,
    );
}

fn findings(frame: &mut Frame, app: &App, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area);
    let all = app.findings();
    let items: Vec<ListItem> = all
        .iter()
        .map(|f| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<6?}", f.severity),
                    Style::default().fg(severity_color(f.severity)),
                ),
                Span::raw(format!(" {} {}", f.invariant_id, f.id)),
            ]))
        })
        .collect();
    let (list, mut st) = selectable(items, app.finding_sel, format!("Findings ({})", all.len()));
    frame.render_stateful_widget(list, left, &mut st);
    let detail = match app.selected_finding() {
        Some(f) => render_finding_text(f)
            .lines()
            .map(|l| plain(l.to_string()))
            .collect(),
        None => vec![plain("No findings.")],
    };
    frame.render_widget(para(detail, "Evidence", app.scroll), right);
}

fn token_config(frame: &mut Frame, app: &App, area: Rect) {
    let Some(r) = app.selected_run() else {
        return no_selection(frame, area, "scenario");
    };
    let m = &r.scenario.mint;
    let mut lines = vec![
        kv(
            "scenario",
            format!("{} ({})", r.scenario.name, r.scenario_id),
        ),
        kv("mint decimals", m.decimals.to_string()),
        kv(
            "initial depositor balance",
            r.scenario.initial_balance.to_string(),
        ),
        plain(""),
        plain("extensions:"),
    ];
    let mut has_ext = false;
    if let Some(f) = m.transfer_fee {
        has_ext = true;
        lines.push(plain(format!(
            "  TransferFeeConfig: {} bp, maximum fee {}",
            f.basis_points, f.maximum_fee
        )));
        lines.push(plain(
            "    fee = min(ceil(amount * bp / 10000), maximum fee)",
        ));
    }
    for ext in &r.scenario.extensions {
        has_ext = true;
        let desc = match ext {
            MintExtension::DefaultAccountState { frozen } => {
                format!("DefaultAccountState: frozen={frozen}")
            }
            MintExtension::Pausable => "Pausable (pause authority: harness payer)".into(),
            MintExtension::PermanentDelegate => {
                "PermanentDelegate (delegate: harness issuer)".into()
            }
            MintExtension::TransferHook => "TransferHook (program: demo-hook)".into(),
        };
        lines.push(plain(format!("  {desc}")));
    }
    if !has_ext {
        lines.push(plain("  (none)"));
    }
    lines.push(plain(""));
    lines.push(plain("authorities (harness-defined):"));
    lines.push(plain("  mint authority / transfer-fee config authority / withdraw-withheld authority: harness payer"));
    lines.push(plain(
        "  freeze authority: harness payer (used by FreezeDepositor / ThawDepositor)",
    ));
    lines.push(plain(
        "  vault owner: escrow PDA (seeds [\"escrow\", escrow_state])",
    ));
    if let Some(t) = &r.trace {
        lines.push(plain(""));
        lines.push(plain("accounts:"));
        for a in &t.accounts {
            lines.push(plain(format!("  {:<22} {}", a.label, a.address)));
        }
    }
    frame.render_widget(para(lines, "Token configuration", app.scroll), area);
}

fn invariants(frame: &mut Frame, app: &App, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area);
    let cat = app.invariant_catalog();
    let items: Vec<ListItem> = cat
        .iter()
        .map(|d| ListItem::new(format!("{} {}", d.id, d.name)))
        .collect();
    let title = format!(
        "Invariants ({} {})",
        cat.len(),
        if app.opts.extended {
            "extended"
        } else {
            "core; x=13"
        }
    );
    let (list, mut st) = selectable(items, app.invariant_sel, title);
    frame.render_stateful_widget(list, left, &mut st);
    let Some(d) = cat
        .get(app.invariant_sel.min(cat.len().saturating_sub(1)))
        .copied()
    else {
        frame.render_widget(
            para(
                vec![plain("No invariants configured.")],
                "Definition and observed behavior",
                app.scroll,
            ),
            right,
        );
        return;
    };
    let mut lines = vec![
        kv("id", d.id),
        kv("level", format!("{:?}", d.level)),
        kv("name", d.name),
        kv("definition", d.description),
        kv("expected", d.expected),
        plain("preconditions:"),
    ];
    lines.extend(d.preconditions.iter().map(|p| plain(format!("  - {p}"))));
    lines.push(plain("legitimate exceptions:"));
    lines.extend(d.exceptions.iter().map(|p| plain(format!("  - {p}"))));
    lines.push(plain(""));
    match app
        .selected_run()
        .and_then(|r| r.trace.as_ref().map(|t| (r, t)))
    {
        Some((r, t)) => {
            lines.push(kv("verdicts for scenario", r.scenario.name.clone()));
            let reg = app.invariant_registry();
            for e in reg
                .evaluate(t)
                .into_iter()
                .filter(|e| e.invariant_id == d.id)
            {
                let (txt, color) = match &e.verdict {
                    Verdict::Held => ("held".to_string(), Color::Green),
                    Verdict::NotApplicable => ("not applicable".to_string(), Color::Gray),
                    Verdict::Violated { observed } => {
                        (format!("VIOLATED - observed: {observed}"), Color::Red)
                    }
                };
                lines.push(Line::from(vec![
                    Span::raw(format!("  step {}: ", e.step_index)),
                    Span::styled(txt, Style::default().fg(color)),
                ]));
            }
        }
        None => lines.push(plain(
            "Select a scenario on the Scenarios screen to see verdicts.",
        )),
    }
    frame.render_widget(
        para(lines, "Definition and observed behavior", app.scroll),
        right,
    );
}

fn corpus(frame: &mut Frame, app: &App, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);
    let items: Vec<ListItem> = app
        .corpus_cases
        .iter()
        .map(|c| {
            let mark = match app.corpus_results.get(&c.id) {
                Some(r) if r.ok => "PASS",
                Some(_) => "FAIL",
                None => " -- ",
            };
            ListItem::new(format!("[{mark}] {} {}", c.id, c.scenario.target))
        })
        .collect();
    let n = items.len();
    let (list, mut st) = selectable(
        items,
        app.corpus_sel,
        format!(
            "Regression corpus ({n}) - {}",
            app.opts.corpus_dir.display()
        ),
    );
    frame.render_stateful_widget(list, left, &mut st);
    let lines = match app.corpus_cases.get(app.corpus_sel) {
        Some(c) => {
            let mut l = vec![
                kv("case", c.id.clone()),
                kv("description", c.description.clone()),
                kv(
                    "scenario",
                    format!("{} ({})", c.scenario.name, c.scenario.id()),
                ),
                kv(
                    "expected",
                    format!("{:?} violated={:?}", c.expect.outcome, c.expect.violated),
                ),
            ];
            match app.corpus_results.get(&c.id) {
                Some(r) => l.push(kv(
                    "last replay",
                    format!(
                        "{} - actual {:?} violated={:?}",
                        if r.ok { "PASS" } else { "FAIL" },
                        r.actual.outcome,
                        r.actual.violated
                    ),
                )),
                None => l.push(plain("Press p or Enter to replay this case.")),
            }
            l
        }
        None => vec![plain("The corpus is empty.")],
    };
    frame.render_widget(para(lines, "Case", app.scroll), right);
}

fn reports(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![];
    match &app.campaign {
        Some(c) => {
            lines.push(kv("campaign", c.id.clone()));
            lines.push(plain(format!(
                "view as JSON: tokenscope report {} --format json --out {}",
                c.id,
                app.opts.out_dir.display()
            )));
        }
        None => lines.push(plain(
            "Campaign still running; reports are available when it finishes.",
        )),
    }
    match &app.artifacts {
        Some(a) => {
            lines.push(plain(""));
            lines.push(plain("exported artifacts:"));
            lines.push(plain(format!("  directory:   {}", a.dir.display())));
            lines.push(plain(format!("  campaign:    {}", a.campaign.display())));
            lines.push(plain(format!("  JSON report: {}", a.report_json.display())));
            lines.push(plain(format!("  text report: {}", a.report_text.display())));
            lines.push(plain(format!(
                "  MD report:   {}",
                a.report_markdown.display()
            )));
            lines.push(plain(format!(
                "  SARIF:       {}",
                a.report_sarif.display()
            )));
            lines.push(plain(format!(
                "  findings:    {} file(s)",
                a.findings.len()
            )));
            lines.push(plain(format!(
                "  scenarios:   {} file(s)",
                a.scenarios.len()
            )));
        }
        None => {
            lines.push(plain(""));
            lines.push(plain(format!(
                "Press e to export artifacts to {}",
                app.opts.out_dir.display()
            )));
        }
    }
    if let Some(f) = app.selected_finding() {
        lines.push(plain(""));
        lines.push(kv("selected finding", f.id.clone()));
        lines.push(kv("reproduce", f.reproduction.command.clone()));
        lines.push(kv("minimize", "tokenscope minimize <findings/<id>.json>"));
    }
    frame.render_widget(para(lines, "Reports and reproduction", app.scroll), area);
}

fn help(frame: &mut Frame, app: &App, area: Rect) {
    let o = &app.opts;
    let inv_ids: Vec<_> = app.invariant_catalog().into_iter().map(|d| d.id).collect();
    let lines = vec![
        plain("Settings"),
        kv("  target", o.target.clone()),
        kv(
            "  seed / generated count",
            format!("{} / {}", o.seed, o.count),
        ),
        kv("  built-in suite", format!("{:?}", o.suite)),
        kv(
            "  invariants",
            format!(
                "{} ({})",
                if o.extended { "extended" } else { "core" },
                inv_ids.len()
            ),
        ),
        kv("  output dir", o.out_dir.display().to_string()),
        kv("  corpus dir", o.corpus_dir.display().to_string()),
        plain(""),
        plain("Capabilities (verified by executable tests)"),
        plain(
            "  Real execution of the system program, the bundled Token-2022 ELF and the demo escrow in the Mollusk SVM",
        ),
        plain(
            "  Token-2022: TransferFeeConfig, Pausable, PermanentDelegate, DefaultAccountState, CPI Guard, TransferHook",
        ),
        plain(format!(
            "  Active invariants ({}): {}",
            inv_ids.len(),
            inv_ids.join(", ")
        )),
        plain(""),
        plain("Limitations"),
        plain(
            "  Only the demo escrow target (plus demo-hook and demo-forwarder fixtures); confidential transfers are out of scope",
        ),
        plain(
            "  Only the depositor-signature, account-identity and initialization checks are modeled; a violation is not proof of exploitability",
        ),
        plain(
            "  The Token-2022 ELF is a mainnet snapshot bundled by mollusk-svm-programs-token-2022",
        ),
        plain(""),
        plain("Shortcuts"),
        plain(
            "  1-9 / Tab / Shift-Tab  switch screen        j k / arrows / Home End  move selection",
        ),
        plain(
            "  PgUp PgDn  scroll details (page lists)       /  filter scenarios (Enter keeps, Esc clears)",
        ),
        plain(
            "  r  re-run   t  toggle vulnerable/corrected   x  toggle 6/13 invariants   e  export   p/Enter  replay case",
        ),
        plain("  ?  help     q or Ctrl-C  quit"),
    ];
    frame.render_widget(para(lines, "Configuration and help", app.scroll), area);
}
