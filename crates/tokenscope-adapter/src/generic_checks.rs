//! Declarative checks over generic SBF observations.
//!
//! A [`CheckSpec`] states an accounting expectation about a step of a [`GenericBatchSpec`]
//! (for example "the amount the maker receives equals the amount recorded in the offer") or
//! requires that a step succeeds. Checks are evaluated only against values observed from real
//! account state after real SVM execution; a failed check yields a [`CheckFinding`].
//!
//! [`GenericBatchSpec`]: crate::GenericBatchSpec

use serde::{Deserialize, Serialize};

use crate::generic_sbf::{SbfCallObservation, SbfCallSpec};

/// Source location a finding points to (for SARIF and code-scanning annotations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckLocation {
    /// Repository-relative file path.
    pub uri: String,
    /// 1-based line number.
    #[serde(default = "default_line")]
    pub line: u32,
}

fn default_line() -> u32 {
    1
}

/// One observed quantity: a value flow of an account in a step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantitySpec {
    /// Account label.
    pub account: String,
    /// Value-flow kind: `balance`, `fee`, `liability`, `reserve`, `shares` or `supply`.
    #[serde(default = "default_kind")]
    pub kind: String,
    /// `delta` (after - before), `before` or `after`.
    #[serde(default = "default_measure")]
    pub measure: String,
    /// Multiply the measured value by -1 (for outflows).
    #[serde(default)]
    pub negate: bool,
}

fn default_kind() -> String {
    "balance".to_string()
}

fn default_measure() -> String {
    "delta".to_string()
}

/// A declarative check evaluated on the steps whose `fn_name` matches [`CheckSpec::step`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckSpec {
    /// Stable rule identifier (e.g. `ESCROW-RECEIVED-001`).
    pub id: String,
    /// One-line description of the expectation.
    pub title: String,
    /// `error`, `warning` or `note`.
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Step `fn_name` the check applies to; every step when omitted.
    #[serde(default)]
    pub step: Option<String>,
    /// Require that the step does not revert.
    #[serde(default)]
    pub must_succeed: bool,
    /// Left-hand quantity of a comparison.
    #[serde(default)]
    pub left: Option<QuantitySpec>,
    /// Right-hand quantity of a comparison.
    #[serde(default)]
    pub right: Option<QuantitySpec>,
    /// Comparison operator: `eq`, `le` or `ge` (left OP right).
    #[serde(default = "default_op")]
    pub op: String,
    /// Source location to attach to findings.
    #[serde(default)]
    pub location: Option<CheckLocation>,
}

fn default_severity() -> String {
    "error".to_string()
}

fn default_op() -> String {
    "eq".to_string()
}

/// A failed check on one step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckFinding {
    /// Rule identifier.
    pub rule_id: String,
    /// Rule title.
    pub title: String,
    /// Severity (`error`, `warning`, `note`).
    pub severity: String,
    /// Index of the step in the batch.
    pub step_index: usize,
    /// Step `fn_name`, if any.
    pub step: Option<String>,
    /// Human-readable observation.
    pub message: String,
    /// Source location, if the check declared one.
    pub location: Option<CheckLocation>,
}

fn measure(obs: &SbfCallObservation, q: &QuantitySpec) -> Result<i128, String> {
    let flow = obs
        .value_flows
        .iter()
        .find(|f| f.account == q.account && f.kind == q.kind);
    let value = match (flow, q.measure.as_str()) {
        (Some(f), "delta") => f.delta,
        (Some(f), "before") => f.before,
        (Some(f), "after") => f.after,
        // No recorded flow of this kind means nothing changed (e.g. a reverted step).
        (None, "delta") => 0,
        (None, other) => {
            return Err(format!(
                "no `{}` value observed for `{}` (measure `{other}`)",
                q.kind, q.account
            ));
        }
        (Some(_), other) => return Err(format!("unknown measure `{other}`")),
    };
    Ok(if q.negate { -value } else { value })
}

fn describe(q: &QuantitySpec) -> String {
    let sign = if q.negate { "-" } else { "" };
    format!("{sign}{}.{}.{}", q.account, q.kind, q.measure)
}

/// Evaluate `checks` against the executed `calls` and their observations.
pub fn evaluate_checks(
    checks: &[CheckSpec],
    calls: &[SbfCallSpec],
    steps: &[SbfCallObservation],
) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    for check in checks {
        for (index, (call, obs)) in calls.iter().zip(steps).enumerate() {
            if let Some(step) = &check.step
                && call.fn_name.as_deref() != Some(step.as_str())
            {
                continue;
            }
            let mut fail = |message: String| {
                findings.push(CheckFinding {
                    rule_id: check.id.clone(),
                    title: check.title.clone(),
                    severity: check.severity.clone(),
                    step_index: index,
                    step: call.fn_name.clone(),
                    message,
                    location: check.location.clone(),
                });
            };
            if check.must_succeed && obs.status != "ok" {
                fail(format!(
                    "step {index} `{}` reverted: {}",
                    call.fn_name.as_deref().unwrap_or("call"),
                    obs.revert_reason
                ));
                continue;
            }
            let (Some(l), Some(r)) = (&check.left, &check.right) else {
                continue;
            };
            let (lv, rv) = match (measure(obs, l), measure(obs, r)) {
                (Ok(lv), Ok(rv)) => (lv, rv),
                (Err(e), _) | (_, Err(e)) => {
                    fail(format!("step {index}: cannot evaluate: {e}"));
                    continue;
                }
            };
            let holds = match check.op.as_str() {
                "le" => lv <= rv,
                "ge" => lv >= rv,
                _ => lv == rv,
            };
            if !holds {
                let op = match check.op.as_str() {
                    "le" => "<=",
                    "ge" => ">=",
                    _ => "==",
                };
                fail(format!(
                    "step {index} `{}`: expected {} {op} {}, observed {lv} vs {rv} (difference {})",
                    call.fn_name.as_deref().unwrap_or("call"),
                    describe(l),
                    describe(r),
                    lv - rv
                ));
            }
        }
    }
    findings
}

/// Render findings as an OASIS SARIF 2.1.0 log. `spec_uri` is used as the location of findings
/// whose check declared none.
pub fn findings_to_sarif(findings: &[CheckFinding], spec_uri: &str) -> serde_json::Value {
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for f in findings {
        if !seen.contains(&f.rule_id.as_str()) {
            seen.push(&f.rule_id);
            rules.push(serde_json::json!({
                "id": f.rule_id,
                "shortDescription": { "text": f.title },
                "properties": { "tags": ["security", "solana", "token-2022"] }
            }));
        }
    }
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let (uri, line) = f
                .location
                .as_ref()
                .map_or((spec_uri.to_string(), 1), |l| (l.uri.clone(), l.line));
            let level = match f.severity.as_str() {
                "warning" | "note" => f.severity.as_str(),
                _ => "error",
            };
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": format!("{}: {}", f.title, f.message) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": line }
                    }
                }]
            })
        })
        .collect();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "TokenScope",
                "informationUri": "https://github.com/integral-830/tokenscope",
                "rules": rules
            }},
            "results": results
        }]
    })
}
