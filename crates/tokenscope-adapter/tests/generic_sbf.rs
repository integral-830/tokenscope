//! Integration tests for GenericSbfAdapter and SbfRpcHandler.

use std::path::PathBuf;

use tokenscope_adapter::{
    AccountSetupSpec, CheckLocation, CheckSpec, GenericBatchSpec, GenericSbfAdapter,
    GenericSbfConfig, MintSetupSpec, QuantitySpec, SbfAccountMetaSpec, SbfCallSpec, SbfRpcHandler,
    SbfRpcRequest, SeedSpec, U64FieldSpec, default_program_dir, findings_to_sarif,
};

fn build_escrow_generic_config(elf_name: &str) -> GenericSbfConfig {
    let dir: PathBuf = default_program_dir();
    GenericSbfConfig {
        target_id: format!("generic-{elf_name}"),
        program_id: None,
        elf_path: dir.join(elf_name),
        extra_programs: vec![],
        mints: vec![MintSetupSpec {
            label: "mint".into(),
            decimals: 6,
            transfer_fee_bp: Some(200),
            maximum_fee: Some(u64::MAX),
            pausable: false,
            default_frozen: None,
            permanent_delegate: None,
            hook_program_label: None,
        }],
        accounts: vec![
            AccountSetupSpec {
                label: "depositor".into(),
                role: "depositor".into(),
                kind: "system".into(),
                mint: None,
                owner_label: None,
                associated: false,
                initial_amount: None,
                lamports: None,
                space: None,
                data_hex: None,
                pda_seeds: vec![],
                pda_program_label: None,
                u64_fields: vec![],
                authority_offsets: vec![],
            },
            AccountSetupSpec {
                label: "escrow_state".into(),
                role: "protocol".into(),
                kind: "program_owned".into(),
                mint: None,
                owner_label: Some("target".into()),
                associated: false,
                initial_amount: None,
                lamports: None,
                space: Some(105),
                data_hex: None,
                pda_seeds: vec![],
                pda_program_label: None,
                u64_fields: vec![U64FieldSpec {
                    name: "escrow_recorded".into(),
                    offset: 97,
                    kind: "liability".into(),
                    asset: Some("mint".into()),
                }],
                authority_offsets: vec![1],
            },
            AccountSetupSpec {
                label: "escrow_authority".into(),
                role: "protocol".into(),
                kind: "pda".into(),
                mint: None,
                owner_label: None,
                associated: false,
                initial_amount: None,
                lamports: None,
                space: None,
                data_hex: None,
                pda_seeds: vec![
                    SeedSpec::Utf8 {
                        value: "escrow".into(),
                    },
                    SeedSpec::Account {
                        label: "escrow_state".into(),
                    },
                ],
                pda_program_label: None,
                u64_fields: vec![],
                authority_offsets: vec![],
            },
            AccountSetupSpec {
                label: "vault".into(),
                role: "vault".into(),
                kind: "token".into(),
                mint: Some("mint".into()),
                owner_label: Some("escrow_authority".into()),
                associated: false,
                initial_amount: Some(0),
                lamports: None,
                space: None,
                data_hex: None,
                pda_seeds: vec![],
                pda_program_label: None,
                u64_fields: vec![],
                authority_offsets: vec![],
            },
            AccountSetupSpec {
                label: "depositor_source".into(),
                role: "depositor".into(),
                kind: "token".into(),
                mint: Some("mint".into()),
                owner_label: Some("depositor".into()),
                associated: false,
                initial_amount: Some(10_000),
                lamports: None,
                space: None,
                data_hex: None,
                pda_seeds: vec![],
                pda_program_label: None,
                u64_fields: vec![],
                authority_offsets: vec![],
            },
        ],
        setup_calls: vec![SbfCallSpec {
            program_label: None,
            data_hex: "00".into(),
            accounts: vec![
                SbfAccountMetaSpec {
                    label: "escrow_state".into(),
                    pubkey: None,
                    is_signer: false,
                    is_writable: true,
                },
                SbfAccountMetaSpec {
                    label: "depositor".into(),
                    pubkey: None,
                    is_signer: true,
                    is_writable: false,
                },
                SbfAccountMetaSpec {
                    label: "mint".into(),
                    pubkey: None,
                    is_signer: false,
                    is_writable: false,
                },
                SbfAccountMetaSpec {
                    label: "vault".into(),
                    pubkey: None,
                    is_signer: false,
                    is_writable: false,
                },
            ],
            caller_label: Some("depositor".into()),
            caller_role: Some("depositor".into()),
            fn_name: Some("init".into()),
        }],
    }
}

fn deposit_call(amount: u64) -> SbfCallSpec {
    let mut payload = vec![1u8];
    payload.extend_from_slice(&amount.to_le_bytes());
    let data_hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
    SbfCallSpec {
        program_label: None,
        data_hex,
        accounts: vec![
            SbfAccountMetaSpec {
                label: "escrow_state".into(),
                pubkey: None,
                is_signer: false,
                is_writable: true,
            },
            SbfAccountMetaSpec {
                label: "depositor".into(),
                pubkey: None,
                is_signer: true,
                is_writable: false,
            },
            SbfAccountMetaSpec {
                label: "depositor_source".into(),
                pubkey: None,
                is_signer: false,
                is_writable: true,
            },
            SbfAccountMetaSpec {
                label: "vault".into(),
                pubkey: None,
                is_signer: false,
                is_writable: true,
            },
            SbfAccountMetaSpec {
                label: "mint".into(),
                pubkey: None,
                is_signer: false,
                is_writable: false,
            },
            SbfAccountMetaSpec {
                label: "token2022".into(),
                pubkey: None,
                is_signer: false,
                is_writable: false,
            },
        ],
        caller_label: Some("depositor".into()),
        caller_role: Some("depositor".into()),
        fn_name: Some("deposit".into()),
    }
}

#[test]
fn generic_sbf_adapter_distinguishes_vulnerable_and_corrected_elfs() {
    let vuln = GenericSbfAdapter::new(GenericBatchSpec {
        config: build_escrow_generic_config("demo_escrow_vulnerable.so"),
        scenario: None,
        calls: vec![deposit_call(1_000)],
        checks: vec![],
    })
    .execute_batch()
    .expect("vulnerable generic batch");

    let corr = GenericSbfAdapter::new(GenericBatchSpec {
        config: build_escrow_generic_config("demo_escrow_corrected.so"),
        scenario: None,
        calls: vec![deposit_call(1_000)],
        checks: vec![],
    })
    .execute_batch()
    .expect("corrected generic batch");

    let v_step = &vuln.steps[0];
    assert_eq!(v_step.status, "ok");
    let v_vault = v_step
        .value_flows
        .iter()
        .find(|f| f.account == "vault" && f.kind == "balance")
        .unwrap();
    let v_rec = v_step
        .value_flows
        .iter()
        .find(|f| f.account == "escrow_state" && f.kind == "liability")
        .unwrap();
    assert_eq!(v_vault.delta, 980);
    assert_eq!(v_rec.delta, 1_000);

    let c_step = &corr.steps[0];
    let c_vault = c_step
        .value_flows
        .iter()
        .find(|f| f.account == "vault" && f.kind == "balance")
        .unwrap();
    let c_rec = c_step
        .value_flows
        .iter()
        .find(|f| f.account == "escrow_state" && f.kind == "liability")
        .unwrap();
    assert_eq!(c_vault.delta, 980);
    assert_eq!(c_rec.delta, 980);
}

#[test]
fn generic_sbf_rpc_snapshot_and_restore_rewind_svm_state() {
    let mut rpc = SbfRpcHandler::new();
    let (dep_res, exit1) = rpc.handle(SbfRpcRequest::Deploy {
        id: 1,
        config: build_escrow_generic_config("demo_escrow_vulnerable.so"),
    });
    assert!(!exit1);
    assert_eq!(dep_res["ok"], serde_json::json!(true));

    let (snap_res, _) = rpc.handle(SbfRpcRequest::Snapshot { id: 2 });
    let snap_id = snap_res["result"]["snapshot_id"].as_u64().unwrap();

    let (call_res, _) = rpc.handle(SbfRpcRequest::Call {
        id: 3,
        call: Some(deposit_call(1_000)),
        calls: vec![],
    });
    assert_eq!(call_res["ok"], serde_json::json!(true));

    let (read_after, _) = rpc.handle(SbfRpcRequest::ReadAccount {
        id: 4,
        label: "vault".into(),
    });
    assert_eq!(read_after["result"]["token_amount"], serde_json::json!(980));

    let (rst_res, _) = rpc.handle(SbfRpcRequest::Restore {
        id: 5,
        snapshot_id: snap_id,
    });
    assert_eq!(rst_res["ok"], serde_json::json!(true));

    let (read_restored, _) = rpc.handle(SbfRpcRequest::ReadAccount {
        id: 6,
        label: "vault".into(),
    });
    assert_eq!(
        read_restored["result"]["token_amount"],
        serde_json::json!(0)
    );
}

fn accounting_check() -> CheckSpec {
    CheckSpec {
        id: "INV-ACCT-001".into(),
        title: "Credited liability equals tokens the vault received".into(),
        severity: "error".into(),
        step: Some("deposit".into()),
        must_succeed: true,
        left: Some(QuantitySpec {
            account: "escrow_state".into(),
            kind: "liability".into(),
            measure: "delta".into(),
            negate: false,
        }),
        right: Some(QuantitySpec {
            account: "vault".into(),
            kind: "balance".into(),
            measure: "delta".into(),
            negate: false,
        }),
        op: "eq".into(),
        location: Some(CheckLocation {
            uri: "programs/demo-escrow/src/lib.rs".into(),
            line: 1,
        }),
    }
}

fn run_with_check(elf: &str, amount: u64) -> tokenscope_adapter::GenericBatchOutput {
    GenericSbfAdapter::new(GenericBatchSpec {
        config: build_escrow_generic_config(elf),
        scenario: None,
        calls: vec![deposit_call(amount)],
        checks: vec![accounting_check()],
    })
    .execute_batch()
    .expect("generic batch with checks")
}

#[test]
fn generic_checks_flag_vulnerable_escrow_and_pass_corrected() {
    let vuln = run_with_check("demo_escrow_vulnerable.so", 1_000);
    assert_eq!(vuln.findings.len(), 1, "{:?}", vuln.findings);
    let finding = &vuln.findings[0];
    assert_eq!(finding.rule_id, "INV-ACCT-001");
    assert_eq!(finding.step_index, 0);
    assert!(
        finding.message.contains("observed 1000 vs 980"),
        "{}",
        finding.message
    );

    let corr = run_with_check("demo_escrow_corrected.so", 1_000);
    assert!(corr.findings.is_empty(), "{:?}", corr.findings);
}

#[test]
fn generic_checks_report_reverted_steps_and_render_sarif() {
    // Depositing more than the source holds reverts inside Token-2022.
    let out = run_with_check("demo_escrow_corrected.so", 1_000_000);
    assert_eq!(out.steps[0].status, "reverted");
    assert_eq!(out.findings.len(), 1, "{:?}", out.findings);
    assert!(out.findings[0].message.contains("reverted"));

    let sarif = findings_to_sarif(&out.findings, "spec.json");
    assert_eq!(sarif["version"], "2.1.0");
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "INV-ACCT-001");
    assert_eq!(result["level"], "error");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "programs/demo-escrow/src/lib.rs"
    );
}
