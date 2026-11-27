//! Target adapters.
//!
//! A program ID alone does not define behavior: an adapter says how to deploy the program, set up
//! its accounts, build its instructions, and observe its state. [`EscrowAdapter`] targets the demo
//! escrow in `programs/demo-escrow`; [`GenericSbfAdapter`] runs any compiled SBF program described
//! by a JSON spec and evaluates the spec's declarative checks.

mod escrow;
pub mod generic_checks;
pub mod generic_sbf;

pub use escrow::{EscrowAdapter, EscrowFlavor, default_program_dir};
pub use generic_checks::{
    CheckFinding, CheckLocation, CheckSpec, QuantitySpec, evaluate_checks, findings_to_sarif,
};
pub use generic_sbf::{
    AccountSetupSpec, ExtraProgramSpec, GenericBatchOutput, GenericBatchSpec, GenericSbfAdapter,
    GenericSbfConfig, GenericSbfSession, MintSetupSpec, ObservedPrivilegeChange,
    ObservedStateDelta, ObservedValueFlow, SbfAccountMetaSpec, SbfCallObservation, SbfCallSpec,
    SbfRpcHandler, SbfRpcRequest, SeedSpec, U64FieldSpec,
};
use tokenscope_executor::ExecError;
use tokenscope_model::{ExecutionTrace, Scenario};

/// Declared capabilities of a target adapter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdapterCapabilities {
    /// Whether this adapter captures raw account state alongside domain snapshots.
    pub raw_state_capture: bool,
    /// Whether this adapter supports multi-instruction atomic transactions.
    pub multi_instruction: bool,
    /// Whether this adapter supports CPI tracing.
    pub cpi_tracing: bool,
    /// Whether this adapter supports multiple programs in one environment.
    pub multi_program: bool,
    /// Whether this adapter supports custom account decoders.
    pub custom_decoders: bool,
}

/// Version information for a target adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterVersion {
    /// Adapter name.
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Schema version this adapter produces.
    pub schema_version: u32,
}

/// Common contract for program target adapters.
///
/// An adapter encapsulates program-specific deployment, account provisioning,
/// instruction encoding, and state observation over real Solana VM execution.
///
/// Required methods define the minimal contract. Default methods extend the
/// adapter with metadata and generic state capture that existing adapters get
/// for free without breaking changes.
pub trait TargetAdapter {
    /// Target identifier matching [`Scenario::target`].
    fn target_id(&self) -> &str;

    /// Execute the scenario and produce an execution trace with before/after snapshots.
    fn run(&self, scenario: &Scenario) -> Result<ExecutionTrace, ExecError>;

    /// Adapter version and metadata. Override to provide real values.
    fn version(&self) -> AdapterVersion {
        AdapterVersion {
            name: self.target_id().to_string(),
            version: "0.1.0".to_string(),
            schema_version: tokenscope_model::SCHEMA_VERSION,
        }
    }

    /// Declared capabilities of this adapter.
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::default()
    }

    /// Human-readable description of the target program this adapter tests.
    fn description(&self) -> &str {
        "No description provided"
    }

    /// List of supported target identifiers. For adapters that handle multiple
    /// flavors (e.g. vulnerable vs corrected), this returns all of them.
    fn supported_targets(&self) -> Vec<&str> {
        vec![self.target_id()]
    }
}

impl TargetAdapter for EscrowAdapter {
    fn target_id(&self) -> &str {
        self.flavor().target_id()
    }

    fn run(&self, scenario: &Scenario) -> Result<ExecutionTrace, ExecError> {
        self.run(scenario)
    }

    fn version(&self) -> AdapterVersion {
        AdapterVersion {
            name: "EscrowAdapter".to_string(),
            version: "0.1.0".to_string(),
            schema_version: tokenscope_model::SCHEMA_VERSION,
        }
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            raw_state_capture: false,
            multi_instruction: true,
            cpi_tracing: false,
            multi_program: true,
            custom_decoders: false,
        }
    }

    fn description(&self) -> &str {
        "Demo escrow adapter for Token-2022 adversarial testing"
    }

    fn supported_targets(&self) -> Vec<&str> {
        vec!["demo-escrow-vulnerable", "demo-escrow-corrected"]
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::*;

    #[test]
    fn escrow_adapter_capabilities_are_declared() {
        let adapter = EscrowAdapter::new(EscrowFlavor::Corrected);
        let caps = adapter.capabilities();
        assert!(caps.multi_instruction);
        assert!(caps.multi_program);
        assert!(!caps.raw_state_capture);
        assert!(!caps.cpi_tracing);
    }

    #[test]
    fn escrow_adapter_version_is_valid() {
        let adapter = EscrowAdapter::new(EscrowFlavor::Vulnerable);
        let ver = adapter.version();
        assert_eq!(ver.name, "EscrowAdapter");
        assert_eq!(ver.schema_version, tokenscope_model::SCHEMA_VERSION);
    }

    #[test]
    fn escrow_adapter_lists_both_targets() {
        let adapter = EscrowAdapter::new(EscrowFlavor::Corrected);
        let targets = adapter.supported_targets();
        assert!(targets.contains(&"demo-escrow-vulnerable"));
        assert!(targets.contains(&"demo-escrow-corrected"));
    }

    #[test]
    fn default_capabilities_are_all_false() {
        let caps = AdapterCapabilities::default();
        assert!(!caps.raw_state_capture);
        assert!(!caps.multi_instruction);
        assert!(!caps.cpi_tracing);
        assert!(!caps.multi_program);
        assert!(!caps.custom_decoders);
    }
}
