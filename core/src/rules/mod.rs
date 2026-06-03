//! Compliance rule evaluation engine (Stage 3)

pub mod wasm_engine;
pub mod remote;

pub use wasm_engine::WasmRuleEngine as RuleBackend;
