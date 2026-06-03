//! Compliance rule evaluation engine (Stage 3)

pub mod remote;
pub mod wasm_engine;

pub use wasm_engine::WasmRuleEngine as RuleBackend;
