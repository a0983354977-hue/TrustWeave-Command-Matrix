#![allow(dead_code, missing_docs)]
//! Dependency parsing and policy checking (Phase 6)
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dep{pub name:String,pub version:String,pub source:String,pub dev:bool,pub origin_file:String,pub kind:String}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepReport{pub dependencies:Vec<Dep>,pub dev_dependencies:Vec<Dep>,pub all:Vec<Dep>}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDepCheck{pub status:String,pub dep:Dep,pub matched_rule:Option<String>,pub reason:Option<String>}
