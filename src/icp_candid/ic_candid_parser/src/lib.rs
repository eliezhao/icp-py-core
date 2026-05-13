// Copyright (c) 2021 Rocklabs
// Copyright (c) 2024 eliezhao (ICP-PY-CORE maintainer)
//
// Licensed under the MIT License
// See LICENSE file for details

use candid_parser::syntax::Binding;
use pyo3::prelude::*;
use candid_parser::{IDLProg};
use candid_parser::syntax::{Dec, IDLType};
use candid::types::FuncMode;
use serde::Serialize;

// --- 1. Define intermediate JSON protocol ---
// We define a clear JSON structure as the communication protocol between Rust and Python

#[derive(Serialize)]
struct ParsedResult {
    env: Vec<DefEntry>,       // Type definitions: type A = ...
    actor: Option<ActorEntry> // Actor definition: service : { ... }
}

#[derive(Serialize)]
struct DefEntry {
    name: String,
    // Python loader expects 'datatype' field name
    datatype: JsonType,
}

#[derive(Serialize)]
struct ActorEntry {
    methods: Vec<MethodEntry>,
    init: Option<Vec<JsonType>>, // Service initialization parameters
}

#[derive(Serialize)]
struct MethodEntry {
    name: String,
    args: Vec<JsonType>,
    rets: Vec<JsonType>,
    modes: Vec<String>, // "query", "oneway"
}

// Custom serialization to ensure consistent format: {"type": "...", "value": ...}
// All types including unit variants (Principal, Empty, etc.) should have "value" field
// This matches Python loader's expectation: {"type": ..., "value": ...}
// Record and Variant use Vec<(String, JsonType)> to serialize as [["key", type], ...]
// which matches Python's expected array format
#[derive(Serialize)]
#[serde(tag = "type", content = "value")]
enum JsonType {
    Prim(String),                    // nat, int, text...
    Principal(()),                   // Unit tuple to ensure "value" field (null)
    Vec(Box<JsonType>),
    Opt(Box<JsonType>),
    // Use Vec<(String, JsonType)> to serialize as [["key", type], ...]
    // This matches Python loader's expectation for array format
    Record(Vec<(String, JsonType)>),
    Variant(Vec<(String, JsonType)>),
    Func { args: Vec<JsonType>, rets: Vec<JsonType>, modes: Vec<String> },
    Service(Vec<MethodEntry>),
    Id(String),                      // Reference to other type (type A = B)
}

/// Convert a Candid FuncMode to the canonical textual token used by the
/// Python encoder ("query", "oneway", "composite_query"). Previously we
/// used `format!("{:?}", m).to_lowercase()`, which produced
/// "compositequery" (no underscore) and broke round-tripping of any DID
/// file that declares a composite_query method.
fn mode_to_string(m: &FuncMode) -> String {
    match m {
        FuncMode::Oneway => "oneway",
        FuncMode::Query => "query",
        FuncMode::CompositeQuery => "composite_query",
    }
    .to_string()
}

// --- 2. Conversion logic: Candid AST -> JSON ---

fn convert_type(t: &IDLType) -> JsonType {
    match t {
        IDLType::PrimT(p) => {
            let s = format!("{:?}", p).to_lowercase();
            JsonType::Prim(s)
        },
        IDLType::PrincipalT => JsonType::Principal(()),
        IDLType::VarT(name) => JsonType::Id(name.clone()),
        IDLType::OptT(inner) => JsonType::Opt(Box::new(convert_type(inner))),
        IDLType::VecT(inner) => JsonType::Vec(Box::new(convert_type(inner))),
        IDLType::RecordT(fields) => {
            // Convert Vec<Field> to Vec<(String, JsonType)> for array format
            // This matches Python loader's expectation: [["key", type], ...]
            let fs: Vec<(String, JsonType)> = fields.iter()
                .map(|f| (f.label.to_string(), convert_type(&f.typ)))
                .collect();
            JsonType::Record(fs)
        },
        IDLType::VariantT(fields) => {
            // Convert Vec<Field> to Vec<(String, JsonType)> for array format
            // This matches Python loader's expectation: [["key", type], ...]
            let fs: Vec<(String, JsonType)> = fields.iter()
                .map(|f| (f.label.to_string(), convert_type(&f.typ)))
                .collect();
            JsonType::Variant(fs)
        },
        IDLType::FuncT(func) => {
            let args = func.args.iter().map(convert_type).collect();
            let rets = func.rets.iter().map(convert_type).collect();
            let modes = func.modes.iter().map(mode_to_string).collect();
            JsonType::Func { args, rets, modes }
        },
        IDLType::ServT(methods) => {
            let ms = methods.iter().map(convert_method).collect();
            JsonType::Service(ms)
        },
        IDLType::ClassT(_, serv) => convert_type(serv), // Class downgraded to Service for processing
    }
}

fn convert_method(m: &Binding) -> MethodEntry {
    if let IDLType::FuncT(func) = &m.typ {
        MethodEntry {
            name: m.id.clone(),
            args: func.args.iter().map(convert_type).collect(),
            rets: func.rets.iter().map(convert_type).collect(),
            modes: func.modes.iter().map(mode_to_string).collect(),
        }
    } else {
        // Theoretically Service fields must be Func, this is defensive code
        MethodEntry { name: m.id.clone(), args: vec![], rets: vec![], modes: vec![] }
    }
}

/// Look up a type name in the declarations and extract service methods if found.
/// This handles the VarT pattern: service : () -> TypeName
fn lookup_service_type(decs: &[Dec], type_name: &str, init: Option<Vec<JsonType>>) -> Option<ActorEntry> {
    for dec in decs {
        if let Dec::TypD(binding) = dec {
            // Convert binding.id to string for comparison (it might be an Id type)
            let binding_id_str = binding.id.to_string();
            if binding_id_str == type_name {
                match &binding.typ {
                    IDLType::ServT(methods) => {
                        let ms = methods.iter().map(convert_method).collect();
                        return Some(ActorEntry { methods: ms, init });
                    },
                    // Handle nested type references (type A = B; type B = service {...})
                    IDLType::VarT(nested_name) => {
                        let nested_name_str = nested_name.to_string();
                        return lookup_service_type(decs, &nested_name_str, init);
                    },
                    _ => {}
                }
                break;
            }
        }
    }
    None
}

// --- 3. Python interface ---

#[pyfunction]
fn parse_did(did_content: String) -> PyResult<String> {
    // Call official Parser
    let prog: IDLProg = did_content.parse()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Candid Syntax Error: {}", e)))?;

    // Convert data
    let mut env_list = Vec::new();
    for dec in &prog.decs {
        match dec {
            Dec::TypD(binding) => env_list.push(DefEntry {
                name: binding.id.clone(),
                datatype: convert_type(&binding.typ),
            }),
            // `import "path"` (ImportType) and `import service "path"`
            // (ImportServ) are recognized by the upstream candid_parser but
            // cannot be resolved here — we don't read files. The Python
            // loader's Id() lookups would silently resolve any referenced
            // external types to empty Rec() placeholders, which is much
            // worse than a clear error.
            //
            // The Candid spec allows imports; this binding intentionally
            // narrows scope: callers must inline their imports (e.g. with
            // `didc bind --inline`) before passing the source here.
            Dec::ImportType(path) | Dec::ImportServ(path) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!(
                        "import directives are not supported (saw `import {:?}`). \
                         Inline imports into a single .did source first.",
                        path
                    ),
                ));
            }
        }
    }

    let mut actor_entry = None;
    if let Some(actor) = &prog.actor {
        // Process actor definition, could be Service, Class, or VarT (type reference)
        match &actor.typ {
            IDLType::ServT(methods) => {
                let ms = methods.iter().map(convert_method).collect();
                actor_entry = Some(ActorEntry { methods: ms, init: None });
            },
            IDLType::ClassT(args, serv) => {
                let init_args: Vec<JsonType> = args.iter().map(convert_type).collect();
                // The service could be inline (ServT) or a type reference (VarT)
                match &**serv {
                    IDLType::ServT(methods) => {
                        let ms = methods.iter().map(convert_method).collect();
                        actor_entry = Some(ActorEntry { methods: ms, init: Some(init_args) });
                    },
                    IDLType::VarT(type_name) => {
                        // Look up the type reference in the environment
                        // Convert type_name to string (it might be an Id type)
                        let type_name_str = type_name.to_string();
                        actor_entry = lookup_service_type(&prog.decs, &type_name_str, Some(init_args));
                    },
                    _ => {}
                }
            },
            IDLType::VarT(type_name) => {
                // Handle type reference pattern: service : () -> TypeName
                // This is common in Motoko-generated DID files
                // Convert type_name to string (it might be an Id type)
                let type_name_str = type_name.to_string();
                actor_entry = lookup_service_type(&prog.decs, &type_name_str, None);
            },
            _ => {}
        }
    }

    let result = ParsedResult { env: env_list, actor: actor_entry };
    
    // Serialize to JSON string and return
    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

// [FIXED] Function name MUST match the module name imported in Python (_ic_candid_core)
#[pymodule]
fn _ic_candid_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_did, m)?)?;
    Ok(())
}