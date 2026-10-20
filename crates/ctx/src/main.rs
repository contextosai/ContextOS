//! `ctx`: offline ContextOS tooling on the same kernel the runtime uses.
//!
//! Exit codes: 0 success, 1 the input was evaluated and failed (invalid, rejected,
//! not allowed), 2 usage or I/O error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use contextos_contract::ingress::parse_strict;
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use contextos_kernel::authorization::digest_action_binding;
use contextos_kernel::{
    CompileDeps, CompileError, ContextPackCompiler, STANDARD_PROFILE_REGISTRY, negotiate_execution_contract,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "ctx", version, about = "ContextOS offline tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a JSON file against a published schema (e.g. `context-pack`, `execution-contract --def ActionBinding`).
    Validate {
        schema: String,
        file: PathBuf,
        #[arg(long)]
        def: Option<String>,
    },
    /// Compile a Context Pack for a request and run context.
    Compile {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        run_context: PathBuf,
        /// JSON object with optional `evidence`, `evidence_conflicts`, `promoted_memory` arrays.
        #[arg(long)]
        deps: Option<PathBuf>,
    },
    /// Print the RFC 8785 digest of an ActionBinding.
    Digest { binding: PathBuf },
    /// Negotiate an execution contract against the standard profile registry.
    Negotiate {
        #[arg(long)]
        contract: PathBuf,
        #[arg(long)]
        support: PathBuf,
        #[arg(long)]
        features: PathBuf,
    },
    /// Review a capability manifest before pinning it.
    Manifest { file: PathBuf },
    /// Print the standard profile registry.
    Profiles,
    /// Hash an API key for the server configuration (reads the key from stdin).
    HashKey,
}

enum Failure {
    Usage(String),
    Rejected(Value),
}

fn read(path: &PathBuf) -> Result<Value, Failure> {
    let bytes = std::fs::read(path).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    parse_strict(&bytes, 64 * 1024 * 1024).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))
}

fn typed<T: serde::de::DeserializeOwned>(value: Value, what: &str) -> Result<T, Failure> {
    serde_json::from_value(value).map_err(|e| Failure::Rejected(json!({"error": format!("{what}: {e}")})))
}

fn schema_target(name: &str, def: Option<&str>) -> Result<SchemaTarget, Failure> {
    let doc = SchemaDoc::ALL
        .into_iter()
        .find(|d| d.file_name().split(".v").next() == Some(name))
        .ok_or_else(|| {
            Failure::Usage(format!(
                "unknown schema {name}; known: {}",
                SchemaDoc::ALL.map(SchemaDoc::file_name).join(", ")
            ))
        })?;
    match def {
        Some(def) if doc.document()["$defs"].get(def).is_none() => {
            Err(Failure::Usage(format!("{name} has no definition {def}")))
        }
        Some(def) => Ok(SchemaTarget::def(doc, def)),
        None => Ok(SchemaTarget::document(doc)),
    }
}

fn run(command: Command) -> Result<Value, Failure> {
    match command {
        Command::Validate { schema, file, def } => {
            let target = schema_target(&schema, def.as_deref())?;
            let instance = read(&file)?;
            match validate(&target, &instance) {
                Ok(()) => Ok(json!({"valid": true})),
                Err(e) => Err(Failure::Rejected(json!({"valid": false, "violations": e.violations}))),
            }
        }
        Command::Compile {
            pack,
            request,
            run_context,
            deps,
        } => {
            let pack_value = read(&pack)?;
            if let Err(e) = validate(&SchemaTarget::document(SchemaDoc::ContextPack), &pack_value) {
                return Err(Failure::Rejected(
                    json!({"error": "pack does not conform to context-pack.v2", "violations": e.violations}),
                ));
            }
            let pack: ContextPack = typed(pack_value, "pack")?;
            let request: InvokeRequest = typed(read(&request)?, "request")?;
            let run_context: RunContext = typed(read(&run_context)?, "run_context")?;
            let deps_value = deps.map(|d| read(&d)).transpose()?.unwrap_or(Value::Null);
            let list = |key: &str| deps_value[key].as_array().cloned().unwrap_or_default();
            let deps = CompileDeps {
                evidence: list("evidence"),
                evidence_conflicts: list("evidence_conflicts"),
                promoted_memory: list("promoted_memory"),
            };
            let compiler =
                ContextPackCompiler::new(pack).map_err(|e| Failure::Rejected(json!({"error": e.to_string()})))?;
            match compiler.compile(&request, &run_context, &deps) {
                Ok(compiled) => Ok(serde_json::to_value(compiled).unwrap_or(Value::Null)),
                Err(CompileError::PolicyEval(detail)) => {
                    Err(Failure::Rejected(serde_json::to_value(&*detail).unwrap_or(Value::Null)))
                }
                Err(CompileError::Invalid(message)) => Err(Failure::Rejected(json!({"error": message}))),
            }
        }
        Command::Digest { binding } => match digest_action_binding(&read(&binding)?) {
            Ok(digest) => Ok(json!({"action_digest": digest})),
            Err(e) => Err(Failure::Rejected(json!({"error": e.to_string()}))),
        },
        Command::Negotiate {
            contract,
            support,
            features,
        } => {
            let registry = serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null);
            let result =
                negotiate_execution_contract(&read(&contract)?, &read(&support)?, &registry, &read(&features)?);
            let value = serde_json::to_value(&result).unwrap_or(Value::Null);
            if value["status"] == "accepted" {
                Ok(value)
            } else {
                Err(Failure::Rejected(value))
            }
        }
        Command::Manifest { file } => {
            let manifest: contextos_gateway::CapabilityManifest = typed(read(&file)?, "manifest")?;
            manifest
                .validate()
                .map_err(|e| Failure::Rejected(json!({"error": e.to_string()})))?;
            Ok(json!({"valid": true, "capability_id": manifest.capability_id}))
        }
        Command::Profiles => Ok(serde_json::to_value(&*STANDARD_PROFILE_REGISTRY).unwrap_or(Value::Null)),
        Command::HashKey => {
            let mut key = String::new();
            std::io::stdin()
                .read_line(&mut key)
                .map_err(|e| Failure::Usage(e.to_string()))?;
            let key = key.trim_end_matches(['\r', '\n']);
            if key.len() < 32 {
                return Err(Failure::Usage("API keys must be at least 32 characters".into()));
            }
            Ok(json!({"key_sha256": format!("sha256:{}", hex::encode(Sha256::digest(key.as_bytes())))}))
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(Failure::Rejected(value)) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            ExitCode::from(1)
        }
        Err(Failure::Usage(message)) => {
            eprintln!("ctx: {message}");
            ExitCode::from(2)
        }
    }
}
