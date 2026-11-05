//! `ctx repl`: try a Context Pack interactively. A session holds one case (request,
//! run context, compile dependencies), starting from an admission body or replay case.
//! Each line is a command, and each answer is one JSON line, so a script can be piped
//! in as well as typed:
//!
//! ```text
//! set request.input.context.refund_amount 4200
//! decide
//! set run_context.user.role "supervisor"
//! plan
//! ```

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use contextos_contract::types::{ContextPack, RunContext};
use contextos_kernel::ContextPackCompiler;
use contextos_kernel::decision_plan::plan_decisions;
use contextos_kernel::pack_test::decide;
use serde_json::{Map, Value, json};

use crate::{Failure, read, typed};

const CASE_KEYS: [&str; 3] = ["request", "run_context", "deps"];

const HELP: &str = "decide | plan [intent] | set PATH JSON | unset PATH | show [PATH] | reset | help | quit; \
PATH is dotted from request, run_context or deps (request.input.context.refund_amount); \
a value that is not JSON is taken as a string";

fn base_case(body: &Value) -> Value {
    let kept: Map<String, Value> = body
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(k, _)| CASE_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Value::Object(kept)
}

fn segments(path: &str) -> Result<Vec<&str>, String> {
    let parts: Vec<&str> = path.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) || !CASE_KEYS.contains(&parts[0]) {
        return Err(format!("{path}: a path starts with request, run_context or deps"));
    }
    Ok(parts)
}

fn set(case: &mut Value, path: &str, value: Value) -> Result<(), String> {
    let parts = segments(path)?;
    let mut target = case;
    for part in &parts[..parts.len() - 1] {
        if !target[*part].is_object() {
            target[*part] = json!({});
        }
        target = &mut target[*part];
    }
    target[parts[parts.len() - 1]] = value;
    Ok(())
}

fn unset(case: &mut Value, path: &str) -> Result<(), String> {
    let parts = segments(path)?;
    let mut target = case;
    for part in &parts[..parts.len() - 1] {
        target = target.get_mut(*part).ok_or_else(|| format!("{path} is not set"))?;
    }
    target
        .as_object_mut()
        .and_then(|o| o.remove(parts[parts.len() - 1]))
        .map(|_| ())
        .ok_or_else(|| format!("{path} is not set"))
}

fn get<'a>(case: &'a Value, path: &str) -> Result<&'a Value, String> {
    segments(path)?
        .into_iter()
        .try_fold(case, |v, part| v.get(part))
        .ok_or_else(|| format!("{path} is not set"))
}

/// One command's answer; `None` ends the session.
fn answer(
    pack: &ContextPack,
    compiler: &ContextPackCompiler,
    base: &Value,
    case: &mut Value,
    line: &str,
) -> Option<Value> {
    let (command, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let rest = rest.trim();
    let result: Result<Value, String> = match command {
        "quit" | "exit" => return None,
        "help" => Ok(json!({"help": HELP})),
        "decide" => decide(compiler, case),
        "plan" => serde_json::from_value::<RunContext>(case["run_context"].clone())
            .map_err(|e| format!("run_context is invalid: {e}"))
            .and_then(|run_context| {
                let intent = (!rest.is_empty())
                    .then(|| rest.to_owned())
                    .or_else(|| run_context.intent.clone())
                    .or_else(|| case["request"]["input"]["intent"].as_str().map(str::to_owned))
                    .ok_or("no intent: plan INTENT, or set run_context.intent")?;
                plan_decisions(pack, &run_context, &intent).map(|p| serde_json::to_value(p).unwrap_or_default())
            }),
        "set" => match rest.split_once(char::is_whitespace) {
            Some((path, text)) => {
                let text = text.trim();
                let value = serde_json::from_str(text).unwrap_or_else(|_| json!(text));
                set(case, path, value.clone()).map(|()| json!({"set": path, "value": value}))
            }
            None => Err("set PATH VALUE".into()),
        },
        "unset" => unset(case, rest).map(|()| json!({"unset": rest})),
        "show" if rest.is_empty() => Ok(case.clone()),
        "show" => get(case, rest).cloned(),
        "reset" => {
            *case = base.clone();
            Ok(json!({"reset": true}))
        }
        other => Err(format!("unknown command {other}; {HELP}")),
    };
    Some(match result {
        Ok(value) => json!({"command": command, "result": value}),
        Err(error) => json!({"command": command, "error": error}),
    })
}

/// Runs a session until `quit` or the end of input. Prints only answers, one per line.
pub fn run(pack_path: &PathBuf, run: &PathBuf) -> Result<(), Failure> {
    let pack: ContextPack = typed(read(pack_path)?, "pack")?;
    let compiler =
        ContextPackCompiler::new(pack.clone()).map_err(|e| Failure::Rejected(json!({"error": e.to_string()})))?;
    let base = base_case(&read(run)?);
    if base.get("run_context").is_none() || base.get("request").is_none() {
        return Err(Failure::Usage(format!(
            "{}: needs request and run_context (an admission body or replay case)",
            run.display()
        )));
    }
    let mut case = base.clone();
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    let mut out = std::io::stdout();
    if interactive {
        eprintln!("ctx repl: {}; {HELP}", pack.pack_meta.pack_ref());
    }
    loop {
        if interactive {
            eprint!("ctx> ");
        }
        let mut line = String::new();
        if stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| Failure::Usage(e.to_string()))?
            == 0
        {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(reply) = answer(&pack, &compiler, &base, &mut case, line) else {
            break;
        };
        let text = if interactive {
            serde_json::to_string_pretty(&reply)
        } else {
            serde_json::to_string(&reply)
        };
        writeln!(out, "{}", text.unwrap_or_default()).map_err(|e| Failure::Usage(e.to_string()))?;
    }
    Ok(())
}
