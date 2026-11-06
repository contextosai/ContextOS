//! The configuration's JSON Schema, generated from the types `Config::load` parses, so
//! the published schema and reference cannot drift from what the server accepts.
//!
//! `contextosd --config-schema` prints it (editors with a TOML language server use it
//! for completion and checking). `deploy/contextosd-config.schema.json` and
//! `docs/CONFIG.md` are generated from it; a test fails when either is stale.

use std::fmt::Write as _;

use serde_json::Value;

/// The JSON Schema of the configuration file.
pub fn schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(crate::Config)).unwrap_or_default();
    schema["title"] = Value::String("contextosd configuration".into());
    clean(&mut schema);
    schema
}

/// Descriptions without rustdoc link syntax or source line breaks.
fn clean(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if let Value::String(text) = v
                    && key == "description"
                {
                    *text = plain(text);
                } else {
                    clean(v);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(clean),
        _ => {}
    }
}

/// Rustdoc links (`` [`crate::audit_sinks`] ``) read as plain code in a reference.
fn plain(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("[`") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        if let Some(end) = tail.find("`]") {
            let name = &tail[1..end];
            out.push('`');
            out.push_str(name.strip_prefix("crate::").unwrap_or(name));
            out.push('`');
            rest = &tail[end + 2..];
        } else {
            out.push('[');
            rest = tail;
        }
    }
    out.push_str(rest);
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

struct Doc<'a> {
    defs: &'a serde_json::Map<String, Value>,
    out: String,
}

impl<'a> Doc<'a> {
    fn resolve(&self, schema: &'a Value) -> &'a Value {
        schema["$ref"]
            .as_str()
            .and_then(|r| r.strip_prefix("#/$defs/"))
            .and_then(|name| self.defs.get(name))
            .unwrap_or(schema)
    }

    /// String values a schema allows, if it is a string enumeration.
    fn choices(&self, schema: &'a Value) -> Option<Vec<String>> {
        let schema = self.resolve(schema);
        if let Some(values) = schema["enum"].as_array() {
            return values
                .iter()
                .map(|v| v.as_str().map(|s| format!("`\"{s}\"`")))
                .collect();
        }
        if let Some(c) = schema["const"].as_str() {
            return Some(vec![format!("`\"{c}\"`")]);
        }
        let variants = schema["oneOf"].as_array().or(schema["anyOf"].as_array())?;
        let mut all = Vec::new();
        for v in variants {
            all.extend(self.choices(v)?);
        }
        Some(all)
    }

    fn is_table(&self, schema: &'a Value) -> bool {
        let schema = self.resolve(schema);
        schema["properties"].is_object() || (schema["oneOf"].is_array() && self.choices(schema).is_none())
    }

    fn type_name(&self, schema: &'a Value) -> String {
        if let Some(choices) = self.choices(schema) {
            return choices.join(" \\| ");
        }
        let resolved = self.resolve(schema);
        if self.is_table(resolved) {
            return "table".into();
        }
        if let Some(inner) = resolved["anyOf"].as_array() {
            let named: Vec<String> = inner
                .iter()
                .filter(|v| v["type"] != "null")
                .map(|v| self.type_name(v))
                .collect();
            return named.join(" \\| ");
        }
        let types: Vec<&str> = match &resolved["type"] {
            Value::String(t) => vec![t.as_str()],
            Value::Array(ts) => ts.iter().filter_map(Value::as_str).filter(|t| *t != "null").collect(),
            _ => vec![],
        };
        match types.as_slice() {
            ["array"] => {
                let items = &resolved["items"];
                if self.is_table(items) {
                    "array of tables".into()
                } else {
                    format!("array of {}", self.type_name(items))
                }
            }
            ["object"] => "table of any".into(),
            [] => "any".into(),
            ts => ts.join(" \\| "),
        }
    }

    fn row(&mut self, key: &str, schema: &'a Value, required: bool) {
        let resolved = self.resolve(schema);
        let default = match schema.get("default") {
            _ if required => "required".to_owned(),
            Some(Value::Null) | None => "unset".to_owned(),
            Some(v) if v.as_array().is_some_and(Vec::is_empty) => "`[]`".to_owned(),
            Some(v) if v.is_object() => "see below".to_owned(),
            Some(v) => format!("`{v}`"),
        };
        let description = schema["description"]
            .as_str()
            .or(resolved["description"].as_str())
            .map(plain)
            .unwrap_or_default();
        let description = description.replace('|', "\\|");
        let _ = writeln!(
            self.out,
            "| `{key}` | {} | {default} | {description} |",
            self.type_name(schema)
        );
    }

    /// One table's keys, then a section for each nested table.
    fn table(&mut self, path: &str, schema: &'a Value, level: usize) {
        let schema = self.resolve(schema);
        if let Some(variants) = schema["oneOf"].as_array() {
            for variant in variants {
                let tag = variant["properties"]
                    .as_object()
                    .and_then(|p| {
                        p.iter()
                            .find_map(|(k, v)| v["const"].as_str().map(|c| format!("{k} = \"{c}\"")))
                    })
                    .unwrap_or_default();
                let _ = write!(self.out, "\n{} `{path}` with `{tag}`\n\n", "#".repeat(level + 1));
                self.table(path, variant, level + 1);
            }
            return;
        }
        if let Some(description) = schema["description"].as_str() {
            let _ = write!(self.out, "{}\n\n", plain(description));
        }
        let Some(properties) = schema["properties"].as_object() else {
            return;
        };
        let required: Vec<&str> = schema["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        self.out
            .push_str("| Key | Type | Default | Description |\n|---|---|---|---|\n");
        let mut nested = Vec::new();
        for (key, property) in properties {
            self.row(key, property, required.contains(&key.as_str()));
            let resolved = self.resolve(property);
            let child = format!("{path}.{key}");
            if self.is_table(property) {
                nested.push((format!("[{child}]"), child, property));
            } else if resolved["items"].is_object() && self.is_table(&resolved["items"]) {
                nested.push((format!("[[{child}]]"), child, &resolved["items"]));
            }
        }
        for (title, child, property) in nested {
            let _ = write!(self.out, "\n{} `{title}`\n\n", "#".repeat(level + 1));
            self.table(&child, property, level + 1);
        }
    }
}

/// The configuration reference (`docs/CONFIG.md`), rendered from [`schema`].
pub fn reference(schema: &Value) -> String {
    let empty = serde_json::Map::new();
    let mut doc = Doc {
        defs: schema["$defs"].as_object().unwrap_or(&empty),
        out: String::new(),
    };
    doc.out.push_str(
        "# contextosd configuration reference\n\n\
         Generated from the server's configuration types by\n\
         `CONTEXTOS_BLESS=1 cargo test -p contextosd --test generated`; do not edit by hand.\n\
         The same schema is `deploy/contextosd-config.schema.json` and\n\
         `contextosd --config-schema`. [GUIDE.md](GUIDE.md) explains when to use each\n\
         setting; `contextosd --check-config` validates a file and its environment.\n\n\
         Unknown keys are refused. Tables written `[[name]]` repeat.\n\n## Top-level keys\n\n",
    );
    let properties = schema["properties"].as_object().cloned().unwrap_or_default();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    doc.out
        .push_str("| Key | Type | Default | Description |\n|---|---|---|---|\n");
    let mut sections = Vec::new();
    for (key, property) in &properties {
        doc.row(key, property, required.contains(&key.as_str()));
        let resolved = doc.resolve(property);
        if doc.is_table(property) {
            sections.push((format!("[{key}]"), key.clone(), property.clone()));
        } else if resolved["items"].is_object() && doc.is_table(&resolved["items"]) {
            sections.push((format!("[[{key}]]"), key.clone(), resolved["items"].clone()));
        }
    }
    let mut out = std::mem::take(&mut doc.out);
    for (title, path, property) in &sections {
        let mut section = Doc {
            defs: doc.defs,
            out: format!("\n## `{title}`\n\n"),
        };
        section.table(path, property, 2);
        out.push_str(&section.out);
    }
    out
}
