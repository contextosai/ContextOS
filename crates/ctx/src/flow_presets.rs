//! Information-flow presets for `ctx init-tool --preset`: labels for the tool sets where
//! the "lethal trifecta" bites (an agent that reads text outsiders wrote, holds private
//! data, and can send data out): GitHub, databases and CRMs.
//!
//! A preset matches the tool's name, word by word, against its rules in order; the first
//! rule with a matching word labels the draft's `flow` (and `sends_data` for a tool that
//! sends data out), and the description's review text says which rule and why. Output
//! is never labelled trusted. The labels are a reviewed starting point, not a decision:
//! the GitHub preset, for one, assumes public repositories for issue text and treats
//! every write as public, so private code read in a run cannot reach an issue, comment
//! or pull request. A tool no rule matches gets no labels.

use serde_json::{Value, json};

pub(crate) const PRESETS: [&str; 3] = ["github", "database", "crm"];

fn presets() -> Value {
    serde_json::from_str(include_str!("flow_presets.json")).unwrap_or(Value::Null)
}

/// The lowercase words of a tool name (split on non-alphanumerics and case changes).
fn words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if (!c.is_ascii_alphanumeric() || (c.is_ascii_uppercase() && previous_lower)) && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if c.is_ascii_alphanumeric() {
            word.push(c.to_ascii_lowercase());
        }
        previous_lower = c.is_ascii_lowercase();
    }
    words.push(word);
    words
}

/// The rule of `preset` that labels a tool named `name`, if any.
pub(crate) fn rule(preset: &str, name: &str) -> Result<Option<Value>, String> {
    let all = presets();
    let rules = all[preset]["rules"]
        .as_array()
        .ok_or_else(|| format!("unknown preset {preset}; one of {}", PRESETS.join(", ")))?;
    let words = words(name);
    Ok(rules
        .iter()
        .find(|r| {
            r["words"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|w| words.iter().any(|x| x == w))
        })
        .cloned())
}

/// Applies `preset` to a draft: its `flow`, `sends_data`, and a note in the description
/// review text saying where the labels came from.
pub(crate) fn apply(manifest: &mut Value, preset: &str, name: &str) -> Result<(), String> {
    let Some(rule) = rule(preset, name)? else {
        let note = format!(" (preset {preset}: no rule matched this tool's name; label its flow yourself)");
        if let Some(text) = manifest["description"].as_str() {
            manifest["description"] = json!(format!("{text}{note}"));
        }
        return Ok(());
    };
    manifest["flow"] = rule["flow"].clone();
    if rule["sends_data"] == true {
        manifest["sends_data"] = json!(true);
    }
    let note = format!(
        " (flow labels from preset {preset}, rule {}: {}; review them like every other field)",
        rule["role"].as_str().unwrap_or("?"),
        rule["why"].as_str().unwrap_or("")
    );
    if let Some(text) = manifest["description"].as_str() {
        manifest["description"] = json!(format!("{text}{note}"));
    }
    Ok(())
}
