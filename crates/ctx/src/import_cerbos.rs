//! Cerbos `api.cerbos.dev/v1` `resourcePolicy` subset importer for `ctx import-policy`.
//!
//! Only a documented, deterministic subset is translated: `resourcePolicy` with
//! `resource`, `version`, and `rules` (`actions`, `effect`, `roles`, and optional
//! `condition.match` with `all`/`any`/`none` and simple `expr` comparisons over
//! `R.attr.*`, `P.attr.*`, `P.id`, and `P.roles`). Any unsupported field or CEL
//! construct fails closed with an explicit error so no restriction is silently dropped
//! (threat T74).

use serde::Deserialize;
use serde_json::{Value, json};

use crate::import_policy::{ImportedEffect, ImportedRule};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CerbosDoc {
    #[serde(rename = "apiVersion")]
    api_version: String,
    #[serde(rename = "resourcePolicy")]
    resource_policy: ResourcePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourcePolicy {
    resource: String,
    #[serde(default)]
    version: Option<String>,
    rules: Vec<CerbosRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CerbosRule {
    #[serde(default)]
    name: Option<String>,
    actions: Vec<String>,
    effect: String,
    roles: Vec<String>,
    #[serde(default)]
    condition: Option<CerbosCondition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CerbosCondition {
    #[serde(rename = "match")]
    r#match: CerbosMatch,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CerbosMatch {
    #[serde(default)]
    expr: Option<String>,
    #[serde(default)]
    all: Option<MatchGroup>,
    #[serde(default)]
    any: Option<MatchGroup>,
    #[serde(default)]
    none: Option<MatchGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchGroup {
    of: Vec<CerbosMatch>,
}

pub(crate) fn parse(raw: Value) -> Result<(String, Vec<ImportedRule>), String> {
    let doc: CerbosDoc = serde_json::from_value(raw).map_err(|e| {
        format!(
            "unsupported Cerbos policy structure (only api.cerbos.dev/v1 resourcePolicy without \
             derivedRoles, schemas, variables or outputs is supported): {e}"
        )
    })?;
    if doc.api_version != "api.cerbos.dev/v1" {
        return Err(format!(
            "unsupported Cerbos apiVersion `{}`; expected `api.cerbos.dev/v1`",
            doc.api_version
        ));
    }
    let rp = doc.resource_policy;
    if rp.resource.trim().is_empty() {
        return Err("resourcePolicy.resource must not be empty".into());
    }
    if rp.rules.is_empty() {
        return Err("resourcePolicy.rules must contain at least one rule".into());
    }
    let mut imported = Vec::new();
    for (idx, rule) in rp.rules.iter().enumerate() {
        if rule.actions.is_empty() {
            return Err(format!("rule #{idx} has empty actions"));
        }
        if rule.roles.is_empty() {
            return Err(format!("rule #{idx} has empty roles"));
        }
        let effect = match rule.effect.as_str() {
            "EFFECT_ALLOW" => ImportedEffect::Allow,
            "EFFECT_DENY" => ImportedEffect::Deny,
            other => {
                return Err(format!(
                    "rule #{idx}: unsupported effect `{other}` (expected EFFECT_ALLOW or EFFECT_DENY)"
                ));
            }
        };
        let role_cond = if rule.roles.iter().any(|r| r == "*") {
            json!(true)
        } else if rule.roles.len() == 1 {
            json!({"==": [{"var": "user.role"}, rule.roles[0]]})
        } else {
            json!({"in": [{"var": "user.role"}, rule.roles]})
        };
        let extra_cond = match &rule.condition {
            Some(c) => Some(compile_match(&c.r#match)?),
            None => None,
        };
        let condition = match extra_cond {
            None => role_cond,
            Some(extra) if role_cond == json!(true) => extra,
            Some(extra) => json!({"and": [role_cond, extra]}),
        };
        for (a_idx, action) in rule.actions.iter().enumerate() {
            let intent = if action == "*" {
                rp.resource.clone()
            } else {
                format!("{}.{}", rp.resource, action)
            };
            let base_id = rule
                .name
                .clone()
                .unwrap_or_else(|| format!("CERBOS_{}_{}", sanitize(&rp.resource), idx + 1));
            let rule_id = if rule.actions.len() == 1 {
                sanitize(&base_id)
            } else {
                format!("{}_{}", sanitize(&base_id), a_idx + 1)
            };
            let version_note = rp.version.as_deref().unwrap_or("default");
            imported.push(ImportedRule {
                rule_id,
                intent: Some(intent),
                effect,
                condition: condition.clone(),
                roles: rule.roles.clone(),
                approver_role: None,
                rationale: format!(
                    "Imported from Cerbos resourcePolicy {} ({version_note}) action `{action}`.",
                    rp.resource
                ),
            });
        }
    }
    Ok((rp.resource, imported))
}

fn sanitize(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() { "RULE".into() } else { out }
}

fn compile_match(m: &CerbosMatch) -> Result<Value, String> {
    let count = usize::from(m.expr.is_some())
        + usize::from(m.all.is_some())
        + usize::from(m.any.is_some())
        + usize::from(m.none.is_some());
    if count != 1 {
        return Err("condition.match must specify exactly one of expr, all, any, or none".into());
    }
    if let Some(expr) = &m.expr {
        return parse_cel_subset(expr);
    }
    if let Some(group) = &m.all {
        if group.of.is_empty() {
            return Err("condition.match.all.of must not be empty".into());
        }
        let items = group.of.iter().map(compile_match).collect::<Result<Vec<_>, _>>()?;
        return Ok(json!({"and": items}));
    }
    if let Some(group) = &m.any {
        if group.of.is_empty() {
            return Err("condition.match.any.of must not be empty".into());
        }
        let items = group.of.iter().map(compile_match).collect::<Result<Vec<_>, _>>()?;
        return Ok(json!({"or": items}));
    }
    if let Some(group) = &m.none {
        if group.of.is_empty() {
            return Err("condition.match.none.of must not be empty".into());
        }
        let items = group.of.iter().map(compile_match).collect::<Result<Vec<_>, _>>()?;
        return Ok(json!({"!": {"or": items}}));
    }
    unreachable!()
}

// ---- deterministic CEL-subset parser ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    Bool(bool),
    And,
    Or,
    Not,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let two = input.get(i..i + 2);
        match two {
            Some("&&") => {
                out.push(Tok::And);
                i += 2;
                continue;
            }
            Some("||") => {
                out.push(Tok::Or);
                i += 2;
                continue;
            }
            Some("==") => {
                out.push(Tok::Eq);
                i += 2;
                continue;
            }
            Some("!=") => {
                out.push(Tok::Ne);
                i += 2;
                continue;
            }
            Some("<=") => {
                out.push(Tok::Le);
                i += 2;
                continue;
            }
            Some(">=") => {
                out.push(Tok::Ge);
                i += 2;
                continue;
            }
            _ => {}
        }
        match b {
            b'!' => {
                out.push(Tok::Not);
                i += 1;
            }
            b'<' => {
                out.push(Tok::Lt);
                i += 1;
            }
            b'>' => {
                out.push(Tok::Gt);
                i += 1;
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b'[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            b']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b'"' | b'\'' => {
                let quote = b;
                i += 1;
                let mut s = String::new();
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 1;
                    }
                    s.push(bytes[i] as char);
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err(format!("unterminated string literal in `{input}`"));
                }
                i += 1;
                out.push(Tok::Str(s));
            }
            b'0'..=b'9' | b'-' => {
                let start = i;
                if b == b'-' {
                    i += 1;
                }
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
                let raw = &input[start..i];
                let num: f64 = raw
                    .parse()
                    .map_err(|_| format!("invalid number `{raw}` in `{input}`"))?;
                out.push(Tok::Num(num));
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.') {
                    i += 1;
                }
                let word = &input[start..i];
                match word {
                    "true" => out.push(Tok::Bool(true)),
                    "false" => out.push(Tok::Bool(false)),
                    "in" => out.push(Tok::In),
                    _ => out.push(Tok::Ident(word.to_owned())),
                }
            }
            _ => {
                return Err(format!(
                    "unsupported character `{}` in Cerbos expression `{input}`",
                    b as char
                ));
            }
        }
    }
    Ok(out)
}

struct Parser<'a> {
    tokens: &'a [Tok],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Tok> {
        self.tokens.get(self.pos)
    }
    fn next(&mut self) -> Option<&'a Tok> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn parse_or(&mut self) -> Result<Value, String> {
        let mut items = vec![self.parse_and()?];
        while self.peek() == Some(&Tok::Or) {
            self.next();
            items.push(self.parse_and()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            json!({"or": items})
        })
    }
    fn parse_and(&mut self) -> Result<Value, String> {
        let mut items = vec![self.parse_unary()?];
        while self.peek() == Some(&Tok::And) {
            self.next();
            items.push(self.parse_unary()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            json!({"and": items})
        })
    }
    fn parse_unary(&mut self) -> Result<Value, String> {
        if self.peek() == Some(&Tok::Not) {
            self.next();
            let inner = self.parse_unary()?;
            return Ok(json!({"!": inner}));
        }
        self.parse_cmp()
    }
    fn parse_cmp(&mut self) -> Result<Value, String> {
        let left = self.parse_atom()?;
        let op = match self.peek() {
            Some(Tok::Eq) => "==",
            Some(Tok::Ne) => "!=",
            Some(Tok::Lt) => "<",
            Some(Tok::Le) => "<=",
            Some(Tok::Gt) => ">",
            Some(Tok::Ge) => ">=",
            Some(Tok::In) => "in",
            _ => return Ok(left),
        };
        self.next();
        let right = self.parse_atom()?;
        Ok(json!({op: [left, right]}))
    }
    fn parse_atom(&mut self) -> Result<Value, String> {
        match self.next() {
            Some(Tok::LParen) => {
                let expr = self.parse_or()?;
                if self.next() != Some(&Tok::RParen) {
                    return Err("expected `)` in Cerbos expression".into());
                }
                Ok(expr)
            }
            Some(Tok::LBracket) => {
                let mut list = Vec::new();
                if self.peek() != Some(&Tok::RBracket) {
                    loop {
                        list.push(self.parse_atom()?);
                        match self.peek() {
                            Some(Tok::Comma) => {
                                self.next();
                            }
                            Some(Tok::RBracket) => break,
                            _ => return Err("expected `,` or `]` in list literal".into()),
                        }
                    }
                }
                self.next();
                Ok(Value::Array(list))
            }
            Some(Tok::Str(s)) => Ok(json!(s)),
            Some(Tok::Bool(b)) => Ok(json!(b)),
            Some(Tok::Num(n)) => Ok(json!(n)),
            Some(Tok::Ident(ident)) => {
                if self.peek() == Some(&Tok::LParen) {
                    return Err(format!(
                        "unsupported CEL function call `{ident}(...)`; only attribute comparisons are supported"
                    ));
                }
                map_cel_var(ident)
            }
            other => Err(format!("unexpected token `{other:?}` in Cerbos expression")),
        }
    }
}

fn map_cel_var(ident: &str) -> Result<Value, String> {
    if let Some(rest) = ident.strip_prefix("R.attr.") {
        if rest.is_empty() {
            return Err("empty resource attribute path".into());
        }
        return Ok(json!({"var": format!("request.context.{rest}")}));
    }
    if let Some(rest) = ident.strip_prefix("P.attr.") {
        if rest.is_empty() {
            return Err("empty principal attribute path".into());
        }
        return Ok(json!({"var": format!("user.{rest}")}));
    }
    match ident {
        "P.id" => Ok(json!({"var": "user.user_id"})),
        "P.roles" => Ok(json!({"var": "user.role"})),
        other => Err(format!(
            "unsupported Cerbos identifier `{other}` (supported: R.attr.*, P.attr.*, P.id, P.roles)"
        )),
    }
}

pub(crate) fn parse_cel_subset(expr: &str) -> Result<Value, String> {
    let tokens = tokenize(expr)?;
    if tokens.is_empty() {
        return Err("empty Cerbos expression".into());
    }
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
    };
    let ast = parser.parse_or()?;
    if parser.pos != tokens.len() {
        return Err(format!(
            "unexpected trailing token `{:?}` in Cerbos expression `{expr}`",
            tokens[parser.pos]
        ));
    }
    Ok(ast)
}
