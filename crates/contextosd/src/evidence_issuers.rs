//! Evidence issuers: who may vouch for a fact a decision's gate requires.
//!
//! Under `[guards] evidence = "strict"`, an evidence entry's `integrity` and
//! `freshness` are not the caller's to set. Each entry carries an `attestation`, a
//! compact JWS from a configured issuer whose payload is
//! `{iss, sub, satisfies, content_hash, observed_at, valid_until, source_version}`.
//! Before compiling, contextosd verifies it and rewrites the labels the compiler reads:
//!
//! - `integrity = "verified"` only when the signature is the issuer's, the issuer serves
//!   the run's tenant, every name the entry `satisfies` is both signed and one the
//!   issuer may satisfy, and `content_hash` is the hash of the entry's content.
//! - `freshness = "current"` only for a verified entry with
//!   `observed_at <= now < valid_until` and a validity no longer than the issuer's
//!   maximum; `"stale"` once `valid_until` has passed; `"unknown"` otherwise.
//!
//! The entry keeps the signed `observed_at` and `valid_until`, and a `verification`
//! record (evaluation time, issuer, subject, labels, reasons). Admission stores the
//! rewritten entries in the run's replay case, so replay reproduces the decision
//! without the clock. The compiler only ever sees labels: it stays pure.

use std::collections::BTreeSet;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contextos_contract::canonical::sha256_text;
use contextos_contract::validation::{compare_contract_times, elapsed_millis};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// `[[evidence_issuers]]`: one service trusted to vouch for named facts.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIssuerConfig {
    /// Exact `iss` of its attestations.
    pub issuer: String,
    /// Tenants whose runs may rely on it.
    pub tenants: Vec<String>,
    /// The `required_evidence` names it may satisfy.
    pub satisfies: Vec<String>,
    /// The longest `valid_until - observed_at` it may claim.
    pub max_validity_seconds: u64,
    /// Its signing algorithm (`EdDSA`, `ES256`, `ES384`, `RS256`, `PS256`, …).
    pub algorithm: String,
    /// Its public keys as a JWK Set (JSON text, as the issuer publishes it). A `kid`
    /// in an attestation's header selects one; several keys allow rotation.
    pub jwks: String,
}

struct Key {
    kid: Option<String>,
    key: DecodingKey,
}

struct Issuer {
    config: EvidenceIssuerConfig,
    algorithm: Algorithm,
    keys: Vec<Key>,
}

/// The configured issuers with their keys parsed.
#[derive(Default)]
pub struct Issuers(Vec<Issuer>);

impl std::fmt::Debug for Issuers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|i| &i.config.issuer)).finish()
    }
}

impl Issuers {
    /// Parses every issuer's keys; a configuration error names the issuer.
    pub fn new(configs: &[EvidenceIssuerConfig]) -> Result<Self, String> {
        let mut seen = BTreeSet::new();
        let mut issuers = Vec::new();
        for config in configs {
            let name = &config.issuer;
            if name.is_empty() || !seen.insert(name.as_str()) {
                return Err("evidence issuers need distinct, non-empty issuer values".into());
            }
            if config.tenants.is_empty() || config.satisfies.is_empty() || config.max_validity_seconds == 0 {
                return Err(format!(
                    "evidence issuer {name}: tenants, satisfies and max_validity_seconds must be set"
                ));
            }
            let algorithm = Algorithm::from_str(&config.algorithm)
                .ok()
                .filter(|a| !matches!(a, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512))
                .ok_or_else(|| format!("evidence issuer {name}: algorithm must be an asymmetric JWS algorithm"))?;
            let set: JwkSet =
                serde_json::from_str(&config.jwks).map_err(|e| format!("evidence issuer {name}: jwks: {e}"))?;
            let keys = set
                .keys
                .iter()
                .map(|jwk| {
                    DecodingKey::from_jwk(jwk)
                        .map(|key| Key {
                            kid: jwk.common.key_id.clone(),
                            key,
                        })
                        .map_err(|e| format!("evidence issuer {name}: jwks key: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if keys.is_empty() {
                return Err(format!("evidence issuer {name}: jwks has no keys"));
            }
            issuers.push(Issuer {
                config: config.clone(),
                algorithm,
                keys,
            });
        }
        Ok(Self(issuers))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Rewrites the labels of every object entry in `evidence` for a run of `tenant`
    /// evaluated at `now` (a contract timestamp). Legacy string entries are left
    /// alone: the compiler already treats them as untrusted.
    pub fn relabel(&self, tenant: &str, now: &str, evidence: &mut [Value]) {
        for entry in evidence.iter_mut().filter(|e| e.is_object()) {
            let verdict = self.verify(tenant, now, entry);
            entry["integrity"] = json!(if verdict.verified { "verified" } else { "untrusted" });
            entry["freshness"] = json!(verdict.freshness);
            for (field, value) in [
                ("observed_at", &verdict.observed_at),
                ("valid_until", &verdict.valid_until),
            ] {
                match value {
                    Some(time) => entry[field] = json!(time),
                    None => {
                        entry.as_object_mut().map(|o| o.remove(field));
                    }
                }
            }
            entry["verification"] = json!({
                "evaluated_at": now,
                "issuer": verdict.issuer,
                "subject": verdict.subject,
                "source_version": verdict.source_version,
                "integrity": entry["integrity"],
                "freshness": verdict.freshness,
                "reasons": verdict.reasons,
            });
        }
    }

    /// The configured issuer named by `iss` with the token's verified claims, or why
    /// not (`issuer_unknown`, `attestation_invalid`, `signature_invalid`).
    pub fn decode(&self, token: &str) -> Result<(&EvidenceIssuerConfig, Value), &'static str> {
        let iss = unverified_issuer(token).ok_or("attestation_invalid")?;
        let issuer = self.0.iter().find(|i| i.config.issuer == iss).ok_or("issuer_unknown")?;
        let claims = issuer.decode(token).ok_or("signature_invalid")?;
        Ok((&issuer.config, claims))
    }

    /// The configuration of the issuer named `iss`, if configured.
    #[must_use]
    pub fn config(&self, iss: &str) -> Option<&EvidenceIssuerConfig> {
        self.0.iter().find(|i| i.config.issuer == iss).map(|i| &i.config)
    }

    fn verify(&self, tenant: &str, now: &str, entry: &Value) -> Verdict {
        let mut verdict = Verdict {
            freshness: "unknown",
            ..Verdict::default()
        };
        let Some(token) = entry["attestation"].as_str() else {
            verdict.reasons.push("attestation_missing");
            return verdict;
        };
        let Some(iss) = unverified_issuer(token) else {
            verdict.reasons.push("attestation_invalid");
            return verdict;
        };
        let Some(issuer) = self.0.iter().find(|i| i.config.issuer == iss) else {
            verdict.reasons.push("issuer_unknown");
            return verdict;
        };
        let Some(claims) = issuer.decode(token) else {
            verdict.reasons.push("signature_invalid");
            return verdict;
        };
        verdict.issuer = Some(iss);
        verdict.subject = claims["sub"].as_str().map(str::to_owned);
        verdict.source_version = claims.get("source_version").cloned().filter(|v| !v.is_null());
        verdict.verified = true;
        if !issuer.config.tenants.iter().any(|t| t == tenant) {
            verdict.fail("issuer_not_for_tenant");
        }
        let signed: BTreeSet<&str> = claims["satisfies"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let claimed = entry["satisfies"].as_array().map_or(&[][..], Vec::as_slice);
        if claimed.iter().any(|name| {
            name.as_str()
                .is_none_or(|n| !signed.contains(n) || !issuer.config.satisfies.iter().any(|s| s == n))
        }) {
            verdict.fail("requirement_not_attested");
        }
        // The content the compiler hashes: `content`, or `evidence_ref` without it.
        let content = entry["content"].as_str().or_else(|| entry["evidence_ref"].as_str());
        if content.is_none_or(|c| claims["content_hash"].as_str() != Some(sha256_text(c).as_str())) {
            verdict.fail("content_mismatch");
        }
        let (observed, until) = (claims["observed_at"].as_str(), claims["valid_until"].as_str());
        verdict.observed_at = observed.map(str::to_owned);
        verdict.valid_until = until.map(str::to_owned);
        verdict.freshness = match (observed, until) {
            _ if !verdict.verified => "unknown",
            (Some(observed), Some(until)) => freshness(
                now,
                observed,
                until,
                issuer.config.max_validity_seconds,
                &mut verdict.reasons,
            ),
            _ => {
                verdict.reasons.push("validity_missing");
                "unknown"
            }
        };
        verdict
    }
}

impl Issuer {
    fn decode(&self, token: &str) -> Option<Value> {
        let kid = jsonwebtoken::decode_header(token).ok()?.kid;
        let mut validation = Validation::new(self.algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_required_spec_claims(&["iss"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        self.keys
            .iter()
            .filter(|k| kid.is_none() || k.kid.is_none() || k.kid == kid)
            .find_map(|k| jsonwebtoken::decode::<Value>(token, &k.key, &validation).ok())
            .map(|data| data.claims)
    }
}

#[derive(Default)]
struct Verdict {
    verified: bool,
    freshness: &'static str,
    issuer: Option<String>,
    subject: Option<String>,
    source_version: Option<Value>,
    observed_at: Option<String>,
    valid_until: Option<String>,
    reasons: Vec<&'static str>,
}

impl Verdict {
    fn fail(&mut self, reason: &'static str) {
        self.verified = false;
        self.reasons.push(reason);
    }
}

pub(crate) fn freshness(
    now: &str,
    observed: &str,
    until: &str,
    max_seconds: u64,
    reasons: &mut Vec<&'static str>,
) -> &'static str {
    use std::cmp::Ordering::Less;
    let Some(span) = elapsed_millis(observed, until).filter(|ms| *ms > 0) else {
        reasons.push("validity_invalid");
        return "unknown";
    };
    if span > max_seconds.saturating_mul(1000) {
        reasons.push("validity_too_long");
        return "unknown";
    }
    match (
        compare_contract_times(now, observed),
        compare_contract_times(now, until),
    ) {
        (Some(Less), _) => {
            reasons.push("observed_in_future");
            "unknown"
        }
        (Some(_), Some(Less)) => "current",
        (Some(_), Some(_)) => {
            reasons.push("expired");
            "stale"
        }
        _ => {
            reasons.push("validity_invalid");
            "unknown"
        }
    }
}

/// The `iss` of a compact JWS, unverified: it only selects which keys to try.
fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    claims["iss"].as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{EncodingKey, Header};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    const NOW: &str = "2026-11-02T12:00:00Z";
    const ISS: &str = "https://kyc.example.test";

    struct Signer(Vec<u8>, Vec<u8>);

    impl Signer {
        fn new() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            let public = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .unwrap()
                .public_key()
                .as_ref()
                .to_vec();
            Self(pkcs8.as_ref().to_vec(), public)
        }

        fn jwks(&self) -> String {
            json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode(&self.1)}]})
            .to_string()
        }

        fn sign(&self, claims: &Value) -> String {
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("k1".into());
            jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(&self.0)).unwrap()
        }
    }

    fn issuers(signer: &Signer) -> Issuers {
        Issuers::new(&[EvidenceIssuerConfig {
            issuer: ISS.into(),
            tenants: vec!["tenant_acme".into()],
            satisfies: vec!["identity_verified".into()],
            max_validity_seconds: 86_400,
            algorithm: "EdDSA".into(),
            jwks: signer.jwks(),
        }])
        .unwrap()
    }

    fn claims() -> Value {
        json!({"iss": ISS, "sub": "customer:cus_77", "satisfies": ["identity_verified"],
            "content_hash": sha256_text("customer cus_77 verified"),
            "observed_at": "2026-11-02T11:00:00Z", "valid_until": "2026-11-02T13:00:00Z", "source_version": "kyc@4"})
    }

    /// An entry the caller labels verified and current, attested by `token`.
    fn entry(token: Option<String>) -> Value {
        let mut entry = json!({"evidence_ref": "kyc:cus_77", "source_id": "kyc", "content": "customer cus_77 verified",
            "integrity": "verified", "freshness": "current", "satisfies": ["identity_verified"]});
        if let Some(token) = token {
            entry["attestation"] = json!(token);
        }
        entry
    }

    fn labels(issuers: &Issuers, tenant: &str, mut entry: Value) -> (String, String, Value) {
        let mut evidence = [entry.take()];
        issuers.relabel(tenant, NOW, &mut evidence);
        let [entry] = evidence;
        (
            entry["integrity"].as_str().unwrap().into(),
            entry["freshness"].as_str().unwrap().into(),
            entry["verification"]["reasons"].clone(),
        )
    }

    #[test]
    fn an_attested_entry_is_verified_and_current_with_the_signed_times() {
        let signer = Signer::new();
        let issuers = issuers(&signer);
        let mut evidence = [entry(Some(signer.sign(&claims())))];
        evidence[0]["observed_at"] = json!("2099-01-01T00:00:00Z");
        issuers.relabel("tenant_acme", NOW, &mut evidence);
        let entry = &evidence[0];
        assert_eq!(
            (entry["integrity"].as_str(), entry["freshness"].as_str()),
            (Some("verified"), Some("current"))
        );
        assert_eq!(
            entry["observed_at"], "2026-11-02T11:00:00Z",
            "the signed time replaces the caller's"
        );
        let verification = &entry["verification"];
        assert_eq!(verification["evaluated_at"], NOW);
        assert_eq!(verification["issuer"], ISS);
        assert_eq!(verification["subject"], "customer:cus_77");
        assert_eq!(verification["source_version"], "kyc@4");
        assert_eq!(verification["reasons"], json!([]));
    }

    #[test]
    fn caller_labels_never_satisfy_a_gate_on_their_own() {
        let signer = Signer::new();
        let issuers = issuers(&signer);
        let other = Signer::new();
        let with = |change: &dyn Fn(&mut Value)| {
            let mut c = claims();
            change(&mut c);
            signer.sign(&c)
        };
        let cases: Vec<(&str, Value, &str, &str, &str)> = vec![
            (
                "unattested",
                entry(None),
                "tenant_acme",
                "unknown",
                "attestation_missing",
            ),
            (
                "expired",
                entry(Some(with(&|c| c["valid_until"] = json!("2026-11-02T11:30:00Z")))),
                "tenant_acme",
                "stale",
                "expired",
            ),
            (
                "future-dated",
                entry(Some(with(&|c| c["observed_at"] = json!("2026-11-02T12:30:00Z")))),
                "tenant_acme",
                "unknown",
                "observed_in_future",
            ),
            (
                "over-long",
                entry(Some(with(&|c| c["valid_until"] = json!("2026-11-04T11:00:00Z")))),
                "tenant_acme",
                "unknown",
                "validity_too_long",
            ),
            (
                "unknown issuer",
                entry(Some(with(&|c| c["iss"] = json!("https://elsewhere.test")))),
                "tenant_acme",
                "unknown",
                "issuer_unknown",
            ),
            (
                "foreign key",
                entry(Some(other.sign(&claims()))),
                "tenant_acme",
                "unknown",
                "signature_invalid",
            ),
            (
                "other tenant",
                entry(Some(signer.sign(&claims()))),
                "tenant_other",
                "unknown",
                "issuer_not_for_tenant",
            ),
            (
                "tampered content",
                {
                    let mut e = entry(Some(signer.sign(&claims())));
                    e["content"] = json!("customer cus_99 verified");
                    e
                },
                "tenant_acme",
                "unknown",
                "content_mismatch",
            ),
            (
                "unsigned requirement",
                {
                    let mut e = entry(Some(signer.sign(&claims())));
                    e["satisfies"] = json!(["identity_verified", "order_lookup"]);
                    e
                },
                "tenant_acme",
                "unknown",
                "requirement_not_attested",
            ),
            (
                "requirement the issuer may not satisfy",
                entry(Some(with(&|c| c["satisfies"] = json!(["order_lookup"])))),
                "tenant_acme",
                "unknown",
                "requirement_not_attested",
            ),
        ];
        for (name, entry, tenant, freshness, reason) in cases {
            let (integrity, got_freshness, reasons) = labels(&issuers, tenant, entry);
            let failed_integrity = integrity != "verified";
            let failed_freshness = got_freshness != "current";
            assert!(
                failed_integrity || failed_freshness,
                "{name}: still verified and current"
            );
            assert_eq!(got_freshness, freshness, "{name}");
            assert!(
                reasons.as_array().unwrap().contains(&json!(reason)),
                "{name}: {reasons}"
            );
        }
    }

    #[test]
    fn issuer_configuration_is_checked() {
        let signer = Signer::new();
        let good = EvidenceIssuerConfig {
            issuer: ISS.into(),
            tenants: vec!["t".into()],
            satisfies: vec!["x".into()],
            max_validity_seconds: 60,
            algorithm: "EdDSA".into(),
            jwks: signer.jwks(),
        };
        assert!(Issuers::new(std::slice::from_ref(&good)).is_ok());
        for (change, expected) in [
            (
                Box::new(|c: &mut EvidenceIssuerConfig| c.algorithm = "HS256".into()) as Box<dyn Fn(&mut _)>,
                "asymmetric",
            ),
            (
                Box::new(|c: &mut EvidenceIssuerConfig| c.jwks = "{\"keys\": []}".into()),
                "no keys",
            ),
            (
                Box::new(|c: &mut EvidenceIssuerConfig| c.satisfies.clear()),
                "must be set",
            ),
        ] {
            let mut config = good.clone();
            change(&mut config);
            let error = Issuers::new(&[config]).unwrap_err();
            assert!(error.contains(expected), "{error}");
        }
        assert!(Issuers::new(&[good.clone(), good]).unwrap_err().contains("distinct"));
    }
}
