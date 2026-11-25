//! Change windows: times when some capabilities' effects are refused or need an
//! approval of the exact action, such as a release freeze or out-of-hours changes.
//!
//! Each `[[guards.change_windows]]` entry names the capabilities it covers (`"*"` for
//! every capability) and is either a **freeze** between two contract timestamps
//! (`from` ≤ now < `until`) or a **recurring** window: `start`–`end` local times
//! (`HH:MM`, an `end` at or before `start` runs past midnight) on `days`, at a fixed
//! `utc_offset` (`+05:30`; time zones with daylight saving are not modelled, so state
//! the offset in force). Inside a window a call is refused (`change_window_closed`) or,
//! with `action = "approval"`, needs an approval of the exact action
//! (`change_window_approval_required`). When several windows apply, refusal wins.
//!
//! The kernel keeps no clock: the gateway decides against its own clock (the server's,
//! through the clock port), and the audit entry (`change_window_decision`) records the
//! time it decided at, so a disputed decision can be checked against it. A window with
//! `observe = true` is audited and refuses nothing.
//!
//! ```toml
//! [[guards.change_windows]]
//! name = "year-end freeze"
//! capabilities = ["*"]
//! from = "2026-12-20T00:00:00Z"
//! until = "2027-01-04T00:00:00Z"
//!
//! [[guards.change_windows]]
//! name = "deploys only in office hours"
//! capabilities = ["adp_infra.deploy"]
//! days = ["sat", "sun"]
//! start = "00:00"
//! end = "00:00"
//! action = "approval"
//! ```

use contextos_contract::validation::{elapsed_millis, is_contract_timestamp, is_within_contract_interval};
use contextos_store::{AppendLog, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admission::RunAdmission;
use crate::guard_policy::FlowGate;
use crate::information_flow::FlowVerdict;
use crate::manifest::CapabilityManifest;
use crate::{Gateway, GatewayError, Pipeline};

/// At most this many windows.
pub const MAX_WINDOWS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WindowAction {
    #[default]
    Refuse,
    Approval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// One `[[guards.change_windows]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeWindow {
    pub name: String,
    /// Capability ids, or `"*"` for every capability.
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub action: WindowAction,
    /// Audit only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub observe: bool,
    /// A freeze's first instant (contract timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// A freeze's end (exclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// A recurring window's days (of its `start`); empty: every day.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<Weekday>,
    /// A recurring window's local start, `HH:MM`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// A recurring window's local end, `HH:MM` (exclusive; at or before `start`: the
    /// next day).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    /// The fixed offset local times are in, `±HH:MM`; `+00:00` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_offset: Option<String>,
}

/// Minutes from `HH:MM`.
fn minutes(hm: &str) -> Option<i64> {
    let (h, m) = hm.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// Minutes east of UTC from `±HH:MM`, within ±14:00.
fn offset_minutes(offset: &str) -> Option<i64> {
    let (sign, rest) = match offset.as_bytes().first()? {
        b'+' => (1, &offset[1..]),
        b'-' => (-1, &offset[1..]),
        _ => return None,
    };
    let m = minutes(rest)?;
    (m <= 14 * 60).then_some(sign * m)
}

/// Whole seconds since the Unix epoch of a contract timestamp.
fn unix_seconds(at: &str) -> Option<i64> {
    elapsed_millis("1970-01-01T00:00:00Z", at).and_then(|ms| i64::try_from(ms / 1000).ok())
}

impl ChangeWindow {
    fn recurring(&self) -> bool {
        self.start.is_some() || self.end.is_some() || !self.days.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        let named = |s: &str| !s.trim().is_empty() && s.len() <= 128;
        if !named(&self.name) {
            return Err("each change window needs a name of up to 128 bytes".into());
        }
        if self.capabilities.is_empty() || self.capabilities.len() > 256 {
            return Err(format!(
                "change window {}: name 1 to 256 capabilities, or \"*\"",
                self.name
            ));
        }
        let freeze = self.from.is_some() || self.until.is_some();
        match (freeze, self.recurring()) {
            (true, false) => {
                let (Some(from), Some(until)) = (&self.from, &self.until) else {
                    return Err(format!(
                        "change window {}: a freeze needs both from and until",
                        self.name
                    ));
                };
                if !is_contract_timestamp(from)
                    || !is_contract_timestamp(until)
                    || unix_seconds(until) <= unix_seconds(from)
                {
                    return Err(format!(
                        "change window {}: from and until must be timestamps with from before until",
                        self.name
                    ));
                }
            }
            (false, true) => {
                if self.start.as_deref().and_then(minutes).is_none() || self.end.as_deref().and_then(minutes).is_none()
                {
                    return Err(format!("change window {}: start and end are HH:MM", self.name));
                }
                if self.utc_offset.as_deref().is_some_and(|o| offset_minutes(o).is_none()) {
                    return Err(format!(
                        "change window {}: utc_offset is ±HH:MM within ±14:00",
                        self.name
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "change window {}: give either from and until (a freeze) or start, end and days (recurring)",
                    self.name
                ));
            }
        }
        Ok(())
    }

    /// Whether the window covers `capability`.
    #[must_use]
    pub fn covers(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == "*" || c == capability)
    }

    /// Whether `now` (a contract timestamp) is inside the window.
    #[must_use]
    pub fn open_at(&self, now: &str) -> bool {
        if let (Some(from), Some(until)) = (&self.from, &self.until) {
            return is_within_contract_interval(now, from, until);
        }
        let (Some(start), Some(end), Some(secs)) = (
            self.start.as_deref().and_then(minutes),
            self.end.as_deref().and_then(minutes),
            unix_seconds(now),
        ) else {
            return false;
        };
        let offset = self.utc_offset.as_deref().map_or(Some(0), offset_minutes).unwrap_or(0);
        let local = secs.div_euclid(60) + offset;
        let (day, minute) = (local.div_euclid(1440), local.rem_euclid(1440));
        // 1970-01-01 was a Thursday (index 3 from Monday).
        let weekday = |d: i64| (d + 3).rem_euclid(7);
        let on = |d: i64| self.days.is_empty() || self.days.iter().any(|w| *w as i64 == weekday(d));
        if start < end {
            on(day) && minute >= start && minute < end
        } else {
            // Runs past midnight (or all day when start == end): the part after start
            // belongs to today, the part before end to the window that began yesterday.
            (on(day) && minute >= start) || (on(day - 1) && minute < end)
        }
    }
}

/// The windows `capability`'s call falls in at `now`, strongest first (enforced
/// refusals, then enforced approvals, then observed ones).
#[must_use]
pub fn applying<'a>(windows: &'a [ChangeWindow], capability: &str, now: &str) -> Vec<&'a ChangeWindow> {
    let mut hit: Vec<&ChangeWindow> = windows
        .iter()
        .filter(|w| w.covers(capability) && w.open_at(now))
        .collect();
    hit.sort_by_key(|w| (w.observe, w.action != WindowAction::Refuse));
    hit
}

/// Refuses an invalid set of windows.
pub fn validate(windows: &[ChangeWindow]) -> Result<(), String> {
    if windows.len() > MAX_WINDOWS {
        return Err(format!("at most {MAX_WINDOWS} change windows"));
    }
    let mut names = std::collections::BTreeSet::new();
    for w in windows {
        w.validate()?;
        if !names.insert(w.name.as_str()) {
            return Err(format!("change window {} is named twice", w.name));
        }
    }
    Ok(())
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The change windows' part in this call's decision. Every window the call falls
    /// in is audited (`change_window_decision`, with the time decided at); an enforced
    /// refusal stops the call, an enforced approval window composes an approval of the
    /// exact action.
    pub(crate) async fn window_guard(
        &self,
        p: &mut Pipeline<'_>,
        admission: &RunAdmission,
        manifest: &CapabilityManifest,
        operation_id: &str,
        now: &str,
    ) -> Result<FlowGate, GatewayError> {
        if self.change_windows.is_empty() {
            return Ok(FlowGate::Pass);
        }
        let hit = applying(&self.change_windows, &manifest.capability_id, now);
        let Some(strongest) = hit.first() else {
            return Ok(FlowGate::Pass);
        };
        let body = json!({"run_id": admission.run_id, "operation_id": operation_id,
            "capability_id": manifest.capability_id, "decided_at": now,
            "windows": hit.iter().map(|w| json!({"name": w.name, "action": w.action, "enforced": !w.observe})).collect::<Vec<_>>()});
        self.record(p, "change_window_decision", body, now).await?;
        if strongest.observe {
            return Ok(FlowGate::Pass);
        }
        if let Some(grant) = self
            .break_glass_for(
                &admission.tenant_id,
                &manifest.capability_id,
                crate::break_glass::Lift::ChangeWindows,
                now,
            )
            .await?
        {
            let body = json!({"run_id": admission.run_id, "operation_id": operation_id,
                "capability_id": manifest.capability_id, "grant_id": grant, "lifted": "change_windows",
                "window": strongest.name});
            self.record(p, "break_glass_used", body, now).await?;
            return Ok(FlowGate::Pass);
        }
        if strongest.action == WindowAction::Refuse {
            return Ok(FlowGate::Refuse(vec!["change_window_closed".to_owned()]));
        }
        Ok(crate::guard_policy::gate(
            admission,
            FlowVerdict::Ask,
            "change_windows",
            "approve_during_change_window",
            vec!["change_window_approval_required".to_owned()],
            "change_window_policy_unpinned",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(v: serde_json::Value) -> ChangeWindow {
        let w: ChangeWindow = serde_json::from_value(v).unwrap();
        w.validate().unwrap();
        w
    }

    #[test]
    fn a_freeze_covers_from_until_exclusive() {
        let w = window(json!({"name": "freeze", "capabilities": ["*"],
            "from": "2026-12-20T00:00:00Z", "until": "2027-01-04T00:00:00Z"}));
        assert!(!w.open_at("2026-12-19T23:59:59.999Z"));
        assert!(w.open_at("2026-12-20T00:00:00Z"));
        assert!(w.open_at("2027-01-03T23:59:59Z"));
        assert!(!w.open_at("2027-01-04T00:00:00Z"));
        assert!(w.covers("anything.at_all"));
    }

    #[test]
    fn a_recurring_window_uses_its_offset_and_days() {
        // Weekdays 18:00–08:00 India time (UTC+05:30).
        let w = window(json!({"name": "nights", "capabilities": ["adp_infra.deploy"],
            "days": ["mon", "tue", "wed", "thu", "fri"], "start": "18:00", "end": "08:00", "utc_offset": "+05:30"}));
        // 2026-11-25 is a Wednesday. 13:00Z = 18:30 IST: inside.
        assert!(w.open_at("2026-11-25T13:00:00Z"));
        // 12:00Z = 17:30 IST: outside.
        assert!(!w.open_at("2026-11-25T12:00:00Z"));
        // Thursday 01:00Z = 06:30 IST, the tail of Wednesday's window: inside.
        assert!(w.open_at("2026-11-26T01:00:00Z"));
        // Saturday 2026-11-28 20:00 IST = 14:30Z: Saturday is not listed.
        assert!(!w.open_at("2026-11-28T14:30:00Z"));
        // Saturday 06:00 IST = Friday 00:30Z: the tail of Friday's window.
        assert!(w.open_at("2026-11-28T00:30:00Z"));
        assert!(!w.covers("adp_payments.issue_refund"));
    }

    #[test]
    fn equal_start_and_end_means_the_whole_day() {
        let w = window(json!({"name": "weekend", "capabilities": ["*"], "days": ["sat", "sun"],
            "start": "00:00", "end": "00:00"}));
        assert!(w.open_at("2026-11-28T12:00:00Z")); // Saturday
        assert!(w.open_at("2026-11-29T23:59:00Z")); // Sunday
        assert!(!w.open_at("2026-11-30T00:00:00Z")); // Monday
    }

    #[test]
    fn invalid_windows_are_refused() {
        let bad = |v: serde_json::Value| serde_json::from_value::<ChangeWindow>(v).unwrap().validate().is_err();
        assert!(bad(
            json!({"name": "x", "capabilities": ["*"], "from": "2026-12-20T00:00:00Z"})
        ));
        assert!(bad(
            json!({"name": "x", "capabilities": ["*"], "from": "2027-01-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"})
        ));
        assert!(bad(
            json!({"name": "x", "capabilities": ["*"], "start": "25:00", "end": "08:00"})
        ));
        assert!(bad(
            json!({"name": "x", "capabilities": ["*"], "start": "18:00", "end": "08:00", "utc_offset": "+15:00"})
        ));
        assert!(bad(
            json!({"name": "x", "capabilities": [], "start": "18:00", "end": "08:00"})
        ));
        assert!(bad(
            json!({"name": "x", "capabilities": ["*"], "from": "2026-12-20T00:00:00Z",
            "until": "2027-01-04T00:00:00Z", "start": "18:00", "end": "08:00"})
        ));
        let twice = vec![
            window(json!({"name": "a", "capabilities": ["*"], "start": "18:00", "end": "08:00"})),
            window(json!({"name": "a", "capabilities": ["*"], "start": "09:00", "end": "10:00"})),
        ];
        assert!(validate(&twice).is_err());
    }

    #[test]
    fn refusal_outranks_approval_and_observation() {
        let windows = vec![
            window(json!({"name": "watch", "capabilities": ["*"], "observe": true, "start": "00:00", "end": "00:00"})),
            window(
                json!({"name": "ask", "capabilities": ["*"], "action": "approval", "start": "00:00", "end": "00:00"}),
            ),
            window(json!({"name": "stop", "capabilities": ["x"], "start": "00:00", "end": "00:00"})),
        ];
        let names: Vec<&str> = applying(&windows, "x", "2026-11-25T10:00:00Z")
            .iter()
            .map(|w| w.name.as_str())
            .collect();
        assert_eq!(names, ["stop", "ask", "watch"]);
    }
}
