// Agent Failure Lab: plays back lab/story.js, recorded from a real contextosd by
// examples/failure-lab/record.py. Every amount, answer and audit entry shown here
// comes from that recording; the words around them are in words.js.
(function () {
  "use strict";
  const STORY = window.LAB_STORY;
  const WORDS = window.LAB_WORDS;
  const REPO = "https://github.com/contextosai/ContextOS";
  const BY_ID = Object.fromEntries(WORDS.scenarios.map((s) => [s.id, s]));

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const inr = (minor) => "INR " + (minor / 100).toLocaleString("en-IN");
  const json = (value) => esc(JSON.stringify(value, null, 2));

  let state = { id: null, index: 0 };

  const words = () => BY_ID[state.id];
  const recorded = (w) => STORY.scenarios[(w || words()).key];
  const steps = () => recorded().steps;
  const finished = () => state.index >= steps().length;
  // The step whose state is on screen: the current one, or the last once the story ends.
  const shown = () => steps()[Math.min(state.index, steps().length - 1)];
  const history = () => steps().slice(0, Math.min(state.index + 1, steps().length));
  // Baselines first, the gateway last; the last baseline is the strongest one.
  const order = (rec) => rec.worlds.filter((w) => w !== "gated").concat("gated");
  const best = (rec) => order(rec)[order(rec).length - 2];
  const last = (rec) => rec.steps[rec.steps.length - 1];

  // The refund a step tries to make, from the recorded request.
  function attempted(step) {
    const body = step.request.body;
    if (step.kind === "refund") return body.args;
    if (step.kind === "admit") {
      const context = body.request.input.context;
      return { order_id: context.order_id, amount_minor: context.refund_amount * 100 };
    }
    return null;
  }

  function reason(codes) {
    const code = (codes || []).find((c) => WORDS.refused[c]);
    return code ? WORDS.refused[code] : (codes || []).join(", ");
  }

  // What the gateway did with a step, as a tile class and a few words.
  function gatedOutcome(step) {
    const s = step.summary;
    const codes = s.reason_codes || [];
    if (s.status === "completed") return { cls: "ok", text: "Sent and paid" };
    if (codes.includes("approval_required")) return { cls: "held", text: "Not sent: waiting for approval" };
    if (s.status === "paused" && !codes.length) return { cls: "held", text: "Held: did it pay? Unknown" };
    if (step.kind === "admit") return { cls: "refused", text: "Run not admitted: " + reason(codes) };
    return { cls: "refused", text: "Not sent: " + reason(codes) };
  }

  function baselineOutcome(step, world) {
    const side = step.worlds[world];
    const a = side.attempt;
    const entry = side.ledger.find((e) => e.refund_id === a.refund_id);
    switch (a.outcome) {
      case "paid":
        return entry.excess_minor > 0 ? { cls: "loss", text: words().lossTile } : { cls: "ok", text: "Paid" };
      case "paid_no_answer": return { cls: "held", text: "Paid, but no answer came back" };
      case "deduplicated": return { cls: "lost", text: "Key recognised: not paid again" };
      case "refused_by_provider": return { cls: "lost", text: "Refused by the provider: more than is left of the payment" };
      case "waiting_for_approval": return { cls: "refused", text: "Stopped by the check: waiting for a person" };
      default: return { cls: "lost", text: a.outcome };
    }
  }

  // One tile per attempt to move money, in the order the agent made them.
  function tiles(world) {
    const out = [];
    for (const step of history()) {
      const a = attempted(step);
      if (world === "gated") {
        if (step.kind === "reconcile") {
          const held = out.find((t) => t.cls === "held");
          if (held) Object.assign(held, step.summary.outcome === "confirmed"
            ? { cls: "ok", text: "Paid: on-call confirmed it" }
            : { cls: "lost", text: "Not paid: on-call proved it" });
        }
        if (step.kind === "approve") {
          const asked = out.find((t) => t.request === step.request.body.approval_request_id);
          if (asked) Object.assign(asked, { cls: "lost", text: "Approved: the agent may send it again" });
        }
        if (a) out.push({ ...gatedOutcome(step), ...a, request: (step.response.body.report || {}).approval_request_id });
      } else if (step.worlds[world].attempt) {
        out.push({ ...baselineOutcome(step, world), ...a });
      }
    }
    if (!out.length) return '<li class="tile empty">No attempts yet.</li>';
    return out.map((t, i) => `<li class="tile tile-${t.cls}"><span class="n">Attempt ${i + 1} <span class="mono">${esc(t.order_id)}</span></span>
      <b class="num">${inr(t.amount_minor)}</b><span>${esc(t.text)}</span></li>`).join("");
  }

  // What the caller got back at the step on screen.
  function answer(step, world) {
    if (world !== "gated") {
      const a = step.worlds[world].attempt;
      if (!a) return { label: "At this step", html: '<span class="chip muted">Nothing happens here</span>' };
      const chip = { paid: ["ok", "Success"], paid_no_answer: ["held", "No answer"], deduplicated: ["ok", "Success"],
        refused_by_provider: ["refused", "Refused"], waiting_for_approval: ["refused", "Waiting"] }[a.outcome];
      const text = {
        paid: `refund ${a.refund_id} succeeded`, paid_no_answer: "connection closed, no answer",
        deduplicated: `refund ${a.refund_id} succeeded (returned for the same key)`,
        refused_by_provider: "amount exceeds the payment's refundable balance",
        waiting_for_approval: "amount is above the approval line: ask a person",
      }[a.outcome];
      return { label: "What the agent's code got back", html: `<span class="chip ${chip[0]}">${chip[1]}</span><q>${esc(text)}</q>` };
    }
    const s = step.summary;
    if (step.actor === "reviewer") {
      return { label: "What the reviewer got back", html: `<span class="chip ok">Approved</span><q>${esc(JSON.stringify(step.response.body))}</q>` };
    }
    if (step.actor === "operator") {
      const text = s.outcome ? `${s.status}: ${s.outcome}` : s.status;
      return { label: "What on-call got back", html: `<span class="chip ok">${esc(s.outcome === "confirmed" ? "Confirmed" : "Done")}</span><q>${esc(text)}</q>` };
    }
    const o = gatedOutcome(step);
    const chip = { ok: "Sent once", held: s.reason_codes ? "Paused" : "Held", refused: "Refused" }[o.cls];
    const text = s.output && s.output.refund_id ? `refund ${s.output.refund_id} ${s.output.status}`
      : `${s.error || s.status}${s.reason_codes ? " [" + s.reason_codes.join(", ") + "]" : ""}`;
    return { label: step.actor === "application" ? "What the application got back" : "What the agent's code got back",
      html: `<span class="chip ${o.cls}">${chip}</span><q>${esc(text)}</q>` };
  }

  function verdict(step, world) {
    const side = step.worlds[world];
    const held = side.balance ? side.balance.held : 0;
    const a = side.attempt;
    if (side.excess > 0) return `<span class="tone-loss">${inr(side.excess)} ${esc(words().excess)}</span>`;
    if (held) return `<span class="tone-held">${inr(held)} held until someone checks</span>`;
    if (a && a.outcome === "paid_no_answer") return '<span class="tone-held">Paid, but the agent was told it failed</span>';
    if (side.paid > 0) return '<span class="tone-ok">All of it authorised</span>';
    return '<span class="tone-muted">Nothing paid</span>';
  }

  function world(step, name) {
    const side = step.worlds[name];
    const w = WORDS.worlds[name];
    const said = answer(step, name);
    const b = side.balance;
    const labels = words().balance;
    const balance = b && labels ? `<p class="legend">${esc(labels[0])}: <span><b>${inr(b.committed)}</b> ${esc(labels[1])}</span>
      <span><b>${inr(b.held)}</b> ${esc(labels[2])}</span> <span><b>${inr(b.available)}</b> ${esc(labels[3])}</span></p>` : "";
    const rows = side.ledger.map((e) => `<li class="${e.excess_minor > 0 ? "excess" : ""}"><span>${esc(e.refund_id)} · ${esc(e.order_id)}</span>
      <span class="leader"></span><span class="num">${inr(e.amount_minor)}</span></li>`).join("") || '<li class="empty">No refunds.</li>';
    const calls = `${side.provider_calls} ${side.provider_calls === 1 ? "call" : "calls"} reached it`;
    return `<article class="world${side.excess > 0 ? " is-loss" : ""}${name === "gated" ? " is-gated" : ""}">
      <header><h3>${esc(w.name)}</h3><p class="path">${esc(w.path)}</p></header>
      <div class="figure">
        <span class="label">Paid out by the provider</span>
        <span class="amount">${inr(side.paid)}</span>
        <span class="verdict">${verdict(step, name)}</span>
      </div>
      <ol class="tiles" aria-label="Attempts to refund">${tiles(name)}</ol>
      ${balance}
      <div class="saw"><span class="label">${esc(said.label)}</span><div>${said.html}</div></div>
      <details class="ledger"><summary>Provider's ledger: ${calls}</summary><ol>${rows}</ol></details>
    </article>`;
  }

  // One line per audit entry, from its recorded payload.
  function describe(entry) {
    const p = entry.payload || {};
    switch (entry.kind) {
      case "authorization_decision":
        return p.verdict === "allow" ? "Checked the call against policy, the agent's authority and the task: allowed"
          : `Checked the call against policy, the agent's authority and the task: ${p.verdict} (${(p.reason_codes || []).join(", ")})`;
      case "effect_observation":
        if (p.outcome === "unknown" || p.finality === "provisional") return "Recorded the provider's outcome as unknown: no answer arrived";
        if ((p.evidence_ref || {}).artifact_type === "dispatch_withheld") return "Recorded that the refund was not sent";
        return `Recorded the provider's answer: ${p.outcome || "observed"}`;
      case "effect_reconciliation":
        return `On-call (${p.principal_id}) recorded the refund as ${String(p.outcome).replace("_", " ")}, citing the provider ledger export`;
      case "shared_guarantee_reserved":
        return `Reserved ${inr(p.amount)} against the limit of ${inr(p.binding.limit)} before sending`;
      case "approval_redeemed":
        return `Redeemed the approval given by ${(p.approvers || []).join(", ")} for this exact action`;
      case "circuit_breaker_tripped":
        return `Circuit breaker ${p.breaker_id} tripped: ${p.estimate} refunds from ${p.target} within ${p.window_seconds / 60} minutes`;
      case "revocation":
        return `Revoked ${p.kind} ${p.target}, by ${p.operator}`;
      case "revocation_restored":
        return `Restored ${p.kind} ${p.target}, by ${p.operator}: ${p.reason}`;
      case "revocation_refusal":
        return p.stage === "admission" ? `Refused a new run of ${p.agent_id}: the ${p.revoked_kind} was revoked by ${p.revoked_by}`
          : `Refused the call: the ${p.revoked_kind} was revoked by ${p.revoked_by}`;
      default:
        return WORDS.kinds[entry.kind] || entry.kind.replace(/_/g, " ");
    }
  }

  function renderMenu() {
    $("menu-list").innerHTML = WORDS.scenarios.map((w, i) => {
      const end = last(recorded(w)).worlds;
      const base = end[best(recorded(w))];
      return `<li><button class="choice" data-scenario="${w.id}" aria-pressed="${w.id === state.id}">
        <span class="n">${i + 1}</span>
        <strong>${esc(w.menu[0])}</strong>
        <span class="what">${esc(w.menu[1])}</span>
        <span class="result"><span class="tone-loss">Without a gateway: <b class="num">${inr(base.excess)}</b> ${esc(w.excess)}</span>
          <span class="tone-ok">Behind ContextOS: <b class="num">${inr(end.gated.excess)}</b></span></span>
      </button></li>`;
    }).join("");
  }

  function renderStage() {
    const w = words();
    const all = steps();
    $("rail").innerHTML = all.map((s, i) => {
      const attr = i === state.index ? ' aria-current="step"' : "";
      return `<li class="${i < state.index ? "done" : ""}"${attr}>${esc(w.steps[s.step].rail)}</li>`;
    }).join("") + `<li${finished() ? ' aria-current="step"' : ""}>Result</li>`;
    if (finished()) {
      $("prompt").innerHTML = `<h2 id="stage-title" tabindex="-1">${esc(w.menu[0])}: the result</h2>
        <p class="aside">${esc(w.rightful)}</p>
        <div class="actions"><button data-restart>Play it again</button></div>`;
      return;
    }
    const t = w.steps[shown().step];
    $("prompt").innerHTML = `
      <p class="aside">${esc(w.rightful)}</p>
      <h2 id="stage-title" tabindex="-1">${esc(t.title)}</h2>
      <p>${esc(t.text)}</p>
      <p class="with"><strong>Behind ContextOS:</strong> ${esc(t.gated)}</p>
      <div class="actions">
        <button class="primary" data-next>${esc(t.next)}</button>
        ${state.index > 0 ? "<button data-restart>Start over</button>" : ""}
      </div>`;
  }

  function renderWorlds() {
    const rec = recorded();
    const names = order(rec);
    $("worlds").className = "worlds worlds-" + names.length;
    $("worlds").innerHTML = names.map((name) => world(shown(), name)).join("");
  }

  function renderRecord() {
    const rec = recorded();
    const step = shown();
    const bySequence = Object.fromEntries(rec.receipt.entries.entries.map((e) => [e.sequence, e]));
    const entries = step.audit.map((n) => bySequence[n]).map((e) => `<li><span class="seq">#${e.sequence}</span>
      <span class="what">${esc(describe(e))}<span class="kind">${esc(e.kind)}</span></span>
      <span class="hash" title="${esc(e.record_hash)}">${esc(e.record_hash.slice(7, 15))}</span></li>`).join("");
    const who = { agent: "agent's", operator: "on-call engineer's", reviewer: "reviewer's", application: "application's" }[step.actor];
    const none = step.actor === "reviewer"
      ? "No new entries: the approval service is outside the gateway. The gateway records the approval when it is redeemed."
      : "No new entries at this step.";
    const to = step.request.service ? ` (${step.request.service})` : "";
    const config = Object.entries(rec.config).map(([key, value]) => `<details><summary>${esc(WORDS.config[key])}</summary>
      <pre>${typeof value === "string" ? esc(value) : json(value)}</pre></details>`).join("");
    $("record").innerHTML = `
      <h2 id="record-title">What ContextOS wrote down at this step</h2>
      <p class="aside">The ${who} request and the answer, exactly as recorded, and the audit entries the gateway added.
        Each entry carries the hash of the one before it and an Ed25519 signature.</p>
      <ol class="entries">${entries || `<li><span></span><span class="what">${none}</span><span></span></li>`}</ol>
      <details><summary>Request: ${esc(step.request.method)} ${esc(step.request.path)}${esc(to)}</summary><pre>${json(step.request.body)}</pre></details>
      ${step.request.evidence ? `<details><summary>Evidence on-call cited: provider ledger export</summary><pre>${json(step.request.evidence)}</pre></details>` : ""}
      <details><summary>Answer: HTTP ${step.response.http_status}</summary><pre>${json(step.response.body)}</pre></details>
      <h3>What was configured to get this</h3>
      ${config}`;
  }

  function button(label, onClick) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", () => onClick(b));
    return b;
  }

  function copyButton(label, text) {
    return button(label, (b) => {
      const failed = () => (b.textContent = "Copy failed: use the download");
      const done = () => { b.textContent = "Copied"; setTimeout(() => (b.textContent = label), 1500); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, failed);
      else failed();
    });
  }

  function downloadButton(name, text) {
    return button("Download " + name, () => {
      const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      const a = Object.assign(document.createElement("a"), { href: url, download: name });
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }

  function renderEnding() {
    const ending = $("ending");
    ending.hidden = !finished();
    if (!finished()) return;
    const w = words();
    const rec = recorded();
    const end = last(rec).worlds;
    const base = end[best(rec)];
    const receipt = rec.receipt;
    const others = WORDS.scenarios.filter((s) => s.id !== state.id);
    ending.innerHTML = `
      <h2>Without a gateway: ${inr(base.excess)} ${esc(w.excess)}. Behind ContextOS: ${inr(end.gated.excess)}.</h2>
      <div class="fair"><h3>Is that a fair comparison?</h3><p>${esc(w.fair)}</p></div>
      <div class="next">
        <section>
          <h3>Check the record yourself</h3>
          <p>The gateway signed every entry of this run (${receipt.entries.entries.length} entries) with its development key.
            Save both files and verify them offline with <span class="mono">ctx</span> from a
            <a href="${REPO}/releases">release archive</a>:</p>
          <pre class="cmd">ctx audit-verify --entries entries.json --keys keys.json</pre>
          <div class="actions" id="receipt-actions"></div>
        </section>
        <section>
          <h3>Replay your own refund calls</h3>
          <p>Export your agent's refund tool calls as JSON Lines and run them through a local gateway. The report says, in
            money, what it would have sent, held or refused, and what it might have blocked by mistake.</p>
          <pre class="cmd">./examples/replay-refunds/run.sh my-calls.jsonl</pre>
          <p><a href="${REPO}/tree/main/examples/replay-refunds">How to export and map your calls</a></p>
        </section>
        <section>
          <h3>Try another failure</h3>
          <div class="actions stack">${others.map((s) => `<button data-scenario="${s.id}">${esc(s.menu[0])}</button>`).join("")}</div>
        </section>
      </div>`;
    const actions = $("receipt-actions");
    const entriesText = JSON.stringify(receipt.entries);
    const keysText = JSON.stringify(receipt.keys);
    // Inside a sandboxed frame downloads are blocked; copying still works.
    if (window.self === window.top) {
      actions.append(downloadButton("entries.json", entriesText), downloadButton("keys.json", keysText));
    }
    actions.append(copyButton("Copy entries.json", entriesText), copyButton("Copy keys.json", keysText));
  }

  // Every scenario's final money, straight from the recording.
  function renderTally() {
    const rows = WORDS.scenarios.map((w) => {
      const rec = recorded(w);
      const end = last(rec).worlds;
      return { w, name: WORDS.worlds[best(rec)].name, base: end[best(rec)], gated: end.gated };
    });
    const cell = (side) => `<b class="num">${inr(side.paid)}</b> ${side.excess > 0
      ? `<span class="tone-loss">${inr(side.excess)} not authorised</span>` : '<span class="tone-ok">all authorised</span>'}`;
    const total = (k) => rows.reduce((t, r) => t + r[k].excess, 0);
    $("tally").innerHTML = `
      <h2 id="tally-title">All five, side by side</h2>
      <table class="score">
        <caption>What the provider paid by the end of each failure. "Not authorised" is money paid twice, beyond what was
          asked, without a required approval or past a configured limit. The left column is the strongest baseline recorded
          for that failure.</caption>
        <thead><tr><th scope="col">Failure</th><th scope="col">Without a gateway</th><th scope="col">Behind ContextOS</th></tr></thead>
        <tbody>${rows.map((r) => `<tr${r.w.id === state.id ? ' class="current"' : ""}>
          <th scope="row"><a href="#${r.w.id}">${esc(r.w.menu[0])}</a><span class="control">${esc(r.w.control)}</span></th>
          <td>${cell(r.base)}<span class="control">${esc(r.name)}</span></td><td>${cell(r.gated)}</td></tr>`).join("")}</tbody>
        <tfoot><tr><th scope="row">Not authorised, in all</th><td><b class="num tone-loss">${inr(total("base"))}</b></td>
          <td><b class="num tone-ok">${inr(total("gated"))}</b></td></tr></tfoot>
      </table>
      <p class="aside">None of this depends on the agent's prompt. The controls are declared on the tool, on the run and in
        the gateway's configuration; each scenario shows its own with its record, and
        <a href="${REPO}/blob/main/docs/GUIDE.md">the guide</a> covers the rest.</p>`;
  }

  function render() {
    renderMenu();
    renderTally();
    const active = Boolean(state.id);
    $("menu").classList.toggle("is-active", active);
    for (const id of ["stage", "worlds", "record"]) $(id).hidden = !active;
    if (!active) {
      $("ending").hidden = true;
      return;
    }
    renderStage();
    renderWorlds();
    renderRecord();
    renderEnding();
  }

  function start(id, scroll) {
    state = { id, index: 0 };
    try { window.history.replaceState(null, "", "#" + id); } catch (e) { /* sandboxed: keep going */ }
    render();
    if (scroll) $("stage").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  document.addEventListener("click", (event) => {
    const target = event.target.closest("button");
    if (!target) return;
    if (target.dataset.scenario) start(target.dataset.scenario, true);
    else if (target.hasAttribute("data-next")) {
      state.index += 1;
      render();
      if (finished()) $("ending").scrollIntoView({ behavior: "smooth", block: "start" });
      else $("stage-title").focus({ preventScroll: true });
    } else if (target.hasAttribute("data-restart")) {
      start(state.id, true);
    }
  });

  window.addEventListener("hashchange", () => {
    const id = location.hash.slice(1).split("/")[0];
    if (BY_ID[id] && id !== state.id) start(id, true);
  });

  $("colophon").innerHTML = `
    <p>Recorded with ${esc(STORY.recorded_with)} against a synthetic card processor that honours idempotency keys and refuses
      refunds above what is left of a payment. No real money, model or account is involved. The fact services (authority,
      controls, approvals) are development stand-ins that vouch for what they are asked.</p>
    <p>The page replays that recording; <a href="${REPO}/tree/main/examples/failure-lab">examples/failure-lab</a> re-records it,
      and CI fails if the gateway's behaviour no longer matches. <a href="${REPO}/tree/main/lab">Page source</a> ·
      <a href="${REPO}">ContextOS on GitHub</a>.</p>`;

  // "#lost-response" opens a scenario; "#lost-response/3" at its third step, "/end" at its result.
  const [initial, at] = location.hash.slice(1).split("/");
  if (BY_ID[initial]) {
    const count = STORY.scenarios[BY_ID[initial].key].steps.length;
    const index = at === "end" ? count : Math.min(Math.max((parseInt(at, 10) || 1) - 1, 0), count);
    state = { id: initial, index };
  }
  render();
})();
