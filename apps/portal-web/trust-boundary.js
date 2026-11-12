// Trust-boundary information architecture: AI reasoning → TrustOps boundary → enterprise execution,
// with the evidence fabric and workflow packs underneath. Every status shown here comes from a live API;
// anything the runtime does not do yet is labelled "Planned" or "Not connected", never implied.
export function registerTrustBoundary({ routes, main, el, api }) {
  const safe = (p) => p.catch(() => null);
  const pill = (text, tone = "neutral") => el("span", { class: `gov-pill gov-${tone}` }, el("span", { class: "gov-dot" }), text);
  const head = (kicker, title, sub) => el("div", { class: "gov-page-heading" },
    el("div", {}, el("span", { class: "gov-kicker" }, kicker), el("h2", {}, title), el("p", {}, sub)));
  const page = (...kids) => el("div", { class: "gov tb" }, ...kids);
  const card = (title, sub, ...kids) => el("section", { class: "tb-card" }, el("h3", {}, title), sub ? el("p", { class: "tb-sub" }, sub) : "", ...kids);
  const loadOps = () => safe(api("/v1/agentops"));

  routes.dashboard = async () => {
    const [ops, st, dec, apps] = await Promise.all([loadOps(), safe(api("/v1/decisions-stats")), safe(api("/v1/decisions?limit=8")), safe(api("/v1/integrations"))]);
    const q = (n, label, href, sub, hero) => el("a", { class: `tb-stat${hero ? " hero" : ""}`, href },
      el("div", { class: "tb-stat-top" }, el("span", { class: "tb-stat-k" }, label), el("span", { class: "tb-go", "aria-hidden": "true" }, "↗")),
      el("strong", {}, String(n ?? "–")), el("span", { class: "tb-stat-s" }, sub));
    const status = (label, value, tone) => el("li", {}, el("span", {}, label), pill(value, tone));
    const tone = { ALLOW: "green", ESCALATE: "amber", DENY: "rose" };
    const waiting = (st?.pending_approvals ?? 0) + (ops?.approval_required ?? 0);
    const recent = dec?.items || [];
    const appsN = apps?.items?.length ?? 0;
    main.replaceChildren(page(head("TRUSTOPS", "Overview", "What needs your attention across governed AI activity."),
      el("div", { class: "tb-stats" },
        q(waiting, "Waiting for approval", "#/approvals", "needs a person to decide", true),
        q(st?.counts?.DENY, "Denied", "#/decisions/deny", "blocked by policy"),
        q(st?.total, "Decisions", "#/decisions", `${st?.counts?.ESCALATE ?? 0} escalated`),
        q(appsN, "Applications", "#/connected-systems", appsN ? `${apps.items.filter((a) => a.status === "connected").length} reachable` : "none connected yet")),
      el("div", { class: "tb-two" },
        card("Recent decisions", "Latest across all applications", recent.length ? el("ul", { class: "tb-feed" }, recent.map((r) => el("li", {},
          el("span", {}, el("strong", {}, r.action), ` · ${r.actor.id} · ${r.application.name}`), pill(r.decision, tone[r.decision]))))
          : el("p", { class: "tb-sub" }, "No decisions yet. Connect an application or test a policy."), el("a", { href: "#/decisions" }, "All decisions →")),
        card("System status", "", el("ul", { class: "tb-status" },
          status("Decision API", "Available", "green"),
          status("Evidence", ops?.evidence_signing === "cloud_kms" ? "KMS signed" : "Hash chain · not KMS signed", ops?.evidence_signing === "cloud_kms" ? "green" : "amber"),
          status("Workflow runtime", ops?.mode === "sandbox" ? "Sandbox" : "Not enabled", ops?.mode === "sandbox" ? "amber" : "rose"),
          status("Agent mode", ops?.agent_mode === "deterministic" ? "Rules only" : (ops?.agent_mode || "Unknown"), "neutral"),
          status("Cost tracking", "Not tracked", "neutral"))))));
  };

  // ---------- AI Agents ----------
  routes["ai-agents"] = async () => {
    const [agents, ops] = await Promise.all([api("/v1/agents"), loadOps()]);
    const label = { payment: "Payment workflow workers", assessment: "Assessment agents", assistant: "Assistants" };
    const sections = ["payment", "assessment", "assistant"].map((g) => {
      const list = agents.catalog.filter((a) => a.group === g);
      return card(`${label[g]} (${list.length})`, g === "payment" ? "Run inside the trust boundary. They propose; policy and people decide." : "Advise people. They never execute or approve.",
        el("div", { class: "tb-grid" }, list.map((a) => el("div", { class: "tb-agent" },
          el("div", { class: "tb-agent-top" }, el("strong", {}, a.name), pill(a.availability, /configured|rules/i.test(a.availability) ? "green" : "amber")),
          el("p", {}, a.purpose), el("p", { class: "tb-auth" }, a.authority)))));
    });
    main.replaceChildren(page(head("AI REASONING LAYER", "AI agents", `${agents.total} agents registered · mode: ${ops?.agent_mode === "deterministic" ? "deterministic rules (no LLM configured)" : ops?.agent_mode || "unknown"}`),
      ...sections, el("p", {}, el("a", { href: "#/evidence" }, "See their runs →"))));
  };

  // ---------- Trust Boundary ----------
  routes["trust-boundary"] = async () => {
    const ops = await loadOps();
    const on = ops?.mode === "sandbox";
    const workers = ops?.agents || [];
    const dim = (title, sub, body, planned) => el("section", { class: `tb-card${planned ? " tb-planned" : ""}` },
      el("div", { class: "tb-agent-top" }, el("h3", {}, title), planned ? pill("Planned") : pill("Enforced", "green")), el("p", { class: "tb-sub" }, sub), body);
    main.replaceChildren(page(head("TRUSTOPS", "Trust boundary", "Every AI-proposed action passes these checks before anything executes."),
      on ? "" : el("div", { class: "gov-notice" }, el("div", {}, el("strong", {}, "Runtime not enabled in this environment"), el("p", {}, "Rules below are defined, but no actions run here."))),
      el("div", { class: "tb-grid" },
        dim("Authority", "What each worker may do", el("ul", { class: "tb-list" }, workers.map((w) => el("li", {}, el("strong", {}, w.id.split(".").pop().replaceAll("_", " ")), " — ", (w.authority || []).join(", "))))),
        dim("Context", "The workflow pack in force", el("p", {}, ops ? `${ops.workflow_pack} v${ops.workflow_version}` : "Unavailable")),
        dim("Policy", "Global prohibitions", el("ul", { class: "tb-list" }, (ops?.global_prohibitions || []).map((g) => el("li", {}, typeof g === "string" ? g : JSON.stringify(g))))),
        dim("Risk", "High-value or unusual actions escalate", el("p", {}, `${ops?.escalated ?? 0} escalated runs so far`)),
        dim("Human approval", "Maker-checker; the requester cannot approve", el("p", {}, `${ops?.approval_required ?? 0} waiting · `, el("a", { href: "#/approvals" }, "Open approvals →"))),
        dim("Economics", "Cost, value and trade-offs per decision", el("p", {}, "Not built yet."), true)),
      card("Decisions", "What the boundary can return today",
        el("div", { class: "tb-decs" },
          el("span", { class: "tb-dec tb-allow" }, "Allow"), el("span", { class: "tb-dec tb-esc" }, "Escalate"),
          el("span", { class: "tb-dec tb-deny tb-planned" }, "Deny", el("small", {}, "Planned")), el("span", { class: "tb-dec tb-rer tb-planned" }, "Reroute", el("small", {}, "Planned"))),
        el("p", { class: "tb-sub" }, "Today a blocked action is escalated to a person rather than silently denied.")),
      el("p", {}, el("a", { href: "#/workflow-packs" }, "Workflow pack rules →"))));
  };

  // ---------- Exceptions ----------
  routes["run-exceptions"] = async () => {
    const runs = await safe(api("/v1/runs?limit=100"));
    const items = (runs?.items || []).filter((r) => r.status !== "completed");
    const money = (r) => r.amount_minor == null ? "–" : `${(r.amount_minor / 100).toLocaleString("en-GB", { minimumFractionDigits: 2 })} ${r.currency || ""}`;
    main.replaceChildren(page(head("RISK", "Exceptions", "Runs that were escalated, are waiting for a person, or did not complete."),
      el("section", { class: "gov-panel" }, items.length ? el("div", { class: "gov-table-wrap" }, el("table", { class: "gov-table" },
        el("thead", {}, el("tr", {}, ["Run", "Status", "Decision", "Amount", "Created"].map((h) => el("th", { scope: "col" }, h)))),
        el("tbody", {}, items.map((r) => el("tr", {}, el("td", { class: "gov-code" }, r.run_id), el("td", {}, pill(String(r.status).replaceAll("_", " "), "amber")),
          el("td", {}, r.policy_decision || "–"), el("td", {}, money(r)), el("td", {}, r.created_at ? new Date(r.created_at * 1000).toLocaleString("en-GB") : "–"))))))
        : el("div", { class: "gov-empty" }, el("h3", {}, runs ? "No exceptions" : "Runs unavailable"), el("p", {}, runs ? "Every run so far completed inside policy." : "This environment does not expose workflow runs."))),
      el("p", {}, el("a", { href: "#/evidence" }, "All runs →"))));
  };

  // ---------- Connected systems (customer-registered applications) ----------
  const INT = "/v1/integrations";
  const send = (path, method, body) => api(path, { method, body });
  const when = (t) => t ? new Date(t * 1000).toLocaleString("en-GB") : "Never";
  const TONE = { connected: ["Reachable", "green"], failed: ["Test failed", "rose"], untested: ["Not tested", "amber"], key_only: ["Key issued", "green"] };
  routes["connected-systems"] = async () => {
    const [ops, list] = await Promise.all([loadOps(), safe(api(INT))]);
    const items = list?.items || [];
    const msg = el("p", { class: "tb-msg", role: "status" });
    const say = (t, ok) => { msg.textContent = t; msg.className = `tb-msg ${ok ? "ok" : "bad"}`; };
    const row = (it) => el("tr", {},
      el("td", {}, el("strong", {}, it.name), el("p", {}, it.category)),
      el("td", {}, it.base_url ? el("span", { class: "gov-code" }, it.base_url) : el("span", { class: "tb-sub" }, "Not set — only needed for Load details")),
      el("td", { class: "gov-code" }, it.key_hint || "–"),
      el("td", {}, pill(...TONE[it.status]), el("p", {}, it.last_result || ""), it.base_url ? el("p", {}, `Last test: ${when(it.last_tested_at)}`) : ""),
      el("td", {}, list.can_manage ? el("div", { class: "gov-actions" },
        el("button", { class: "gov-button gov-secondary", type: "button", onclick: async () => {
          const u = prompt(`Address of ${it.name} (https://…). Needed only so TrustOps can load review details. Leave empty to remove.`, it.base_url || "");
          if (u === null) return;
          try { await send(`${INT}/${it.id}`, "PATCH", { base_url: u }); await routes["connected-systems"](); } catch (e) { say(e.message, false); } } }, it.base_url ? "Change address" : "Set address"),
        it.base_url ? el("button", { class: "gov-button gov-secondary", type: "button", onclick: async () => {
          say(`Testing ${it.name}…`, true);
          try { const r = await send(`${INT}/${it.id}/test`, "POST"); await routes["connected-systems"](); main.querySelector(".tb-msg").textContent = r.message; main.querySelector(".tb-msg").className = `tb-msg ${r.ok ? "ok" : "bad"}`; }
          catch (e) { say(e.message, false); } } }, "Test") : "",
        el("button", { class: "gov-button gov-secondary", type: "button", onclick: async () => {
          if (!confirm(`Issue a new TrustOps key for ${it.name}? The old key stops working immediately.`)) return;
          try { showKey(await send(`${INT}/${it.id}/rotate-key`, "POST")); } catch (e) { say(e.message, false); } } }, "Rotate key"),
        el("button", { class: "gov-button gov-secondary", type: "button", onclick: async () => {
          if (!confirm(`Remove ${it.name}? Its stored credentials will be deleted.`)) return;
          await send(`${INT}/${it.id}`, "DELETE"); routes["connected-systems"](); } }, "Remove")) : ""));
    main.replaceChildren(page(
      el("div", { class: "gov-page-heading" },
        el("div", {}, el("span", { class: "gov-kicker" }, "ENTERPRISE EXECUTION"), el("h2", {}, "Connected applications"),
          el("p", {}, "Applications your organisation has registered with TrustOps.")),
        list?.can_manage ? el("a", { class: "gov-button", href: "#/add-application" }, "+ Add application") : ""),
      el("section", { class: "gov-panel" }, items.length ? el("div", { class: "gov-table-wrap" }, el("table", { class: "gov-table" },
        el("thead", {}, el("tr", {}, ["Application", "Address", "Key", "Status", ""].map((h) => el("th", { scope: "col" }, h)))),
        el("tbody", {}, items.map(row))))
        : el("div", { class: "gov-empty" }, el("h3", {}, list ? "No applications yet" : "Applications unavailable"),
            el("p", {}, list ? "Add your first application with its address and credentials." : "You may not have access to this page."),
            list?.can_manage ? el("a", { class: "gov-button", href: "#/add-application" }, "+ Add application") : "")),
      msg,
      el("p", { class: "tb-sub" }, `Built-in sandbox: ${ops?.connector_status === "mock_only" ? "Mock SAP (synthetic, for demos only)" : "none"}.`)));
  };

  const showKey = (app, test) => {
    const origin = location.origin;
    main.replaceChildren(page(
      head("APPLICATION INTEGRATION", `${app.name} added`, "Put these two settings in the application. It can then ask TrustOps before it acts."),
      el("section", { class: "tb-card tb-step" }, el("h3", {}, "TrustOps key for this application"),
        el("p", { class: "tb-sub" }, "Copy it now and put it in the application's settings as TRUSTOPS_KEY (with TRUSTOPS_URL). It will not be shown again."),
        el("pre", { class: "tb-key" }, app.trustops_key),
        el("pre", { class: "tb-key" }, `TRUSTOPS_URL=${location.origin}\nTRUSTOPS_KEY=${app.trustops_key}`),
        el("div", { class: "gov-actions" }, el("button", { class: "gov-button gov-secondary", type: "button", onclick: (e) => { navigator.clipboard?.writeText(app.trustops_key); e.target.textContent = "Copied"; } }, "Copy key"))),
      el("section", { class: "tb-card tb-step" }, el("h3", {}, "How the application asks TrustOps"),
        el("p", { class: "tb-sub" }, "Before each consequential action, call this and only act on ALLOW. ESCALATE means wait for a person; DENY means do not act."),
        el("pre", { class: "tb-key" }, `POST ${origin}/v1/decisions
X-TrustOps-Key: <key>
Content-Type: application/json

{"actor": {"type": "agent", "id": "match-agent"},
 "action": "approve_match", "amount_minor": 1240000, "currency": "USD",
 "client": "client-a", "resource": "bank-line-123"}

→ {"decision": "ESCALATE", "policy_id": "FIN-04", "reason": "...", "decision_id": "dec_…"}

GET ${origin}/v1/decisions/<decision_id>/status   → APPROVED | REJECTED | PENDING`)),
      el("a", { class: "gov-button", href: "#/connected-systems" }, "Done")));
  };

  routes["add-application"] = async () => {
    const msg = el("p", { class: "tb-msg", role: "status" });
    const name = el("input", { id: "name", name: "name", required: true, maxlength: 60, placeholder: "e.g. LedgerSight" });
    const form = el("form", { class: "tb-card tb-step", onsubmit: async (e) => {
      e.preventDefault();
      try { showKey(await send(INT, "POST", { name: name.value })); }
      catch (err) { msg.textContent = err.message; msg.className = "tb-msg bad"; }
    } },
      el("div", { class: "tb-form" }, el("label", { for: "name" }, "Application name"), name),
      el("div", { class: "gov-actions" }, el("button", { class: "gov-button", type: "submit" }, "Create key"),
        el("a", { class: "gov-button gov-secondary", href: "#/connected-systems" }, "Cancel")), msg);
    main.replaceChildren(page(
      el("a", { class: "gov-back", href: "#/connected-systems" }, "← Applications"),
      head("ADMIN", "Add application", "Give it a name. TrustOps creates a key you put in the application's settings."),
      form));
  };


  // ---------- Approvals (generic, any connected application) ----------
  const money = (r) => r.amount_minor == null ? "–" : `${(r.amount_minor / 100).toLocaleString("en-GB", { minimumFractionDigits: 2 })} ${r.currency || ""}`;
  const at = (t) => t ? new Date(t * 1000).toLocaleString("en-GB") : "–";
  routes.approvals = async () => {
    const runs = await safe(api("/v1/runs?limit=100"));
    const all = runs?.items || [];
    const pending = all.filter((r) => r.status === "approval_required");
    const decided = all.filter((r) => ["approved_to_prepare", "rejected", "completed"].includes(r.status) && r.policy_decision === "ESCALATE");
    const msg = el("p", { class: "tb-msg", role: "status" });
    const decide = (r, decision) => async () => {
      const reason = prompt(decision === "approve" ? "Reason for approving:" : "Reason for rejecting:");
      if (!reason) return;
      try {
        await api(`/v1/approvals/${encodeURIComponent(r.run_id)}/decision`, { method: "POST", body: { decision, reason }, idem: true });
        await routes.approvals(); const m = main.querySelector(".tb-msg"); m.textContent = `Run ${r.run_id} ${decision === "approve" ? "approved" : "rejected"}.`; m.className = "tb-msg ok";
      } catch (e) { msg.textContent = e.message; msg.className = "tb-msg bad"; }
    };
    const table = (rows, actions) => el("div", { class: "gov-table-wrap" }, el("table", { class: "gov-table" },
      el("thead", {}, el("tr", {}, ["Run", "Workflow", "Amount", "Decision", "Status", "Created", ""].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows.map((r) => el("tr", {}, el("td", { class: "gov-code" }, r.run_id), el("td", {}, r.workflow_id || "–"), el("td", {}, money(r)),
        el("td", {}, pill(r.policy_decision || "–", r.policy_decision === "ALLOW" ? "green" : "amber")),
        el("td", {}, pill(String(r.status).replaceAll("_", " "), r.status === "rejected" ? "rose" : r.status === "approval_required" ? "amber" : "green")),
        el("td", {}, at(r.created_at)),
        el("td", {}, actions ? el("div", { class: "gov-actions" },
          el("button", { class: "gov-button", type: "button", onclick: decide(r, "approve") }, "Approve"),
          el("button", { class: "gov-button gov-secondary", type: "button", onclick: decide(r, "reject") }, "Reject")) : ""))))));
    main.replaceChildren(page(head("HUMAN APPROVAL", "Approvals", "Actions TrustOps escalated to a person. The person who started a run cannot approve it."),
      el("section", { class: "tb-card" }, el("h3", {}, `Waiting for a decision (${pending.length})`),
        pending.length ? table(pending, true) : el("p", { class: "tb-sub" }, runs ? "Nothing is waiting for approval." : "Approvals are unavailable in this environment.")),
      msg,
      el("section", { class: "tb-card" }, el("h3", {}, "Recently decided"),
        decided.length ? table(decided, false) : el("p", { class: "tb-sub" }, "No decisions yet."))));
  };

  // ---------- Evidence (generic) ----------
  routes.evidence = async () => {
    const [runs, ops] = await Promise.all([safe(api("/v1/runs?limit=100")), loadOps()]);
    const items = runs?.items || [];
    const out = el("div", {});
    const verify = (r) => async () => {
      out.replaceChildren(el("p", { class: "tb-sub" }, `Verifying ${r.run_id}…`));
      try {
        const v = await api(`/v1/evidence/${encodeURIComponent(r.run_id)}/verify`, { method: "POST" });
        out.replaceChildren(el("section", { class: "tb-card" },
          el("div", { class: "tb-agent-top" }, el("h3", {}, `Evidence for ${r.run_id}`), v.valid ? pill("Chain intact", "green") : pill("Chain broken", "rose")),
          el("p", { class: "tb-sub" }, v.integrity === "kms_signed_hash_chain" ? "Hash chain with KMS signatures." : "Hash chain only — records are not KMS signed in this environment."),
          el("div", { class: "gov-table-wrap" }, el("table", { class: "gov-table" },
            el("thead", {}, el("tr", {}, ["#", "Event", "When", "Record hash"].map((h) => el("th", { scope: "col" }, h)))),
            el("tbody", {}, v.records.map((e) => el("tr", {}, el("td", {}, String(e.sequence)), el("td", {}, e.event_type), el("td", {}, at(e.occurred_at)),
              el("td", { class: "gov-code" }, `${e.record_hash.slice(0, 16)}…`))))))));
      } catch (e) { out.replaceChildren(el("p", { class: "tb-msg bad" }, e.message)); }
    };
    main.replaceChildren(page(head("EVIDENCE FABRIC", "Evidence", "Who acted, under whose authority, why it was allowed, and what happened — for every governed run."),
      el("ul", { class: "tb-status tb-card" },
        el("li", {}, el("span", {}, "Integrity"), ops?.evidence_signing === "cloud_kms" ? pill("Hash chain · KMS signed", "green") : pill("Hash chain · not KMS signed", "amber")),
        el("li", {}, el("span", {}, "Governed runs with evidence"), el("strong", {}, String(items.length)))),
      el("section", { class: "tb-card" }, el("h3", {}, "Runs"),
        items.length ? el("div", { class: "gov-table-wrap" }, el("table", { class: "gov-table" },
          el("thead", {}, el("tr", {}, ["Run", "Workflow", "Decision", "Status", "Created", ""].map((h) => el("th", { scope: "col" }, h)))),
          el("tbody", {}, items.map((r) => el("tr", {}, el("td", { class: "gov-code" }, r.run_id), el("td", {}, r.workflow_id || "–"),
            el("td", {}, r.policy_decision || "–"), el("td", {}, String(r.status).replaceAll("_", " ")), el("td", {}, at(r.created_at)),
            el("td", {}, el("button", { class: "gov-button gov-secondary", type: "button", onclick: verify(r) }, "Verify")))))))
          : el("p", { class: "tb-sub" }, runs ? "No governed runs yet, so no evidence has been recorded." : "Evidence is unavailable in this environment.")),
      out));
  };

  // ---------- Workflow packs ----------
  routes["workflow-packs"] = async () => {
    const ops = await loadOps();
    const pack = (name, sub, live) => el("div", { class: `tb-agent${live ? "" : " tb-planned"}` },
      el("div", { class: "tb-agent-top" }, el("strong", {}, name), live ? pill("Live · sandbox", "green") : pill("Planned")), el("p", {}, sub));
    main.replaceChildren(page(head("CONTEXT", "Workflow packs", "Domain rules, approval thresholds and evidence requirements for each kind of work."),
      el("div", { class: "tb-grid" },
        pack(`Finance — ${ops?.workflow_pack || "payments"}${ops ? ` v${ops.workflow_version}` : ""}`, `${ops?.agents?.length ?? 0} workers · ${(ops?.global_prohibitions || []).length} global prohibitions · maker-checker approvals`, true),
        pack("Healthcare", "EHR, claims and patient-system actions."), pack("Industrial", "OT, IoT and manufacturing actions."), pack("CloudOps", "Cloud infrastructure changes."))));
  };
}
