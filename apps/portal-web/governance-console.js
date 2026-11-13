// TrustOps governance console: decisions, policies, approvals of escalations, risk, evidence and reports.
// All data comes from the TrustOps API. Nothing here is sample data.
export function registerGovernanceConsole({ routes, main, el, api }) {
  const safe = (p) => p.catch(() => null);
  const pill = (text, tone = "neutral") => el("span", { class: `gov-pill gov-${tone}` }, el("span", { class: "gov-dot" }), text);
  const TONE = { ALLOW: "green", ESCALATE: "amber", DENY: "rose", APPROVED: "green", REJECTED: "rose", PENDING: "amber" };
  const head = (kicker, title, sub, ...actions) => el("div", { class: "gov-page-heading" },
    el("div", {}, el("span", { class: "gov-kicker" }, kicker), el("h2", {}, title), el("p", {}, sub)),
    actions.length ? el("div", { class: "gov-actions" }, ...actions) : "");
  const page = (...kids) => el("div", { class: "gov tb" }, ...kids);
  const card = (title, sub, ...kids) => el("section", { class: "tb-card" }, title ? el("h3", {}, title) : "", sub ? el("p", { class: "tb-sub" }, sub) : "", ...kids);
  const at = (t) => (t ? new Date(t * 1000).toLocaleString("en-GB") : "–");
  const money = (r) => (r.amount_minor == null ? "–" : `${(r.amount_minor / 100).toLocaleString("en-GB", { minimumFractionDigits: 2 })} ${r.currency || ""}`);
  const final = (r) => (r.resolution ? (r.resolution.outcome === "approve" ? "APPROVED" : "REJECTED") : r.decision === "ESCALATE" ? "PENDING" : r.decision);
  const table = (cols, rows) => el("div", { class: "gov-table-wrap" }, el("table", { class: "gov-table" },
    el("thead", {}, el("tr", {}, cols.map((h) => el("th", { scope: "col" }, h)))), el("tbody", {}, rows)));
  const msgEl = () => el("p", { class: "tb-msg", role: "status" });
  const say = (m, text, ok) => { m.textContent = text; m.className = `tb-msg ${ok ? "ok" : "bad"}`; };
  const download = async (path, name) => {
    const r = await api(path, { raw: true });
    if (!r.ok) throw new Error("Export failed");
    const url = URL.createObjectURL(await r.blob());
    const a = el("a", { href: url, download: name }); document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };
  const decisionRow = (r) => el("tr", {},
    el("td", {}, at(r.at)),
    el("td", {}, el("strong", {}, r.application.name), r.simulated ? el("p", {}, "simulated") : ""),
    el("td", {}, `${r.actor.type}: ${r.actor.id}`),
    el("td", { class: "gov-code" }, r.action),
    el("td", {}, r.client || "–", el("p", {}, money(r))),
    el("td", {}, pill(r.decision, TONE[r.decision]), el("p", { class: "gov-code" }, r.policy_id)),
    el("td", { class: "w" }, r.reason),
    el("td", {}, pill(final(r), TONE[final(r)])));
  const DCOLS = ["Time", "Application", "Actor", "Action", "Client · amount", "Decision", "Reason", "Outcome"];

  // ---------- Decisions feed ----------
  routes.decisions = async (filter) => {
    const f = (filter || "all").toUpperCase();
    const search = el("input", { class: "tb-search", type: "search", placeholder: "Search actor, action, client…", "aria-label": "Search decisions" });
    const body = el("div", {});
    const load = async () => {
      const qs = new URLSearchParams({ limit: "300" });
      if (f !== "ALL") qs.set("decision", f);
      if (search.value.trim()) qs.set("q", search.value.trim());
      const d = await safe(api(`/v1/decisions?${qs}`));
      body.replaceChildren(!d ? el("p", { class: "tb-sub" }, "Decisions are unavailable.")
        : d.items.length ? table(DCOLS, d.items.map(decisionRow))
        : el("div", { class: "gov-empty" }, el("h3", {}, "No decisions yet"), el("p", {}, "Decisions appear when a connected application asks TrustOps before acting, or when you test a policy.")));
    };
    search.addEventListener("input", () => { clearTimeout(search.t); search.t = setTimeout(load, 250); });
    const tab = (k, label) => el("a", { class: `tb-seg${f === k ? " on" : ""}`, href: `#/decisions/${k.toLowerCase()}` }, label);
    main.replaceChildren(page(head("LIVE DECISION FEED", "Decisions", "Every Allow, Escalate and Deny across your applications, with the policy and reason."),
      el("div", { class: "tb-toolbar" }, el("div", { class: "tb-segs" }, tab("ALL", "All"), tab("ALLOW", "Allowed"), tab("ESCALATE", "Escalated"), tab("DENY", "Denied")), search),
      el("section", { class: "gov-panel" }, body)));
    await load();
  };

  // ---------- Approvals: escalated decisions + governed runs ----------
  const runsApprovals = routes.approvals;
  routes.approvals = async () => {
    const [d, me] = await Promise.all([safe(api("/v1/decisions?pending=true")), safe(api("/v1/me"))]);
    const myEmail = (me?.email || me?.sub || "").toLowerCase();
    await runsApprovals();
    const m = msgEl();
    const resolve = (r, outcome) => async () => {
      const reason = prompt(outcome === "approve" ? "Reason for approving:" : "Reason for rejecting:");
      if (!reason) return;
      try { await api(`/v1/decisions/${r.id}/resolve`, { method: "POST", body: { outcome, reason } }); await routes.approvals(); }
      catch (e) { say(m, e.message, false); }
    };
    const all = d?.items || [];
    const mineOnly = sessionStorage.getItem("ap-mine") === "1";
    const assignee = (r) => r.assignment?.to || null;
    const items = mineOnly ? all.filter((r) => assignee(r) === myEmail) : all;
    const mineCount = all.filter((r) => assignee(r) === myEmail).length;
    const tab = (label, on, val) => el("button", { type: "button", class: `gov-button${on ? "" : " gov-secondary"}`,
      onclick: () => { sessionStorage.setItem("ap-mine", val); routes.approvals(); } }, label);
    const item = (r) => el("li", { class: "ap-item" },
      el("div", { class: "ap-main" },
        el("div", { class: "ap-top" }, el("strong", {}, r.details?.title || r.action.replaceAll("_", " ")), pill(r.policy_id, "amber"), r.amount_minor != null ? el("span", { class: "ap-amt" }, money(r)) : ""),
        r.details?.summary ? el("p", {}, r.details.summary) : "",
        el("p", { class: "ap-meta" }, el("strong", {}, "Reviewer: "), assignee(r) ? (assignee(r) === myEmail ? `${assignee(r)} (you)` : assignee(r)) : "Any approver"),
        el("p", { class: "ap-meta" }, `${r.application.name} · submitted by ${r.actor.type === "agent" ? "agent " : ""}${r.actor.id}${r.client ? ` · ${r.client}` : ""} · ${at(r.at)} · ${r.reason}`),
        r.details?.link ? el("a", { href: r.details.link, target: "_blank", rel: "noopener noreferrer" }, `Open in ${r.application.name} ↗`) : ""),
      el("a", { class: "gov-button", href: `#/approval/${r.id}` }, "Review →"));
    const section = card(`Waiting for your approval (${items.length})`, "Items your applications sent to TrustOps. Open each one, check what is in it, then approve or reject. The application picks up the result.",
      el("div", { class: "gov-actions" }, tab(`All (${all.length})`, !mineOnly, "0"), tab(`Assigned to me (${mineCount})`, mineOnly, "1")),
      items.length ? el("ul", { class: "ap-list" }, items.map(item)) : el("p", { class: "tb-sub" }, mineOnly ? "Nothing is assigned to you." : "Nothing is waiting."), m);
    const root = main.querySelector(".tb");
    root?.querySelector(".gov-page-heading")?.after(section);
    const runCard = root?.querySelectorAll(".tb-card")[1];
    runCard?.querySelector("h3")?.replaceChildren(runCard.querySelector("h3").textContent.replace("Waiting for a decision", "Governed workflow runs waiting"));
  };

  // ---------- Review one escalated item ----------
  routes.approval = async (did) => {
    const [r, revs] = await Promise.all([api(`/v1/decisions/${encodeURIComponent(did)}`), safe(api("/v1/decisions-reviewers"))]);
    const ld = r.loaded_details;
    const d = { ...(r.details || {}) };
    if (ld) for (const k of ["title", "summary", "compare", "lines", "recommendation", "consequence", "link"]) if (ld[k]) d[k] = ld[k];
    if (ld?.facts?.length) d.facts = [...(d.facts || []), ...ld.facts];
    if (ld?.documents?.length) d.documents = [...(d.documents || []), ...ld.documents];
    const m = msgEl();
    const hasDetails = !!(d.facts?.length || d.lines || d.compare);
    const lm = msgEl();
    const loadBtn = el("button", { class: "gov-button", type: "button", onclick: async () => {
      loadBtn.disabled = true; say(lm, `Loading from ${r.application.name}…`, true);
      try { await api(`/v1/decisions/${r.id}/load-details`, { method: "POST" }); await routes.approval(did); }
      catch (e) { loadBtn.disabled = false; say(lm, e.message, false); } } }, `Load details from ${r.application.name}`);
    const reason = el("textarea", { id: "ap-reason", rows: "3", placeholder: "Why are you approving or rejecting this? (required)", "aria-label": "Reason" });
    const checked = el("input", { type: "checkbox", id: "ap-checked" });
    const approveBtn = el("button", { class: "gov-button", type: "button" }, "Approve");
    const sync = () => { approveBtn.disabled = !hasDetails && !checked.checked; };
    checked.addEventListener("change", sync); sync();
    const decide = (outcome) => async () => {
      if (!reason.value.trim()) { say(m, "Write a reason first.", false); reason.focus(); return; }
      try { await api(`/v1/decisions/${r.id}/resolve`, { method: "POST", body: { outcome, reason: reason.value.trim(), checked_in_app: checked.checked } }); location.hash = "#/approvals"; }
      catch (e) { say(m, e.message, false); }
    };
    approveBtn.addEventListener("click", decide("approve"));
    const pending = r.decision === "ESCALATE" && !r.resolution;
    const am = msgEl();
    const assignSel = el("select", { id: "ap-assign", "aria-label": "Reviewer", onchange: async () => {
      try { await api(`/v1/decisions/${r.id}/assign`, { method: "POST", body: { to: assignSel.value || null } }); say(am, "Reviewer updated.", true); }
      catch (e) { say(am, e.message, false); } } },
      el("option", { value: "" }, "Any approver"),
      (revs?.items || []).map((x) => el("option", { value: x.email, selected: r.assignment?.to === x.email }, `${x.email} · ${x.role}`)));
    const fact = (label, value) => el("div", { class: "rv-fact" }, el("span", {}, label), el("strong", {}, value ?? "–"));
    const norm = (v) => String(v || "").replace(/[\s,]/g, "").toLowerCase();
    const compare = d.compare ? el("section", { class: "tb-card" }, el("h3", {}, "Side by side"),
      el("p", { class: "tb-sub" }, "Fields that differ are highlighted."),
      table(["", d.compare.left_title, d.compare.right_title], d.compare.rows.map(([f, l, rr]) => {
        const diff = norm(l) !== norm(rr);
        return el("tr", { class: diff ? "rv-diff" : "" }, el("td", {}, el("strong", {}, f)), el("td", { class: "w" }, l || "—"), el("td", { class: "w" }, rr || "—", diff ? el("span", { class: "rv-flag" }, " differs") : ""));
      }))) : "";
    main.replaceChildren(page(
      el("a", { class: "gov-back", href: "#/approvals" }, "← Approvals"),
      head("REVIEW", d.title || r.action.replaceAll("_", " "), d.summary || r.reason),
      compare,
      d.recommendation || d.consequence ? el("div", { class: "tb-two" },
        d.recommendation ? el("section", { class: "tb-card rv-reco" }, el("h3", {}, "Agent recommendation"), el("p", {}, d.recommendation)) : el("div", {}),
        d.consequence ? el("section", { class: "tb-card rv-cons" }, el("h3", {}, "If you approve"), el("p", {}, d.consequence)) : el("div", {})) : "",
      d.facts?.length ? el("section", { class: "tb-card" }, el("h3", {}, "Details from the application"),
        el("div", { class: "rv-facts" }, d.facts.map((f) => fact(f.label, f.value)))) : "",
      d.lines ? el("section", { class: "tb-card" }, el("h3", {}, d.lines.title || "Line items"),
        table(d.lines.columns, d.lines.rows.map((row) => el("tr", {}, row.map((v) => el("td", { class: "w" }, v)))))) : "",
      d.documents?.length || d.link ? el("section", { class: "tb-card" }, el("h3", {}, "Documents"),
        el("ul", { class: "tb-list" }, (d.documents || []).map((x) => el("li", {}, el("a", { href: x.url, target: "_blank", rel: "noopener noreferrer" }, `${x.name} ↗`))),
          d.link ? el("li", {}, el("a", { href: d.link, target: "_blank", rel: "noopener noreferrer" }, `Open this item in ${r.application.name} ↗`)) : "")) : "",
      !hasDetails ? el("div", { class: "rv-warn" }, el("strong", {}, "The application sent no details for this item."),
        el("p", {}, `Load them from ${r.application.name} to review here. Approve stays locked until details are loaded${d.link ? " or you confirm you checked the item in the application" : ""}.`),
        el("div", { class: "gov-actions rv-load" }, loadBtn), lm) : "",
      ld ? el("p", { class: "tb-sub" }, `Details loaded from ${r.application.name} by ${ld.loaded_by} · ${at(ld.loaded_at)} · recorded in evidence`) : "",
      el("section", { class: "tb-card" }, el("h3", {}, "Request"),
        el("div", { class: "rv-facts" },
          fact("Application", r.application.name), fact("Submitted by", `${r.actor.type}: ${r.actor.id}`),
          fact("Action", r.action), fact("Client", r.client), fact("Amount", money(r)), fact("Submitted", at(r.at)),
          fact("Why it is here", `${r.policy_id} — ${r.reason}`), fact("Evidence record", `#${r.sequence} ${r.record_hash.slice(0, 12)}…`),
          pending ? "" : fact("Reviewer", r.assignment?.to || "Any approver")),
        pending ? el("div", { class: "tb-form" }, el("label", { for: "ap-assign" }, "Reviewer"), assignSel,
          el("p", { class: "tb-sub" }, r.assignment?.by ? `Assigned by ${r.assignment.by} · ${at(r.assignment.at)}` : "Any Admin or Approver can review this."), am) : ""),
      pending ? el("section", { class: "tb-card tb-step" }, el("h3", {}, "Your decision"),
        el("p", { class: "tb-sub" }, "What you saw here is recorded in the evidence chain with your decision. Approvers cannot approve items they submitted; an administrator approving their own item is recorded as a self-approval."),
        !hasDetails && d.link ? el("label", { class: "rv-check", for: "ap-checked" }, checked, ` I opened this item in ${r.application.name} and checked it`) : "",
        el("div", { class: "tb-form" }, reason),
        el("div", { class: "gov-actions" }, approveBtn,
          el("button", { class: "gov-button gov-secondary", type: "button", onclick: decide("reject") }, hasDetails ? "Reject" : "Reject — ask for details")), m)
        : el("section", { class: "tb-card" }, el("h3", {}, "Decision"),
            r.resolution ? el("div", { class: "rv-facts" }, fact("Outcome", r.resolution.outcome === "approve" ? "Approved" : "Rejected"), fact("By", r.resolution.by + (r.resolution.self_resolved ? " (self-approved by administrator)" : "")), fact("When", at(r.resolution.at)), fact("Reason", r.resolution.reason),
              fact("Based on", { details_in_trustops: "Details shown in TrustOps", checked_in_application: "Checked in the application", none: "—" }[r.resolution.basis] || "—"))
              : el("p", { class: "tb-sub" }, `${r.decision} — no person needed.`))));
  };

  // ---------- Policies ----------
  routes.policies = async () => {
    const [pol, ops] = await Promise.all([api("/v1/policies"), safe(api("/v1/agentops"))]);
    let rules = pol.rules.map((r) => ({ ...r }));
    const m = msgEl();
    const edit = pol.can_edit;
    const decSel = (r) => el("select", { disabled: !edit, onchange: (e) => { r.decision = e.target.value; } },
      ["ALLOW", "ESCALATE", "DENY"].map((d) => el("option", { value: d, selected: r.decision === d }, d)));
    const limit = (r) => el("input", { type: "number", min: "0", step: "1", value: r.min_amount_minor == null ? "" : r.min_amount_minor / 100, placeholder: "any", disabled: !edit, class: "tb-num",
      onchange: (e) => { r.min_amount_minor = e.target.value === "" ? null : Math.round(Number(e.target.value) * 100); } });
    const on = (r) => el("input", { type: "checkbox", checked: r.enabled, disabled: !edit, "aria-label": `Enable ${r.id}`, onchange: (e) => { r.enabled = e.target.checked; } });
    const rows = rules.map((r) => el("tr", {}, el("td", {}, on(r)), el("td", { class: "gov-code" }, r.id),
      el("td", { class: "w" }, el("strong", {}, r.name), el("p", {}, r.reason)),
      el("td", { class: "gov-code w" }, r.actions.join(", ")), el("td", {}, r.actor_types.length ? r.actor_types.join(", ") : "anyone"),
      el("td", {}, limit(r), el("p", {}, r.min_amount_minor == null ? "" : "applies above")), el("td", {}, decSel(r))));
    const save = el("button", { class: "gov-button", type: "button", disabled: !edit, onclick: async () => {
      try { await api("/v1/policies", { method: "PUT", body: { rules } }); say(m, "Policies saved. New decisions use them immediately.", true); }
      catch (e) { say(m, e.message, false); } } }, "Save policies");
    const reset = el("button", { class: "gov-button gov-secondary", type: "button", disabled: !edit, onclick: async () => {
      if (!confirm("Reset all rules to the Finance pack defaults?")) return; await api("/v1/policies/reset", { method: "POST" }); routes.policies(); } }, "Reset to defaults");

    // policy tester
    const tm = el("div", {});
    const fld = (id, label, attrs = {}) => [el("label", { for: id }, label), el("input", { id, ...attrs })];
    const aType = el("select", { id: "t-type" }, ["agent", "human", "service"].map((x) => el("option", {}, x)));
    const test = el("form", { class: "tb-form tb-inline", onsubmit: async (e) => {
      e.preventDefault();
      const amt = document.getElementById("t-amt").value;
      try {
        const r = await api("/v1/decisions/simulate", { method: "POST", body: { actor: { type: aType.value, id: document.getElementById("t-id").value || "test-actor" },
          action: document.getElementById("t-action").value, amount_minor: amt === "" ? null : Math.round(Number(amt) * 100), client: "policy-test" } });
        tm.replaceChildren(el("div", { class: "tb-result" }, pill(r.decision, TONE[r.decision]), el("span", { class: "gov-code" }, r.policy_id), el("span", {}, r.reason)));
      } catch (err) { tm.replaceChildren(el("p", { class: "tb-msg bad" }, err.message)); }
    } },
      el("label", { for: "t-type" }, "Actor type"), aType, ...fld("t-id", "Actor ID", { placeholder: "match-agent" }),
      ...fld("t-action", "Action", { required: true, placeholder: "approve_match", list: "t-actions" }),
      el("datalist", { id: "t-actions" }, [...new Set(rules.flatMap((r) => r.actions))].map((a) => el("option", { value: a }))),
      ...fld("t-amt", "Amount", { type: "number", min: "0", step: "0.01", placeholder: "optional" }),
      el("button", { class: "gov-button", type: "submit", disabled: !edit }, "Test decision"));

    main.replaceChildren(page(head("POLICIES & WORKFLOW PACKS", "Policies", "Rules are checked top to bottom. The first rule that matches decides. If none match, a person decides (Escalate)."),
      card(`Finance pack${ops ? ` · ${ops.workflow_pack} v${ops.workflow_version}` : ""}`, "Other packs (Healthcare, Industrial, CloudOps) are planned and not available yet."),
      el("section", { class: "gov-panel" }, table(["On", "ID", "Rule", "Actions", "Who", "Amount limit", "Decision"], rows)),
      el("div", { class: "gov-actions" }, save, reset), m,
      card("Test a decision", "Runs the rules above without any application. The result is recorded as simulated.", test, tm),
      edit ? "" : el("p", { class: "tb-sub" }, "Only a workspace administrator can change policies.")));
  };

  // ---------- Risk: what needs attention now ----------
  routes.risk = async () => {
    const [r, au] = await Promise.all([api("/v1/risk"), safe(api("/v1/authority"))]);
    const m = msgEl();
    const canEdit = au?.can_edit;
    const LV = { act: ["🔴", "Act now", "rose"], watch: ["🟠", "Watch", "amber"], normal: ["🟢", "Normal", "green"] };
    const [dot, label] = LV[r.level];
    const suspend = (w) => async () => {
      const reason = prompt(`Suspend ${w.actor_id}? Every request from it will be denied.\nReason:`, `Risk: ${w.why}`);
      if (!reason) return;
      try { await api(`/v1/authority/agents/${w.agent_id}`, { method: "PATCH", body: { status: "suspended", reason } }); await routes.risk(); }
      catch (e) { say(m, e.message, false); }
    };
    const banner = el("section", { class: `rk-banner rk-${r.level}` },
      el("div", { class: "rk-title" }, el("span", { "aria-hidden": "true" }, dot), el("strong", {}, r.level === "act" ? `Act now — ${r.reasons.length === 1 ? "1 thing needs" : `${r.reasons.length} things need`} you` : r.level === "watch" ? "Watch" : "Normal — nothing needs you")),
      r.reasons.length ? el("ul", {}, r.reasons.map((x) => el("li", {}, x))) : el("p", {}, "No blocked agents and no approvals waiting too long."));
    const agentRow = (w) => el("li", { class: `rk-row${w.status === "suspended" ? " off" : ""}` },
      el("div", {}, el("strong", {}, w.actor_id), " ", w.status === "suspended" ? pill("Suspended", "rose") : pill(LV[w.level][1], LV[w.level][2]),
        el("p", {}, `${w.application} · ${w.why} · mostly “${w.top_action}”`)),
      el("div", { class: "gov-actions" },
        canEdit && w.status === "active" ? el("button", { class: "gov-button", type: "button", onclick: suspend(w) }, "Suspend") : "",
        el("a", { class: "gov-button gov-secondary", href: `#/decisions/all` }, "See decisions")));
    const waitRow = (w) => el("li", { class: "rk-row" },
      el("div", {}, el("strong", {}, w.title), " ", pill(`${w.hours >= 24 ? Math.floor(w.hours / 24) + "d " : ""}${Math.round(w.hours % 24)}h waiting`, w.hours >= 24 ? "rose" : "amber"),
        el("p", {}, `${w.application} · submitted by ${w.submitted_by}`)),
      el("a", { class: "gov-button", href: `#/approval/${w.decision_id}` }, "Review →"));
    const max = Math.max(1, ...r.trend.map((d) => d.ALLOW + d.ESCALATE + d.DENY));
    const bar = (d) => { const col = el("div", { class: "rk-col", title: `${d.day}: ${d.ALLOW} allowed, ${d.ESCALATE} escalated, ${d.DENY} blocked` });
      for (const [k, cls] of [["DENY", "no"], ["ESCALATE", "esc"], ["ALLOW", "ok"]]) { const s = el("span", { class: `rk-seg ${cls}` }); s.style.height = `${(d[k] / max) * 100}%`; col.append(s); }
      return el("div", { class: "rk-day" }, col, el("small", {}, d.day)); };
    main.replaceChildren(page(head("RISK", "Risk", "What needs your attention, and the one-click fix."),
      banner, m,
      card(`Agents to watch (${r.agents_to_watch.length})`, "Agents that were blocked this week or escalated often today.",
        r.agents_to_watch.length ? el("ul", { class: "rk-list" }, r.agents_to_watch.map(agentRow)) : el("p", { class: "tb-sub" }, "None.")),
      card(`Waiting for a person (${r.waiting.length})`, "Oldest first. Anything over 24 hours is flagged.",
        r.waiting.length ? el("ul", { class: "rk-list" }, r.waiting.slice(0, 10).map(waitRow)) : el("p", { class: "tb-sub" }, "Nothing is waiting.")),
      el("div", { class: "tb-two" },
        card("Last 7 days", "", el("div", { class: "rk-chart" }, r.trend.map(bar)),
          el("div", { class: "rk-legend" }, el("span", { class: "ok" }, "Allowed"), el("span", { class: "esc" }, "Escalated"), el("span", { class: "no" }, "Blocked"))),
        card("Rules firing most (7 days)", "A rule that fires a lot is either strict or catching real problems.",
          r.top_rules.length ? el("ul", { class: "tb-status" }, r.top_rules.map((x) => el("li", {}, el("span", { class: "gov-code" }, x.policy_id), pill(`${x.count} ${x.decision === "DENY" ? "blocked" : "escalated"}`, x.decision === "DENY" ? "rose" : "amber"))))
            : el("p", { class: "tb-sub" }, "No blocks or escalations this week."), el("a", { href: "#/policies" }, "Open Policies →"))),
      el("p", { class: "tb-sub" }, r.thresholds)));
  };

  // ---------- Evidence: decision chain + runs ----------
  const runsEvidence = routes.evidence;
  routes.evidence = async () => {
    await runsEvidence();
    const m = msgEl();
    const out = el("div", {});
    const search = el("input", { class: "tb-search", type: "search", placeholder: "Search by decision ID, actor, client, policy…", "aria-label": "Search evidence" });
    const find = async () => {
      if (!search.value.trim()) { out.replaceChildren(); return; }
      const d = await safe(api(`/v1/decisions?q=${encodeURIComponent(search.value.trim())}&limit=100`));
      out.replaceChildren(d?.items.length ? table([...DCOLS, "Record hash"], d.items.map((r) => { const tr = decisionRow(r); tr.append(el("td", { class: "gov-code" }, `#${r.sequence} ${r.record_hash.slice(0, 12)}…`)); return tr; }))
        : el("p", { class: "tb-sub" }, "No matching records."));
    };
    search.addEventListener("input", () => { clearTimeout(search.t); search.t = setTimeout(find, 250); });
    const verify = el("button", { class: "gov-button", type: "button", onclick: async () => {
      try { const v = await api("/v1/decisions-verify"); say(m, v.valid ? `Chain intact: ${v.checked} records verified. ${v.note}` : `Chain broken at ${v.broken_at}.`, v.valid); }
      catch (e) { say(m, e.message, false); } } }, "Verify decision chain");
    const pdf = el("button", { class: "gov-button gov-secondary", type: "button", onclick: () => download("/v1/decisions-export?fmt=pdf", "trustops-governance-report.pdf").catch((e) => say(m, e.message, false)) }, "PDF report");
    main.querySelector(".gov-page-heading")?.after(card("Decision evidence", "Every decision from every application, in one SHA-256 hash chain.",
      el("div", { class: "tb-toolbar" }, search, el("div", { class: "gov-actions" }, verify, pdf)), m, out));
  };

  // ---------- Reports ----------
  routes["governance-reports"] = async () => {
    const [s, v, pol, apps] = await Promise.all([safe(api("/v1/decisions-stats")), safe(api("/v1/decisions-verify")), safe(api("/v1/policies")), safe(api("/v1/integrations"))]);
    const m = msgEl();
    const dl = (label, path, name, primary) => el("button", { class: `gov-button${primary ? "" : " gov-secondary"}`, type: "button", onclick: () => download(path, name).catch((e) => say(m, e.message, false)) }, label);
    const row = (k, val) => el("li", {}, el("span", {}, k), el("strong", {}, String(val)));
    const report = el("section", { class: "tb-card tb-report", id: "gov-report" },
      el("div", { class: "tb-agent-top" }, el("h3", {}, "Governance report"), el("span", { class: "tb-sub" }, `Generated ${new Date().toLocaleString("en-GB")}`)),
      el("ul", { class: "tb-status" },
        row("Connected applications", apps?.items.length ?? "–"),
        row("Decisions (excluding simulated)", s?.total ?? "–"),
        row("Allowed", s?.counts.ALLOW ?? "–"), row("Escalated to a person", s?.counts.ESCALATE ?? "–"), row("Denied", s?.counts.DENY ?? "–"),
        row("Still waiting for a person", s?.pending_approvals ?? "–"),
        row("Active policy rules", pol ? pol.rules.filter((r) => r.enabled).length : "–"),
        row("Evidence chain", v ? (v.valid ? `Intact (${v.checked} records, hash-chained, not KMS signed)` : `Broken at ${v.broken_at}`) : "–")),
      el("p", { class: "tb-sub" }, "The PDF has this summary, the policies in force, every escalation and denial with who decided it, the full decision log and an integrity check. It describes recorded activity only; it is not a compliance certification."), m);
    main.replaceChildren(page(head("OUTPUTS", "Reports", "Reports for your risk committee, auditors or regulators.",
      el("button", { class: "gov-button", type: "button", onclick: () => download("/v1/decisions-export?fmt=pdf", "trustops-governance-report.pdf").catch(() => {}) }, "Download PDF report")),
      report));
  };

  // ---------- Authority: applications → agents → what each may do; people ----------
  routes.authority = async () => {
    const [au, apps] = await Promise.all([api("/v1/authority"), safe(api("/v1/integrations"))]);
    const m = msgEl();
    const edit = au.can_edit;
    const setStatus = async (a, status) => {
      let reason = "";
      if (status === "suspended") { reason = prompt(`Suspend ${a.actor_id}? Every request from it will be denied.\nReason:`); if (!reason) return; }
      try { await api(`/v1/authority/agents/${a.id}`, { method: "PATCH", body: { status, reason } }); await routes.authority(); }
      catch (e) { say(m, e.message, false); }
    };
    // what an agent may do, derived from the policy matrix (actor type "agent")
    const can = { ALLOW: [], ESCALATE: [], DENY: [] };
    for (const action of au.matrix.actions) {
      for (const x of au.matrix.cells[`agent|${action}`]) {
        if (x.when === "no rule") { can.ESCALATE.push(action); continue; }
        const cells = au.matrix.cells[`agent|${action}`];
        const limit = cells.find((y) => y.when.startsWith("above"));
        const label = x.when === "otherwise" && limit ? `${action} up to ${limit.when.replace("above ", "")}` : x.when === "always" || x.when === "otherwise" ? action : `${action} ${x.when}`;
        if (!can[x.decision].includes(label)) can[x.decision].push(label);
      }
    }
    const rights = el("div", { class: "au-rights" },
      el("div", { class: "au-r ok" }, el("b", {}, "✓ Can do"), el("span", {}, can.ALLOW.join(", ") || "nothing")),
      el("div", { class: "au-r esc" }, el("b", {}, "! Must ask a person"), el("span", {}, can.ESCALATE.join(", ") || "nothing")),
      el("div", { class: "au-r no" }, el("b", {}, "✕ Never"), el("span", {}, can.DENY.join(", ") || "nothing")));
    const agentLine = (a) => el("li", { class: `au-agent${a.status === "suspended" ? " off" : ""}` },
      el("div", {}, el("strong", {}, a.actor_id), " ",
        a.status === "active" ? pill("Active", "green") : pill("Suspended", "rose"),
        a.status === "suspended" && a.status_changed?.reason ? el("p", {}, `${a.status_changed.reason} — ${a.status_changed.by}`) : "",
        el("p", {}, `${(a.counts.ALLOW || 0) + (a.counts.ESCALATE || 0) + (a.counts.DENY || 0)} requests · last ${at(a.last_seen)}`)),
      edit ? (a.status === "active"
        ? el("button", { class: "gov-button gov-secondary", type: "button", onclick: () => setStatus(a, "suspended") }, "Suspend")
        : el("button", { class: "gov-button", type: "button", onclick: () => setStatus(a, "active") }, "Resume")) : "");
    const appCards = (apps?.items || []).map((x) => {
      const agents = au.agents.filter((a) => a.application.id === x.id);
      return el("section", { class: "tb-card au-app" },
        el("div", { class: "tb-agent-top" }, el("div", {}, el("h3", {}, x.name), el("p", { class: "tb-sub" }, `${x.category} · key ${x.key_hint || "–"} · registered by ${x.created_by}`)),
          el("a", { class: "gov-button gov-secondary", href: "#/connected-systems" }, "Manage key")),
        agents.length ? el("ul", { class: "au-agents" }, agents.map(agentLine))
          : el("p", { class: "tb-sub" }, "No agents yet. They appear the first time this application asks TrustOps."));
    });
    const group = (title, list) => el("div", { class: "au-people" }, el("b", {}, title), el("span", {}, list.length ? list.join(", ") : "–"));
    const has = (x, r) => x.roles.includes(r);
    const recent = au.history.slice(0, 5);
    main.replaceChildren(page(
      head("AUTHORITY", "Authority", "What your AI is allowed to do, who gave it that authority, and how to take it away."),
      card("What every agent may do", "Set by your Policies. The same limits apply to every agent until you change them.", rights, el("a", { href: "#/policies" }, "Change in Policies →")),
      el("h3", { class: "au-h" }, "1. Applications and their agents"),
      appCards.length ? el("div", { class: "au-apps" }, ...appCards)
        : card("No applications yet", "Register an application to give it authority to ask TrustOps.", el("a", { class: "gov-button", href: "#/add-application" }, "+ Add application")),
      m,
      el("h3", { class: "au-h" }, "2. People"),
      card("", "", group("Can change rules and authority", au.people.filter((x) => has(x, "Administrator")).map((x) => x.user)),
        group("Can approve escalations", au.people.filter((x) => has(x, "Controller / approver") || has(x, "Administrator")).map((x) => x.user)),
        group("View only", au.people.filter((x) => !has(x, "Administrator") && !has(x, "Controller / approver") && !has(x, "Contributor")).map((x) => x.user)),
        el("a", { href: "#/governance-team" }, "Manage people →")),
      el("h3", { class: "au-h" }, "Recent changes"),
      card("", "", recent.length ? el("ul", { class: "tb-status" }, recent.map((e) => el("li", {}, el("span", {}, `${e.sub} · ${e.action.replace("authority.agent.", "agent ").replace("integration.", "application ").replace("policy.", "policy ").replace("decision.resolve.", "escalation ")}`), el("span", { class: "tb-sub" }, `${e.ref || ""} · ${at(e.at)}`))))
        : el("p", { class: "tb-sub" }, "No changes yet."))));
  };
}
