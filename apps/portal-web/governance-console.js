// TrustOps governance console: decisions, policies, approvals of escalations, risk, evidence and reports.
// All data comes from the TrustOps API. Nothing here is sample data.
import { fmtDateTime } from "./dates.js?v=d-2026-11-16";

export function registerGovernanceConsole({ routes, main, el, api }) {
  const safe = (p) => p.catch(() => null);
  const pill = (text, tone = "neutral") => el("span", { class: `gov-pill gov-${tone}` }, el("span", { class: "gov-dot" }), text);
  const TONE = { ALLOW: "green", ESCALATE: "amber", DENY: "rose", APPROVED: "green", REJECTED: "rose", PENDING: "amber" };
  const head = (kicker, title, sub, ...actions) => el("div", { class: "gov-page-heading" },
    el("div", {}, el("span", { class: "gov-kicker" }, kicker), el("h2", {}, title), el("p", {}, sub)),
    actions.length ? el("div", { class: "gov-actions" }, ...actions) : "");
  const page = (...kids) => el("div", { class: "gov tb" }, ...kids);
  const card = (title, sub, ...kids) => el("section", { class: "tb-card" }, title ? el("h3", {}, title) : "", sub ? el("p", { class: "tb-sub" }, sub) : "", ...kids);
  const at = (t) => fmtDateTime(t);          // "16 Nov 2026, 14:05" everywhere (16/11)
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
  // Five grouped columns (LedgerSight table style: a main line and a muted second line) so the feed fits without sideways scrolling.
  const decisionRow = (r) => {
    const [day, time] = String(at(r.at)).split(/,\s*/);
    const amount = money(r);
    return el("tr", {},
      el("td", { class: "dt-when" }, el("span", { class: "dt-main" }, day), time ? el("span", { class: "dt-sub" }, time) : ""),
      el("td", {}, el("strong", { class: "dt-main" }, r.actor.id),
        el("span", { class: "dt-sub" }, `${r.actor.type} · ${r.application.name}${r.simulated ? " · simulated" : ""}`)),
      el("td", {}, el("span", { class: "dt-main gov-code" }, r.action),
        el("span", { class: "dt-sub" }, [r.client || "no client", amount && amount !== "–" ? amount : ""].filter(Boolean).join(" · "))),
      el("td", { class: "dt-dec" }, el("span", { class: "dt-main" }, pill(r.decision, TONE[r.decision]), " ", el("span", { class: "gov-code" }, r.policy_id)),
        final(r) !== r.decision ? el("span", { class: "dt-sub" }, pill(final(r), TONE[final(r)])) : ""),
      el("td", { class: "dt-why" }, r.reason));
  };
  const DCOLS = ["When", "Who", "Action", "Decision", "Reason"];

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
  const APPROVER_ROLES = ["customer_controller", "customer_admin", "cloudseals_admin"];
  routes.approvals = async () => {
    // 16/11 (slow pages): the governed-runs section and the escalations load at the same time, not one after the other.
    const [d, me, revs] = await Promise.all([safe(api("/v1/decisions?pending=true")), safe(api("/v1/me")), safe(api("/v1/decisions-reviewers")), runsApprovals()]);
    const myEmail = (me?.email || me?.sub || "").toLowerCase();
    const canAct = (me?.roles || []).some((r) => APPROVER_ROLES.includes(r));
    const m = msgEl();
    const all = d?.items || [];
    const mineOnly = sessionStorage.getItem("ap-mine") === "1";
    const assignee = (r) => r.assignment?.to || null;
    // 2026-11-13 action items: items an application sent again after a rejection are shown on their own
    const resub = (r) => +(r.context?.resubmission || 0);
    const shown = mineOnly ? all.filter((r) => assignee(r) === myEmail) : all;
    const again = shown.filter((r) => resub(r) > 0), items = shown.filter((r) => !resub(r));
    const mineCount = all.filter((r) => assignee(r) === myEmail).length;
    const title = (r) => r.details?.title || r.action.replaceAll("_", " ");
    const tab = (label, on, val) => el("button", { type: "button", class: `gov-button${on ? "" : " gov-secondary"}`,
      onclick: () => { sessionStorage.setItem("ap-mine", val); routes.approvals(); } }, label);

    // Bulk handling (16/11 action items): tick items (or Select all), then assign them, or approve / reject them with one
    // reason. The server checks every item exactly as it does one at a time and says which ones it could not do and why.
    const sel = new Set();
    const boxes = [];
    const selAll = el("input", { type: "checkbox", id: "ap-all" });
    const count = el("span", { class: "ap-count", "aria-live": "polite" });
    const bulkReason = el("input", { id: "ap-bulk-reason", class: "tb-search", maxlength: 2000, placeholder: "One reason, recorded on every selected item", "aria-label": "Reason for the selected items" });
    const bulkTo = el("select", { id: "ap-bulk-to", "aria-label": "Assign the selected items to" }, el("option", { value: "" }, "Assign to…"),
      (revs?.items || []).map((x) => el("option", { value: x.email }, `${x.email} · ${x.role}`)));
    const bm = el("div", { class: "tb-msg", role: "status" });          // say() replaces its class, so the wrapper carries ap-bulk-msg
    const buttons = [];
    const sync = () => {
      count.textContent = sel.size ? `${sel.size} selected` : "None selected";
      selAll.checked = boxes.length > 0 && sel.size === boxes.length;
      selAll.indeterminate = sel.size > 0 && sel.size < boxes.length;
      for (const b of buttons) b.disabled = !sel.size;
    };
    selAll.addEventListener("change", () => {
      for (const [id, b] of boxes) { b.checked = selAll.checked; if (selAll.checked) sel.add(id); else sel.delete(id); }
      sync();
    });
    const pick = (r) => {
      const b = el("input", { type: "checkbox", class: "ap-pick", "aria-label": `Select ${title(r)}` });
      b.addEventListener("change", () => { if (b.checked) sel.add(r.id); else sel.delete(r.id); sync(); });
      boxes.push([r.id, b]);
      return b;
    };
    const runBulk = (op) => async () => {
      const ids = [...sel];
      if (!ids.length) return;
      const body = { ids, op };
      if (op === "assign") {
        if (!bulkTo.value) { say(bm, "Choose who to assign them to.", false); bulkTo.focus(); return; }
        body.to = bulkTo.value;
      } else {
        if (!bulkReason.value.trim()) { say(bm, "Write one reason first; it is recorded on every selected item.", false); bulkReason.focus(); return; }
        body.reason = bulkReason.value.trim();
        const n = ids.length;
        if (!confirm(`${op === "approve" ? "Approve" : "Reject"} ${n} item${n === 1 ? "" : "s"} with this reason?\n\n“${body.reason}”`)) return;
      }
      for (const b of buttons) b.disabled = true;
      say(bm, "Working…", true);
      try {
        const out = await api("/v1/decisions-bulk", { method: "POST", body });
        const names = Object.fromEntries(all.map((r) => [r.id, title(r)]));
        const verb = { approve: "Approved", reject: "Rejected", assign: `Assigned to ${body.to}` }[op];
        const lines = out.results.filter((x) => !x.ok).map((x) => `${names[x.id] || x.id}: ${x.message || "could not be done"}`);
        sessionStorage.setItem("ap-bulk-msg", JSON.stringify({ ok: !out.failed, text: `${verb}: ${out.done} of ${out.results.length}.`, lines }));
        await routes.approvals();
      } catch (e) { say(bm, e.message, false); sync(); }
    };
    const bulkBtn = (label, op, secondary) => {
      const b = el("button", { type: "button", class: `gov-button${secondary ? " gov-secondary" : ""}`, onclick: runBulk(op) }, label);
      buttons.push(b);
      return b;
    };
    const bulkBar = canAct && shown.length ? el("div", { class: "ap-bulk", role: "group", "aria-label": "Act on selected items" },
      el("div", { class: "ap-bulk-row" }, el("label", { class: "ap-all", for: "ap-all" }, selAll, " Select all"), count),
      el("div", { class: "ap-bulk-row" }, bulkTo, bulkBtn("Assign", "assign", true)),
      el("div", { class: "ap-bulk-row" }, bulkReason, bulkBtn("Approve selected", "approve"), bulkBtn("Reject selected", "reject", true)),
      el("p", { class: "tb-sub" }, "Each item is checked as if you opened it. Items assigned to someone else, items you sent and items without details are not approved; they are listed here with the reason."),
      el("div", { class: "ap-bulk-msg" }, bm)) : "";
    const prior = sessionStorage.getItem("ap-bulk-msg");
    if (prior && bulkBar) {
      sessionStorage.removeItem("ap-bulk-msg");
      const p = JSON.parse(prior);
      say(bm, p.text, p.ok);
      if (p.lines.length) bm.append(el("ul", { class: "tb-list" }, p.lines.map((t) => el("li", {}, t))));
    }

    const item = (r) => el("li", { class: "ap-item" + (resub(r) ? " ap-resub" : "") },
      canAct ? el("div", { class: "ap-check" }, pick(r)) : "",
      el("div", { class: "ap-main" },
        el("div", { class: "ap-top" }, el("strong", {}, title(r)), pill(r.policy_id, "amber"),
          resub(r) ? pill(`Resubmitted${resub(r) > 1 ? " ×" + resub(r) : ""}`, "rose") : "", r.amount_minor != null ? el("span", { class: "ap-amt" }, money(r)) : ""),
        r.details?.summary ? el("p", {}, r.details.summary) : "",
        el("p", { class: "ap-meta" }, el("strong", {}, "Reviewer: "),
          assignee(r) ? (assignee(r) === myEmail ? `${assignee(r)} (you)` : `${assignee(r)} · only they can decide`) : "Any approver"),
        el("p", { class: "ap-meta" }, `${r.application.name} · submitted by ${r.actor.type === "agent" ? "agent " : ""}${r.actor.id}${r.client ? ` · ${r.client}` : ""} · ${at(r.at)} · ${r.reason}`),
        r.details?.link ? el("a", { href: r.details.link, target: "_blank", rel: "noopener noreferrer" }, `Open in ${r.application.name} ↗`) : ""),
      el("a", { class: "gov-button", href: `#/approval/${r.id}` }, "Review →"));
    const section = card(`Waiting for your approval (${items.length})`, "Items your applications sent to TrustOps. Open each one, check what is in it, then approve or reject. The application picks up the result.",
      el("div", { class: "gov-actions" }, tab(`All (${all.length})`, !mineOnly, "0"), tab(`Assigned to me (${mineCount})`, mineOnly, "1")),
      bulkBar,
      items.length ? el("ul", { class: "ap-list" }, items.map(item)) : el("p", { class: "tb-sub" }, mineOnly ? "Nothing is assigned to you." : "Nothing is waiting."), m);
    const againCard = again.length ? card(`Sent again after a rejection (${again.length})`,
      "These were rejected before. The application has attached new proof and sent them again; the earlier rejection is shown on each item.",
      el("ul", { class: "ap-list" }, again.map(item))) : "";
    sync();
    const root = main.querySelector(".tb");
    const runCard = root?.querySelectorAll(".tb-card")[0];      // the governed-runs card rendered by runsApprovals()
    root?.querySelector(".gov-page-heading")?.after(section);
    if (againCard) section.before(againCard);
    runCard?.querySelector("h3")?.replaceChildren(runCard.querySelector("h3").textContent.replace("Waiting for a decision", "Governed workflow runs waiting"));
  };

  // ---------- Review one escalated item ----------
  routes.approval = async (did) => {
    const [r, revs, me] = await Promise.all([api(`/v1/decisions/${encodeURIComponent(did)}`), safe(api("/v1/decisions-reviewers")), safe(api("/v1/me"))]);
    const myIds = [me?.email, me?.sub].filter(Boolean).map((x) => x.toLowerCase());
    const requesters = [r.actor.id, r.requested_by].filter(Boolean).map((x) => String(x).toLowerCase());
    const named = r.assignment?.to || null;
    const notMine = !!named && !myIds.includes(named);      // 16/11: a named approver is binding
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
    const rejectBtn = el("button", { class: "gov-button gov-secondary", type: "button" }, hasDetails ? "Reject" : "Reject — ask for details");
    const sync = () => { approveBtn.disabled = notMine || (!hasDetails && !checked.checked); rejectBtn.disabled = notMine; };
    checked.addEventListener("change", sync); sync();
    const decide = (outcome) => async () => {
      if (!reason.value.trim()) { say(m, "Write a reason first.", false); reason.focus(); return; }
      try { await api(`/v1/decisions/${r.id}/resolve`, { method: "POST", body: { outcome, reason: reason.value.trim(), checked_in_app: checked.checked } }); location.hash = "#/approvals"; }
      catch (e) { say(m, e.message, false); }
    };
    approveBtn.addEventListener("click", decide("approve"));
    rejectBtn.addEventListener("click", decide("reject"));
    const pending = r.decision === "ESCALATE" && !r.resolution;
    const am = msgEl();
    const assignSel = el("select", { id: "ap-assign", "aria-label": "Reviewer", onchange: async () => {
      try { await api(`/v1/decisions/${r.id}/assign`, { method: "POST", body: { to: assignSel.value || null } }); await routes.approval(did); }
      catch (e) { say(am, e.message, false); } } },
      el("option", { value: "" }, "Any approver"),
      // the person who sent it can never approve it, so they are not offered (16/11)
      (revs?.items || []).filter((x) => !requesters.includes(x.email)).map((x) => el("option", { value: x.email, selected: named === x.email }, `${x.email} · ${x.role}`)));
    const fact = (label, value) => el("div", { class: "rv-fact" }, el("span", {}, label), el("strong", {}, value ?? "–"));
    // Supporting files (2026-11-13 action items: "Upload button for reviewers"): the approver can upload a receipt,
    // remittance or other proof while the item waits; each file is checked and scanned, then listed with its SHA-256.
    const fm = msgEl();
    const kb = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);
    const fileInput = el("input", { type: "file", id: "ap-file", hidden: true,
      accept: ".pdf,.png,.jpg,.jpeg,.csv,.txt,.json,.docx,.xlsx,application/pdf,image/png,image/jpeg,text/csv,text/plain,application/json" });
    const TYPE_BY_EXT = { pdf: "application/pdf", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", csv: "text/csv", txt: "text/plain", json: "application/json",
      docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" };
    const uploadBtn = el("button", { class: "gov-button gov-secondary", type: "button", onclick: () => fileInput.click() }, "Upload file");
    fileInput.addEventListener("change", async () => {
      const f = fileInput.files[0]; fileInput.value = "";
      if (!f) return;
      const type = f.type || TYPE_BY_EXT[(f.name.split(".").pop() || "").toLowerCase()] || "application/octet-stream";
      if (f.size > 10 * 1024 * 1024) { say(fm, "Files can be at most 10 MB.", false); return; }
      uploadBtn.disabled = true; say(fm, `Checking and uploading ${f.name}…`, true);
      try {
        await api(`/v1/decisions/${r.id}/attachments?filename=${encodeURIComponent(f.name)}`, { method: "POST", body: await f.arrayBuffer(), headers: { "Content-Type": type } });
        await routes.approval(did);
      } catch (e) { uploadBtn.disabled = false; say(fm, e.message, false); }
    });
    const files = r.attachments || [];
    const filesCard = files.length || (r.decision === "ESCALATE" && !r.resolution) ? el("section", { class: "tb-card", id: "ap-files" },
      el("h3", {}, "Supporting files"),
      el("p", { class: "tb-sub" }, files.length ? "Uploaded by reviewers in TrustOps. Each file is checked and scanned before it is kept."
        : "Upload a receipt, remittance or other proof you used for this decision. PDF, image, Word, Excel, CSV or text, up to 10 MB."),
      files.length ? el("ul", { class: "tb-list ap-files" }, files.map((a) => el("li", {},
        el("a", { href: `#/approval/${r.id}`, class: "ap-file-link", title: "Download this file", onclick: (e) => { e.preventDefault();
          download(`/v1/decisions/${r.id}/attachments/${a.id}`, a.filename).catch((err) => say(fm, err.message, false)); } }, a.filename),
        el("span", { class: "tb-sub" }, ` · ${kb(a.size)} · ${a.by} · ${at(a.at)} · sha256 ${a.sha256.slice(0, 12)}…`)))) : "",
      r.decision === "ESCALATE" && !r.resolution ? el("div", { class: "gov-actions" }, uploadBtn, fileInput) : "", fm) : "";
    const norm = (v) => String(v || "").replace(/[\s,]/g, "").toLowerCase();
    const compare = d.compare ? el("section", { class: "tb-card" }, el("h3", {}, "Side by side"),
      el("p", { class: "tb-sub" }, "Fields that differ are highlighted."),
      table(["", d.compare.left_title, d.compare.right_title], d.compare.rows.map(([f, l, rr]) => {
        const diff = norm(l) !== norm(rr);
        return el("tr", { class: diff ? "rv-diff" : "" }, el("td", {}, el("strong", {}, f)), el("td", { class: "w" }, l || "—"), el("td", { class: "w" }, rr || "—", diff ? el("span", { class: "rv-flag" }, " differs") : ""));
      }))) : "";
    const prevId = r.context?.resubmission_of;
    const prev = prevId ? await api(`/v1/decisions/${encodeURIComponent(prevId)}`).catch(() => null) : null;
    const resubBanner = r.context?.resubmission ? el("section", { class: "tb-card rv-resub" },
      el("h3", {}, `Sent again after a rejection${r.context.resubmission > 1 ? ` (attempt ${r.context.resubmission + 1})` : ""}`),
      prev?.resolution ? el("p", {}, `Rejected by ${prev.resolution.by} on ${at(prev.resolution.at)}: “${prev.resolution.reason}”`) : "",
      el("p", { class: "tb-sub" }, `${r.application.name} attached new proof and sent it again. Check what changed (see “New proof since the rejection” below) before you decide.`),
      prevId ? el("a", { href: `#/approval/${prevId}` }, "Open the earlier request →") : "") : "";
    // Layout (2026-11-13 review): header and resubmission banner across the top; what to check on the left;
    // reviewer + decision in a sticky panel on the right (one column below 1180px).
    const requestCard = el("section", { class: "tb-card" }, el("h3", {}, "Request"),
      el("div", { class: "rv-facts" },
        fact("Application", r.application.name), fact("Submitted by", `${r.actor.type}: ${r.actor.id}`),
        fact("Action", r.action), fact("Client", r.client), fact("Amount", money(r)), fact("Submitted", at(r.at)),
        fact("Why it is here", `${r.policy_id} — ${r.reason}`), fact("Evidence record", `#${r.sequence} ${r.record_hash.slice(0, 12)}…`),
        pending ? "" : fact("Reviewer", r.assignment?.to || "Any approver")));
    const reviewerCard = pending ? el("section", { class: "tb-card ap-side-card" }, el("h3", {}, "Reviewer"),
      el("div", { class: "tb-form" }, el("label", { for: "ap-assign", class: "sr-only" }, "Reviewer"), assignSel,
        el("p", { class: "tb-sub" }, r.assignment?.by ? `Assigned by ${r.assignment.by} · ${at(r.assignment.at)}${named ? ". Only the person named here can decide it." : ""}` : "Any Admin or Approver can review this."), am)) : "";
    const decisionCard = pending ? el("section", { class: "tb-card tb-step ap-side-card" }, el("h3", {}, "Your decision"),
        notMine ? el("div", { class: "rv-warn" }, el("strong", {}, `Assigned to ${named}.`),
          el("p", {}, `Only ${named} can approve or reject it. To decide it yourself, change the reviewer below first (the change is recorded).`)) : "",
        el("p", { class: "tb-sub" }, "What you saw here is recorded in the evidence chain with your decision. Approvers cannot approve items they submitted; an administrator approving their own item is recorded as a self-approval."),
        !hasDetails && d.link ? el("label", { class: "rv-check", for: "ap-checked" }, checked, ` I opened this item in ${r.application.name} and checked it`) : "",
        el("div", { class: "tb-form" }, reason),
        el("div", { class: "gov-actions ap-decide" }, approveBtn, rejectBtn), m)
      : el("section", { class: "tb-card ap-side-card" }, el("h3", {}, "Decision"),
          r.resolution ? el("div", { class: "rv-facts ap-stack" }, fact("Outcome", r.resolution.outcome === "approve" ? "Approved" : "Rejected"), fact("By", r.resolution.by + (r.resolution.self_resolved ? " (self-approved by administrator)" : "")), fact("When", at(r.resolution.at)), fact("Reason", r.resolution.reason),
            fact("Based on", { details_in_trustops: "Details shown in TrustOps", checked_in_application: "Checked in the application", none: "—" }[r.resolution.basis] || "—"))
            : el("p", { class: "tb-sub" }, `${r.decision} — no person needed.`));
    main.replaceChildren(page(
      el("a", { class: "gov-back", href: "#/approvals" }, "← Approvals"),
      head("REVIEW", d.title || r.action.replaceAll("_", " "), d.summary || r.reason),
      resubBanner,
      el("div", { class: "ap-layout" },
        el("div", { class: "rv-main" },
          d.recommendation || d.consequence ? el("div", { class: "tb-two ap-two" },
            d.recommendation ? el("section", { class: "tb-card rv-reco" }, el("h3", {}, "Agent recommendation"), el("p", {}, d.recommendation)) : "",
            d.consequence ? el("section", { class: "tb-card rv-cons" }, el("h3", {}, "If you approve"), el("p", {}, d.consequence)) : "") : "",
          compare,
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
          filesCard,
          requestCard),
        el("aside", { class: "rv-side", "aria-label": "Decision" }, decisionCard, reviewerCard))));
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
        tm.replaceChildren(el("div", { class: "tb-result" }, pill(r.decision, TONE[r.decision]), el("span", { class: "gov-code" }, r.policy_id), el("span", {}, r.reason),
          pill("Simulated · not counted", "neutral")));
      } catch (err) { tm.replaceChildren(el("p", { class: "tb-msg bad" }, err.message)); }
    } },
      el("label", { for: "t-type" }, "Actor type"), aType, ...fld("t-id", "Actor ID", { placeholder: "match-agent" }),
      ...fld("t-action", "Action", { required: true, placeholder: "approve_match", list: "t-actions" }),
      el("datalist", { id: "t-actions" }, [...new Set(rules.flatMap((r) => r.actions))].map((a) => el("option", { value: a }))),
      ...fld("t-amt", "Amount", { type: "number", min: "0", step: "0.01", placeholder: "optional" }),
      el("button", { class: "gov-button", type: "submit", disabled: !edit, title: edit ? "" : "Only a workspace administrator can test policies" }, "Test decision"));

    main.replaceChildren(page(head("POLICIES & WORKFLOW PACKS", "Policies", "Rules are checked top to bottom. The first rule that matches decides. If none match, a person decides (Escalate)."),
      card(`Finance pack${ops ? ` · ${ops.workflow_pack} v${ops.workflow_version}` : ""}`, "Other packs (Healthcare, Industrial, CloudOps) are planned and not available yet."),
      el("section", { class: "gov-panel" }, table(["On", "ID", "Rule", "Actions", "Who", "Amount limit", "Decision"], rows)),
      el("div", { class: "gov-actions" }, save, reset), m,
      card("Test a decision", "",
        el("div", { class: "tb-explain" },
          el("p", {}, el("strong", {}, "What it is for: "), "check what your rules would answer before an application ever asks. ",
            "Pick who is acting (an agent, a person or a service), the action and, if it matters, an amount. TrustOps runs the rules above, top to bottom, ",
            "and shows the answer — Allow, Escalate or Deny — with the rule that decided it."),
          el("p", {}, el("strong", {}, "What it does not do: "), "nothing is sent to any application and nothing is approved. ",
            "Each test is kept in the evidence log marked “simulated”, so it is visible to auditors but left out of the figures on Overview, Risk and Reports."),
          el("p", { class: "tb-sub" }, "Typical use: after changing a rule, test the actions it should affect, for example an agent asking for approve_match above the limit.")),
        test, tm),
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
    const [, dlCard] = await Promise.all([runsEvidence(), downloadCard()]);   // 16/11: in parallel, not one after the other
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
    // 16/11: "Verify decision chain" worked without selecting anything and nobody knew why. It checks the WHOLE log, so it
    // needs no selection; the card now says so and the result says how many records were checked, the head hash and when.
    const vm = el("div", { class: "ev-verify-out", role: "status" });
    const verify = el("button", { class: "gov-button", type: "button", id: "ev-verify", onclick: async () => {
      verify.disabled = true; vm.replaceChildren(el("p", { class: "tb-sub" }, "Checking every record…"));
      try {
        const v = await api("/v1/decisions-verify");
        vm.replaceChildren(el("div", { class: `tb-msg ${v.valid ? "ok" : "bad"}` },
          v.valid ? `Intact. All ${v.checked} records were checked and none has been changed or removed.` : `Broken at record ${v.broken_at} (after checking ${v.checked} records). Records from there on cannot be trusted.`),
          el("ul", { class: "tb-status" },
            el("li", {}, el("span", {}, "Records checked"), el("strong", {}, String(v.checked))),
            v.head ? el("li", {}, el("span", {}, "Latest record hash"), el("span", { class: "gov-code", title: v.head }, `${v.head.slice(0, 16)}…`)) : "",
            el("li", {}, el("span", {}, "Checked"), el("strong", {}, fmtDateTime(new Date()))),
            el("li", {}, el("span", {}, "Signing"), el("span", {}, v.signed ? "KMS signed" : "Hash chain only (not KMS signed)"))));
      } catch (e) { vm.replaceChildren(el("p", { class: "tb-msg bad" }, e.message)); }
      finally { verify.disabled = false; } } }, "Verify the whole evidence chain");
    const verifyCard = card("Is the evidence intact?", "",
      el("p", { class: "tb-sub" }, "Every decision is linked to the one before it by a SHA-256 hash. This check recalculates every link across the whole log — every application, every record — so there is nothing to select. If any record was changed or deleted, it tells you where."),
      el("div", { class: "gov-actions" }, verify), vm);
    main.querySelector(".gov-page-heading")?.after(card("Find a decision", "Search every decision from every application by ID, person or agent, client or policy.",
      el("div", { class: "tb-toolbar" }, search), m, out), verifyCard, dlCard);
  };

  // Download evidence (2026-11-13 action items): everything, or only one person's / agent's actions, one application,
  // one outcome or a date range; as a PDF report, a CSV table or the JSON audit pack. The chain check always covers
  // every record, and a filtered file says what was filtered.
  const downloadCard = async () => {
    const meta = await safe(api("/v1/decisions-people")) || { people: [], applications: [] };
    const dm = msgEl();
    const opt = (v, t) => el("option", { value: v }, t);
    const person = el("select", { id: "ev-person", "aria-label": "Person or agent" }, opt("", "Everyone"),
      meta.people.map((x) => opt(x.id, `${x.kind === "agent" ? "Agent " + x.id.replace(/^agent:/, "") : x.id} · ${x.records} record${x.records === 1 ? "" : "s"}`)));
    const app = el("select", { id: "ev-app", "aria-label": "Application" }, opt("", "All applications"), meta.applications.map((a) => opt(a, a)));
    const outcome = el("select", { id: "ev-outcome", "aria-label": "Outcome" }, opt("", "All outcomes"),
      [["ALLOW", "Allowed"], ["ESCALATE", "Sent to a person"], ["DENY", "Blocked"], ["APPROVED", "Approved"], ["REJECTED", "Rejected"], ["PENDING", "Still waiting"]].map(([v, t]) => opt(v, t)));
    const since = el("input", { type: "date", id: "ev-since", "aria-label": "From date" });
    const until = el("input", { type: "date", id: "ev-until", "aria-label": "To date" });
    const query = () => [["person", person.value], ["application", app.value], ["outcome", outcome.value], ["since", since.value], ["until", until.value]]
      .filter(([, v]) => v).map(([k, v]) => `&${k}=${encodeURIComponent(v)}`).join("");
    const filtered = () => !!query();
    const summary = el("p", { class: "tb-sub ev-scope" });
    const refresh = () => { summary.textContent = filtered()
      ? `Only ${[person.value && (person.selectedOptions[0].textContent.split(" · ")[0]), app.value, outcome.value && outcome.selectedOptions[0].textContent.toLowerCase(),
        since.value && `from ${since.value}`, until.value && `to ${until.value}`].filter(Boolean).join(" · ")}.`
      : "Everything in this workspace."; };
    [person, app, outcome, since, until].forEach((x) => x.addEventListener("change", refresh)); refresh();
    const get = (fmt, ext, label, primary) => el("button", { class: `gov-button${primary ? "" : " gov-secondary"}`, type: "button", onclick: async (e) => {
      const b = e.currentTarget; b.disabled = true; say(dm, "Preparing the download…", true);
      try { await download(`/v1/decisions-export?fmt=${fmt}${query()}`, `trustops-${fmt === "json" ? "audit-pack" : fmt === "csv" ? "decisions" : "governance-report"}.${ext}`); say(dm, "Downloaded.", true); }
      catch (err) { say(dm, err.message, false); } finally { b.disabled = false; } } }, label);
    const reset = el("button", { class: "gov-button gov-secondary", type: "button", onclick: () => { [person, app, outcome, since, until].forEach((x) => { x.value = ""; }); refresh(); } }, "Clear filters");
    const field = (label, ctl) => el("label", { class: "ev-field" }, el("span", {}, label), ctl);
    return card("Download evidence", "Download everything, or only what one person or agent did. Each file is generated from the hash-chained records.",
      el("div", { class: "ev-filters" }, field("Person or agent", person), field("Application", app), field("Outcome", outcome), field("From", since), field("To", until)),
      summary,
      el("div", { class: "gov-actions" }, get("pdf", "pdf", "PDF report", true), get("csv", "csv", "CSV table"), get("json", "json", "JSON audit pack"), reset), dm);
  };

  // ---------- Reports ----------
  routes["governance-reports"] = async () => {
    const [s, v, pol, apps] = await Promise.all([safe(api("/v1/decisions-stats")), safe(api("/v1/decisions-verify")), safe(api("/v1/policies")), safe(api("/v1/integrations"))]);
    const m = msgEl();
    const dl = (label, path, name, primary) => el("button", { class: `gov-button${primary ? "" : " gov-secondary"}`, type: "button", onclick: () => download(path, name).catch((e) => say(m, e.message, false)) }, label);
    const row = (k, val) => el("li", {}, el("span", {}, k), el("strong", {}, String(val)));
    const report = el("section", { class: "tb-card tb-report", id: "gov-report" },
      el("div", { class: "tb-agent-top" }, el("h3", {}, "Governance report"), el("span", { class: "tb-sub" }, `Generated ${fmtDateTime(new Date())}`)),
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
    const recent = au.history.slice(0, 10);     // newest first; each one is a plain sentence written by the server (16/11)
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
      card("", "Who changed what, newest first: agents suspended or limited, policies saved, applications added, approvals and reviewer changes.",
        recent.length ? el("ul", { class: "au-changes" }, recent.map((e) => el("li", {},
          el("span", { class: "au-what" }, e.text || e.action),
          el("span", { class: "au-who tb-sub" }, `${e.who || e.sub} · ${at(e.at)}`))))
        : el("p", { class: "tb-sub" }, "No changes yet."))));
  };
}
