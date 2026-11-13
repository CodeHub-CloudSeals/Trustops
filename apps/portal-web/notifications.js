// Notifications bell (TrustOps side of the LedgerSight ↔ TrustOps link). Port of LedgerSight's bell.
// The server reads them from the decision records (GET /v1/notifications): approvers are told when an application sends an
// item for approval or an agent's action is escalated; everyone is told when someone else approves or rejects an item and
// when an agent is blocked. Polled every 10 seconds while the page is visible (and on focus); "seen" is stored on the
// server per person, so it is the same in every browser. Opening the list marks it as seen.
export function registerNotifications({ el, api, toast, state }) {
  const ICON = {
    SUBMITTED: "M22 2L11 13M22 2l-7 20-4-9-9-4z", RESUBMITTED: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7", ESCALATED: "M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
    APPROVED: "M5 12.5l4.5 4.5L19 7.5", REJECTED: "M7 7l10 10M17 7L7 17", DENIED: "M12 3l8 3v6c0 4.6-3.4 8.3-8 9-4.6-.7-8-4.4-8-9V6zM9 9l6 6M15 9l-6 6",
  };
  const svg = (d, cls) => {
    const s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true");
    if (cls) s.setAttribute("class", cls);
    d.split("|").forEach((part) => { const p = document.createElementNS(s.namespaceURI, "path"); p.setAttribute("d", part); s.append(p); });
    return s;
  };
  const money = (it) => (it.amount_minor == null ? "" : `${(it.amount_minor / 100).toLocaleString("en-GB", { minimumFractionDigits: 2 })} ${it.currency || ""}`.trim());
  const who = (it) => (it.by_type === "agent" ? `Agent ${it.by}` : it.by || "Someone");
  function text(it) {
    const t = `“${it.title}”`;
    if (it.kind === "SUBMITTED") return `${who(it)} sent ${t} from ${it.application} for approval`;
    if (it.kind === "RESUBMITTED") return `${who(it)} sent ${t} again after a rejection, with new proof`;
    if (it.kind === "ESCALATED") return `${who(it)} needs a person: ${it.action}${money(it) ? " · " + money(it) : ""}`;
    if (it.kind === "APPROVED") return `${who(it)} approved ${t}`;
    if (it.kind === "REJECTED") return `${who(it)} rejected ${t}`;
    if (it.kind === "DENIED") return `${who(it)} was blocked: ${it.action}`;
    return `${who(it)} · ${it.title}`;
  }
  const ago = (sec) => (sec < 60 ? "just now" : sec < 3600 ? `${Math.round(sec / 60)} min ago` : `${Math.round(sec / 3600)} h ago`);
  const when = (t) => { const s = Date.now() / 1000 - t; return s < 86400 ? ago(Math.max(1, s)) : new Date(t * 1000).toLocaleDateString("en-GB"); };

  // One bell for the whole session: app.js puts the same element back into the top bar on every page.
  const count = el("span", { class: "notif-count hidden", "aria-hidden": "true" });
  const btn = el("button", { id: "notif-btn", class: "iconbtn", type: "button", "aria-label": "Notifications", "aria-haspopup": "dialog",
    "aria-expanded": "false", title: "Notifications" }, svg("M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9|M10.3 21a1.94 1.94 0 0 0 3.4 0"), count);
  const panel = el("div", { id: "notif-panel", class: "notif-panel hidden", role: "dialog", "aria-label": "Notifications" });
  const wrap = el("div", { class: "notif-wrap" }, btn, panel);
  let data = null, timer = 0;

  function group(items) {           // newest first; repeats of the same thing (e.g. an agent blocked 3 times) become one row
    const out = [], byKey = {};
    for (const it of items) {
      const k = it.kind === "DENIED" ? [it.kind, it.by, it.action, it.policy_id].join("|") : [it.kind, it.by, it.decision_id].join("|");
      if (byKey[k]) { byKey[k].times++; if (it.unread) byKey[k].unread = true; continue; }
      byKey[k] = { ...it, times: 1 }; out.push(byKey[k]);
    }
    return out;
  }
  function open(it) {
    close();
    location.hash = it.kind === "DENIED" ? "#/decisions/deny" : `#/approval/${it.decision_id}`;
  }
  function render() {
    const n = data || { items: [], unread: 0, for: "viewer" };
    panel.replaceChildren(
      el("div", { class: "np-head" }, el("b", {}, "Notifications"),
        el("span", { class: "np-sub" }, n.for === "approver" ? "Items sent for approval, decisions and blocked actions" : "Decisions and blocked actions")),
      n.items.length ? el("ul", { class: "np-list" }, group(n.items).map((it) => el("li", {
          class: `np-item k-${it.kind}${it.unread ? " unread" : ""}`, role: "button", tabindex: "0",
          title: it.kind === "DENIED" ? "Open blocked actions" : "Open this item", onclick: () => open(it), onkeydown: (e) => { if (e.key === "Enter") open(it); } },
        el("span", { class: "np-ico" }, svg(ICON[it.kind] || ICON.SUBMITTED)),
        el("div", { class: "np-b" }, el("div", { class: "np-t" }, text(it)),
          it.note ? el("div", { class: "np-note" }, it.kind === "APPROVED" || it.kind === "REJECTED" ? `“${it.note}”` : it.note) : "",
          el("div", { class: "np-m" }, [when(it.at), it.times > 1 ? `${it.times} times` : "", it.policy_id, it.for_me && it.pending ? "assigned to you" : "",
            it.pending && (it.kind === "SUBMITTED" || it.kind === "RESUBMITTED" || it.kind === "ESCALATED") ? "waiting" : ""].filter(Boolean).join(" · "))),
        it.unread ? el("i", { class: "np-dot", "aria-label": "new" }) : "")))
      : el("div", { class: "np-empty" }, el("b", {}, "Nothing yet"),
        el("span", {}, n.for === "approver" ? "When an application sends an item for approval, or someone decides one, it shows up here."
          : "When someone approves or rejects an item, or an agent is blocked, it shows up here.")));
  }
  function ring() {
    btn.classList.remove("ring"); count.classList.remove("bump"); void btn.offsetWidth;
    btn.classList.add("ring"); count.classList.add("bump");
    setTimeout(() => { btn.classList.remove("ring"); count.classList.remove("bump"); }, 1200);
  }
  async function load(quiet) {
    if (!state.token || !state.me) return;
    let n; try { n = await api("/v1/notifications"); } catch { return; }
    const before = data, newest = n.items[0];
    const fresh = before && newest && (!before.items[0] || newest.seq > before.items[0].seq);
    const was = count.classList.contains("hidden") ? 0 : +count.dataset.n || 0;
    data = n;
    count.textContent = n.unread > 9 ? "9+" : String(n.unread); count.dataset.n = n.unread; count.classList.toggle("hidden", !n.unread);
    btn.classList.toggle("has-unread", !!n.unread);
    btn.setAttribute("aria-label", n.unread ? `Notifications, ${n.unread} new` : "Notifications");
    if (n.unread > was) ring();
    if (fresh && !quiet && newest.unread) toast(text(newest));
    if (isOpen()) render();
  }
  const M = () => (window.Motion && window.Motion.animate && !matchMedia("(prefers-reduced-motion: reduce)").matches ? window.Motion : null);
  const isOpen = () => !panel.classList.contains("hidden") && !panel.classList.contains("closing");
  async function openPanel() {
    panel.classList.remove("hidden", "closing"); btn.setAttribute("aria-expanded", "true"); btn.classList.add("open");
    render();
    const m = M();
    if (m) {
      m.animate(panel, { opacity: [0, 1], scale: [0.86, 1], y: [-14, 0], filter: ["blur(8px)", "blur(0px)"], clipPath: ["circle(0% at 92% 0%)", "circle(150% at 92% 0%)"] },
        { type: m.spring, visualDuration: 0.5, bounce: 0.22 });
      const rows = [...panel.querySelectorAll(".np-head, .np-item, .np-empty")];
      rows.forEach((r) => { r.style.opacity = "0"; });
      const a = m.animate(rows, { opacity: [0, 1], y: [12, 0], x: [6, 0] }, { type: m.spring, visualDuration: 0.42, bounce: 0.18, delay: m.stagger(0.045, { startDelay: 0.08 }) });
      const clear = () => rows.forEach((r) => { r.style.opacity = ""; r.style.transform = ""; });
      (a.finished || a).then(clear, clear);
    }
    await load(true);
    const top = data && data.items[0];
    if (top && data.unread) {          // opening the list marks everything in it as seen (on the server, for this person only)
      try { await api("/v1/notifications/seen", { method: "POST", body: { upto: top.seq } }); } catch { return; }
      data.unread = 0; count.classList.add("hidden"); btn.classList.remove("has-unread"); btn.setAttribute("aria-label", "Notifications");
    }
  }
  function close() {
    btn.setAttribute("aria-expanded", "false"); btn.classList.remove("open");
    if (data) data.items.forEach((it) => { it.unread = false; });
    if (panel.classList.contains("hidden")) return;
    const m = M();
    if (!m) { panel.classList.add("hidden"); return; }
    panel.classList.add("closing");
    const a = m.animate(panel, { opacity: [1, 0], scale: [1, 0.9], y: [0, -10], filter: ["blur(0px)", "blur(6px)"], clipPath: ["circle(150% at 92% 0%)", "circle(0% at 92% 0%)"] },
      { duration: 0.24, ease: [0.4, 0, 1, 1] });
    const done = () => { if (panel.classList.contains("closing")) { panel.classList.add("hidden"); panel.classList.remove("closing"); }
      panel.style.opacity = ""; panel.style.transform = ""; panel.style.filter = ""; panel.style.clipPath = ""; };
    (a.finished || a).then(done, done);
  }
  btn.addEventListener("click", (e) => { e.stopPropagation(); if (isOpen()) close(); else openPanel(); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".notif-wrap") && isOpen()) close(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && isOpen()) { close(); btn.focus(); } });
  window.addEventListener("hashchange", () => { if (isOpen()) close(); });
  const tick = () => { if (document.visibilityState === "visible") load(false); };
  window.addEventListener("focus", tick);
  document.addEventListener("visibilitychange", tick);

  return {
    element() {                       // the same bell every time the top bar is drawn
      if (!timer) { timer = setInterval(tick, 10000); load(true); }
      return wrap;
    },
    reset() { data = null; clearInterval(timer); timer = 0; close(); count.classList.add("hidden"); },   // sign-out
  };
}
