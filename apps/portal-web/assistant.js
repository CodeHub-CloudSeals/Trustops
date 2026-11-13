// TrustTwin - Your Governance Digital Twin: the TrustOps counterpart of LedgerSight's FinTwin (same sidebar button,
// same right-hand panel, same Ctrl+K). Read-only: answers come only from the server (POST /v1/assistant/ask), built
// from this workspace's decision records, and list the records they used. Nothing is generated or changed here.
export function registerAssistant({ el, api, state }) {
  const NAME = "TrustTwin", SUB = "Your Governance Digital Twin";
  const svg = (paths, attrs = {}) => {
    const s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true");
    for (const [k, v] of Object.entries(attrs)) s.setAttribute(k, v);
    for (const p of paths) {
      const n = document.createElementNS(s.namespaceURI, "path"); n.setAttribute("d", p.d || p);
      if (p.cls) n.setAttribute("class", p.cls);
      if (p.fill) { n.setAttribute("fill", "currentColor"); n.setAttribute("stroke", "none"); }
      s.append(n);
    }
    return s;
  };
  const BUBBLE = "M20 11.4a7.6 7.6 0 0 1-11.3 6.6L4 19.6l1.6-4.4A7.6 7.6 0 1 1 20 11.4z";
  const SPARK = "M12.2 7.6l.85 2.15 2.15.85-2.15.85-.85 2.15-.85-2.15-2.15-.85 2.15-.85z";
  const STATUS = { ANSWERED: ["gov-green", "Answered"], ATTENTION: ["gov-red", "Needs attention"], REFUSED: ["gov-amber", "Read-only"],
    NO_DATA: ["gov-neutral", "No data"], NO_MATCH: ["gov-neutral", "No match"], ERROR: ["gov-red", "Error"] };

  // ---- sidebar button (bottom of the menu) ----
  const openBtn = el("button", { type: "button", id: "ask-open", class: "side-ask", "aria-expanded": "false", "aria-controls": "ask-drawer",
    "aria-label": `${NAME} - ${SUB} (read-only)`, title: `${NAME} · Ctrl K` },
    el("span", { class: "sa-ico", "aria-hidden": "true" }, svg([BUBBLE, { d: SPARK, cls: "sa-spark", fill: true }])),
    el("span", { class: "sa-t" }, el("b", {}, NAME), el("span", {}, SUB)),
    el("kbd", { class: "sa-k" }, "Ctrl K"));
  const foot = el("div", { class: "sidefoot" }, openBtn, el("div", { id: "app-version", class: "small" }, "TrustOps"));

  // ---- the panel ----
  const out = el("div", { id: "ask-out" });
  const scroll = el("div", { class: "drawer-body", id: "ask-scroll" },
    el("div", { id: "ask-welcome", class: "qa ask-welcome" }, el("div", { class: "a-bubble" }, `Hi, I'm ${NAME}! How can I help you?`)), out);
  const chips = el("div", { id: "ask-chips", class: "chips" });
  const input = el("input", { id: "ask-q", placeholder: `Ask ${NAME} a question…`, maxlength: 500, "aria-label": "Question", autocomplete: "off" });
  const askBtn = el("button", { id: "ask-btn", class: "primary", type: "button" }, "Ask");
  const closeBtn = el("button", { id: "ask-close", class: "iconbtn", type: "button", "aria-label": `Close ${NAME}` }, svg(["M6 6l12 12M18 6L6 18"]));
  const drawer = el("aside", { id: "ask-drawer", class: "drawer", role: "dialog", "aria-modal": "false", "aria-labelledby": "ask-title", "aria-hidden": "true" },
    el("div", { class: "drawer-head" },
      el("div", { class: "drawer-ico", "aria-hidden": "true" }, svg(["M21 12a8.5 8.5 0 0 1-12.3 7.6L3 21l1.4-5.4A8.5 8.5 0 1 1 21 12z"])),
      el("div", { class: "grow" }, el("div", { class: "drawer-title", id: "ask-title" }, `${NAME} - ${SUB}`),
        el("div", { class: "drawer-sub" }, "Read-only · answers from your decision records")),
      closeBtn),
    scroll, el("div", { class: "drawer-foot" }, chips, el("div", { class: "ask-row" }, input, askBtn)));
  drawer.inert = true;

  let log = [], tenant = null, isOpen = false, suggestions = null;
  const chip = (t) => el("button", { class: "chip", type: "button", onclick: () => { input.value = t; ask(); } }, t);
  const goTo = (href) => { close(); if (href) location.hash = href; };

  function bubble(a) {
    const [cls, label] = STATUS[a.status] || STATUS.NO_MATCH;
    const links = a.links || [];
    return el("div", { class: "a-bubble" },
      el("div", { class: "row" }, el("span", { class: `gov-pill ${cls}` }, el("span", { class: "gov-dot" }), label)),
      el("div", { class: "a" }, a.answer),
      a.rows && a.rows.length ? el("div", { class: "tablewrap" }, el("table", {},
        el("thead", {}, el("tr", {}, a.columns.map((c) => el("th", {}, c)))),
        el("tbody", {}, a.rows.map((r, i) => el("tr", {}, r.map((c, j) => el("td", {}, j === 0 && links[i]
          ? el("button", { class: "linkbtn", type: "button", title: "Open this in TrustOps", onclick: () => goTo(links[i]) }, String(c))
          : String(c)))))))) : "",
      a.suggestions && a.suggestions.length ? el("div", { class: "chips" }, a.suggestions.map(chip)) : "",
      a.citations && a.citations.length ? el("div", { class: "cites" }, "Sources", el("ul", { class: "plain" }, a.citations.map((c) => el("li", {},
        el("button", { class: "linkbtn", type: "button", title: "Open this record", onclick: () => goTo(c.link) }, c.ref), ` · ${c.source}`,
        c.sha256 ? el("span", { class: "mono" }, ` · sha256 ${c.sha256.slice(0, 12)}…`) : "")))) : "");
  }
  function renderLog() {
    out.replaceChildren(...log.map(({ q, a }) => el("div", { class: "qa" }, el("div", { class: "q-bubble" }, q),
      a ? bubble(a) : el("div", { class: "a-bubble" }, el("span", { class: "typing", "aria-label": `${NAME} is answering` }, el("i"), el("i"), el("i"))))));
    scroll.scrollTop = scroll.scrollHeight;
  }
  async function loadChips() {
    if (!suggestions) { try { suggestions = (await api("/v1/assistant/suggestions")).suggestions; } catch { suggestions = []; } }
    chips.replaceChildren(...suggestions.map(chip));
  }
  async function ask() {
    const q = input.value.trim(); if (!q) return;
    input.value = "";
    const item = { q, a: null }; log.push(item); renderLog();
    try { item.a = await api("/v1/assistant/ask", { method: "POST", body: { question: q } }); }
    catch (e) { item.a = { status: "ERROR", answer: e.message || "TrustOps could not answer just now.", rows: [], citations: [] }; }
    renderLog();
  }
  function set(open) {
    isOpen = open;
    drawer.classList.toggle("open", open); drawer.setAttribute("aria-hidden", String(!open)); drawer.inert = !open;
    openBtn.setAttribute("aria-expanded", String(open)); openBtn.classList.toggle("on", open);
    document.body.classList.toggle("ask-open", open);
  }
  function open() { set(true); loadChips(); renderLog(); setTimeout(() => input.focus(), 120); }
  function close() { if (!isOpen) return; set(false); openBtn.focus(); }
  const usable = () => !!(state.me && state.me.tenant && document.body.classList.contains("workspace-ready"));

  openBtn.addEventListener("click", () => (isOpen ? close() : open()));
  closeBtn.addEventListener("click", close);
  askBtn.addEventListener("click", ask);
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") ask(); });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k" && usable()) { e.preventDefault(); isOpen ? input.focus() : open(); }
    else if (e.key === "Escape" && isOpen && !document.querySelector("dialog[open]")) close();
  });

  return {
    // Called on every render: puts the button under the menu (once) and the panel on the page. Only for people in a
    // customer workspace; the conversation starts again when the workspace or the person changes.
    mount(header) {
      const key = state.me && state.me.tenant ? `${state.me.sub}|${JSON.stringify(state.me.tenant)}` : null;
      if (key !== tenant) { log = []; suggestions = null; tenant = key; }
      if (!usable()) { foot.remove(); drawer.remove(); set(false); return; }
      if (foot.parentNode !== header) header.append(foot);
      if (!drawer.isConnected) document.body.append(drawer);
    },
    reset() { set(false); log = []; suggestions = null; tenant = null; foot.remove(); drawer.remove(); },
  };
}
