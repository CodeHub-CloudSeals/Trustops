// Overview charts (2026-11-13): two interactive round charts built from the decision records (GET /v1/decisions-insights).
// Deliberately different from LedgerSight's bar / line charts. Plain SVG (no library), colours from the TrustOps palette.
// Arcs draw in one after another, the centre number counts up, and pointing at (or tabbing to) a slice or a legend row
// lifts that slice, dims the rest and shows its figures in the centre. Every chart has a text equivalent; motion is
// skipped when the viewer prefers reduced motion.
const NS = "http://www.w3.org/2000/svg";
const C = { allow: "#16A36A", esc: "#E9A23B", deny: "#E05252",
  pol: ["#172B4D", "#356AE6", "#7FA3F0", "#A9C6F5", "#D3E1F7"], track: "#E8EEF6" };
const calm = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

function s(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v);
  kids.flat().forEach((k) => k != null && n.append(k));
  return n;
}
const pct = (n, d) => (d ? Math.round((100 * n) / d) : 0);

function countUp(node, to, suffix = "") {
  if (calm() || !to) { node.textContent = `${to}${suffix}`; return; }
  const t0 = performance.now(), dur = 900;
  const step = (t) => {
    const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
    node.textContent = `${Math.round(to * e)}${suffix}`;
    if (k < 1 && node.isConnected !== false) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// A ring of slices. items: [{label, value, color, note}]; centre shows `idle` until a slice is pointed at.
function ring(el, { items, r, width, gap, idle, kind }) {
  const total = items.reduce((a, x) => a + x.value, 0);
  const len = 2 * Math.PI * r;
  let at = 0;
  const segs = items.map((x, i) => {
    const f = total ? x.value / total : 0;
    const g = items.filter((y) => y.value).length > 1 ? gap : 0;
    const c = s("circle", { r, cx: 70, cy: 70, fill: "none", stroke: x.color, "stroke-width": width,
      "stroke-linecap": kind === "pol" ? "butt" : "round", "stroke-dasharray": `${Math.max(0.01, f * len - g * len)} ${len}`,
      "stroke-dashoffset": -(at + g / 2) * len, transform: "rotate(-90 70 70)", class: "oc-seg", tabindex: x.value ? "0" : null,
      role: "img", "aria-label": `${x.label}: ${x.value}, ${pct(x.value, total)}%` });
    c.style.setProperty("--i", i);
    at += f;
    return x.value ? c : null;
  });
  const big = s("text", { x: 70, y: 70, class: "oc-big" }, "0");
  const small = s("text", { x: 70, y: 89, class: "oc-small" }, idle.small);
  const svg = s("svg", { viewBox: "0 0 140 140", class: `oc-svg oc-${kind}` },
    s("circle", { r: r + width / 2 + 7, cx: 70, cy: 70, fill: "none", class: "oc-orbit" }),
    s("circle", { r, cx: 70, cy: 70, fill: "none", stroke: C.track, "stroke-width": width }),
    segs, big, small);

  const dot = (color) => { const i = el("i", { "aria-hidden": "true" }); i.style.background = color; return i; };
  const bar = (x) => { const b = el("i", { "aria-hidden": "true" }); b.style.background = x.color; b.style.setProperty("--w", `${pct(x.value, total)}%`); return el("span", { class: "oc-bar" }, b); };
  const rows = items.map((x) => el("li", { tabindex: "0", title: x.label },
    dot(x.color), el("span", { class: "oc-l" }, x.label), el("b", {}, `${x.value}`), el("em", {}, `${pct(x.value, total)}%`),
    bar(x), x.note ? el("small", {}, x.note) : ""));
  rows.forEach((li, i) => li.style.setProperty("--i", i));
  const legend = el("ul", { class: "oc-legend" }, rows);

  let card = null;
  const show = (i) => {
    card ||= svg.closest(".oc-card");
    card?.classList.toggle("oc-hot", i != null);
    segs.forEach((c, j) => c?.classList.toggle("on", j === i));
    rows.forEach((li, j) => li.classList.toggle("on", j === i));
    if (i == null) { big.textContent = idle.big; small.textContent = idle.small; return; }
    big.textContent = idle.pct ? `${pct(items[i].value, total)}%` : String(items[i].value);
    small.textContent = idle.pct ? `${items[i].value} · ${items[i].short || items[i].label}` : `${pct(items[i].value, total)}% · ${items[i].short || items[i].label}`;
  };
  [segs, rows].forEach((list) => list.forEach((n, i) => {
    if (!n) return;
    n.addEventListener("mouseenter", () => show(i)); n.addEventListener("focus", () => show(i));
    n.addEventListener("mouseleave", () => show(null)); n.addEventListener("blur", () => show(null));
  }));
  // when the chart comes into view: count the centre up to its idle value
  const start = () => { const m = /^(\d+)(%?)$/.exec(idle.big); if (m) countUp(big, Number(m[1]), m[2]); else big.textContent = idle.big; };
  return { svg, legend, total, start };
}

export function overviewCharts(el, d) {
  const card = (cls, title, sub, fig, label, legend) => el("section", { class: `oc-card ${cls}` },
    el("div", { class: "oc-h" }, el("h3", {}, title), el("p", {}, sub)),
    el("div", { class: "oc-body" }, el("div", { class: "oc-fig", role: "img", "aria-label": label }, fig), legend));

  // 1. decision mix: every request, split by what TrustOps answered
  const m = d.mix, tot = m.ALLOW + m.ESCALATE + m.DENY;
  const mix = ring(el, { kind: "mix", r: 50, width: 16, gap: 0.014, idle: { big: String(tot), small: "decisions" }, items: [
    { label: "Allowed", short: "allowed", value: m.ALLOW, color: C.allow, note: "Went ahead without a person" },
    { label: "Sent to a person", short: "sent to a person", value: m.ESCALATE, color: C.esc, note: "Waited for an approver" },
    { label: "Blocked", short: "blocked", value: m.DENY, color: C.deny, note: "Stopped by a policy" }] });
  const c1 = card("oc-c-mix", "Decision mix", "What TrustOps answered for every request your applications made", mix.svg,
    `${tot} decisions: ${m.ALLOW} allowed, ${m.ESCALATE} sent to a person, ${m.DENY} blocked`, mix.legend);

  // 2. policies that decide most: which rule answered each request
  const pols = d.policies || [], ptot = pols.reduce((a, x) => a + x.count, 0), top = pols[0];
  const pol = ring(el, { kind: "pol", r: 50, width: 12, gap: 0.02,
    idle: { big: top ? `${pct(top.count, ptot)}%` : "–", small: top ? (top.id === "OTHER" ? "other rules" : top.id) : "no data", pct: true },
    items: pols.map((x, i) => ({ label: x.id === "OTHER" ? x.name : `${x.id} · ${x.name}`, short: x.id === "OTHER" ? "other" : x.id,
      value: x.count, color: C.pol[i % C.pol.length] })) });
  const c2 = card("oc-c-pol", "Policies that decide most", "Which rule answered each request", pol.svg,
    pols.map((x) => `${x.id} ${x.count}`).join(", ") || "No decisions yet", pol.legend);

  // the arcs, bars and counters start when the row scrolls into view (CSS animations wait for .oc-in)
  const row = el("div", { class: "oc-row" }, c1, c2);
  const go = () => { row.classList.add("oc-in"); mix.start(); pol.start(); };
  if (calm() || !("IntersectionObserver" in window)) go();
  else { const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { io.disconnect(); go(); } }, { threshold: 0.25 }); io.observe(row); }
  return row;
}
