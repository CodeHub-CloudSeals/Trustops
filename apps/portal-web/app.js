import { registerGovernanceConsole } from "./governance-console.js?v=gc-2026-11-13d";
import { registerTrustBoundary } from "./trust-boundary.js?v=tb-2026-11-13t";
import { registerApplications } from "./applications.js?v=access-2026-11-13f";
// TAAD portal: dependency-free ES module. All dynamic text goes through textContent (no innerHTML).
const $ = (s, r = document) => r.querySelector(s);
const main = $("#main"), nav = $("#nav"), who = $("#who"), contextBar = $("#contextBar");
const state = { token: sessionStorage.getItem("taad_token"), me: null, cfg: { mode: "oidc", oidc: {} } };
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else if (v !== false && v != null) n.setAttribute(k, v);
  }
  for (const c of kids.flat()) n.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
  return n;
}
function displayAISystemName(name) {
  return String(name || "").replace(/^\s*(?:DEMO\s*\|\s*|SYNTHETIC SAMPLE\s*[—–-]\s*)/i, "");
}
const say = (m) => { $("#live").textContent = m; };
function tenantLabel(tenant) {
  if (state.cfg.mode === "dev") {
    const localNames = { "t-bank": "T-Bank", "t-health": "T-Health", "t-logistics": "T-Logistics" };
    if (localNames[tenant?.tenant_id]) return localNames[tenant.tenant_id];
  }
  return tenant?.name || tenant?.tenant_id || "Customer workspace";
}
function toast(msg, bad = false) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast" + (bad ? " err" : ""); t.hidden = false;
  say(msg); clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, 5000);
}

async function api(path, { method = "GET", body, headers = {}, raw = false, idem = false } = {}) {
  const h = { Authorization: `Bearer ${state.token}`, ...headers };
  if (body !== undefined && !(body instanceof ArrayBuffer)) h["Content-Type"] = "application/json";
  if (idem) h["Idempotency-Key"] = crypto.randomUUID();
  const r = await fetch(path, { method, headers: h, body: body === undefined ? undefined : body instanceof ArrayBuffer ? body : JSON.stringify(body) });
  if (raw) return r;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    // An expired or revoked sign-in (Google ID tokens last one hour): return to the sign-in page instead of failing silently.
    if (r.status === 401 && state.token && !path.startsWith("/v1/auth/")) { sessionStorage.removeItem("taad_token"); state.token = null; state.me = null; setTimeout(render, 0); }
    const e = new Error(data.message || r.statusText); e.status = r.status; e.code = data.code; throw e;
  }
  return data;
}
// Advisory agent output: always labelled, always plain text, never saved automatically.
function advisoryBox(title, lines) {
  return el("div", { class: "card advisory", role: "status" }, el("span", { class: "tag medium" }, "ADVISORY · NOT SAVED"), el("strong", {}, ` ${title}`),
    el("ul", {}, lines.map((l) => el("li", {}, l))));
}
const agentButton = (label, out, run) => el("button", { class: "secondary", onclick: safe(async (e) => {
  const b = e.currentTarget; b.disabled = true;
  try { out.replaceChildren(await run()); } catch (err) { out.replaceChildren(el("p", { class: "help" }, `Agent unavailable: ${err.message}`)); } finally { b.disabled = false; }
}) }, label);
const safe = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

// ---------- auth ----------
async function sha256Hex(buf) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", buf))].map((b) => b.toString(16).padStart(2, "0")).join(""); }
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function oidcLogin() {
  const o = state.cfg.oidc;
  if (![o.authorize_url, o.token_url, o.client_id, o.redirect_uri].every(Boolean)) {
    throw new Error("Organisation sign-in is not configured. Contact your CloudSeals administrator.");
  }
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64u(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const st = b64u(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem("pkce", JSON.stringify({ verifier, st }));
  location.href = `${o.authorize_url}?response_type=code&client_id=${encodeURIComponent(o.client_id)}&redirect_uri=${encodeURIComponent(o.redirect_uri)}&scope=${encodeURIComponent(o.scope)}&code_challenge=${challenge}&code_challenge_method=S256&state=${st}${o.provider === "google" ? "&prompt=select_account" : ""}`;
}
async function oidcCallback(params) {
  if (params.has("error") || !params.get("code")) {
    sessionStorage.removeItem("pkce");
    throw new Error("Organisation sign-in was cancelled or could not be completed.");
  }
  const saved = JSON.parse(sessionStorage.getItem("pkce") || "{}");
  if (!saved.st || saved.st !== params.get("state")) throw new Error("Invalid login state");
  const o = state.cfg.oidc;
  const r = await fetch(o.token_url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", client_id: o.client_id, code: params.get("code"), redirect_uri: o.redirect_uri, code_verifier: saved.verifier }) });
  if (!r.ok) throw new Error("Sign-in failed");
  state.token = (await r.json()).access_token;
  sessionStorage.setItem("taad_token", state.token); sessionStorage.removeItem("pkce");
  history.replaceState({}, "", location.pathname);
}
function logout() {
  sessionStorage.removeItem("taad_token"); sessionStorage.removeItem("pkce"); state.token = null; state.me = null;
  const o = state.cfg.oidc;
  if (state.cfg.mode === "oidc" && o.logout_url && o.client_id && o.redirect_uri) {
    const url = new URL(o.logout_url); url.searchParams.set("client_id", o.client_id); url.searchParams.set("logout_uri", o.redirect_uri);
    location.assign(url.href); return;
  }
  render();
}

async function loginView() {
  document.body.classList.remove("workspace-ready");
  nav.replaceChildren(); who.textContent = "";
  if (state.cfg.mode === "dev") {
    const users = await fetch("/v1/dev/users").then((r) => r.ok ? r.json() : { items: [] }).catch(() => ({ items: [] }));
    const localAdmin = users.items.find((u) => u.sub === "admin@t-bank");
    if (localAdmin?.token) {
      state.token = localAdmin.token;
      sessionStorage.setItem("taad_token", localAdmin.token);
      await render();
      return;
    }
  }
  document.body.classList.add("login-page");
  const point = (t) => el("li", {}, t);
  const step = (n, t, d) => el("li", {}, el("b", {}, n), el("div", {}, el("strong", {}, t), el("span", {}, d)));
  const visual = el("section", { class: "lg-visual lg-light" },
    el("div", { class: "lgl-brand" }, el("img", { src: "images/logo.svg", alt: "" }), el("span", {}, "CloudSeals")),
    el("div", { class: "lgl-copy" },
      el("span", { class: "lgl-eyebrow" }, "TrustOps · AI governance"),
      el("h2", {}, "Every AI action.", el("br"), el("em", {}, "Checked before it happens.")),
      el("p", {}, "Your applications ask TrustOps before they act. Routine work goes through, risky work waits for the right person, and every decision is kept as evidence.")),
    el("div", { class: "lgl-stage", "aria-hidden": "true" },
      el("div", { class: "lgl-card" },
        el("div", { class: "lgl-row" }, el("span", { class: "lgl-app" }, "LedgerSight"), el("span", { class: "lgl-pill esc" }, "Waiting for approval")),
        el("strong", { class: "lgl-title" }, "Partial receipt · $3,000.00"),
        el("span", { class: "lgl-muted" }, "Invoice INV-2104 open $5,000.00 · $2,000.00 still owed"),
        el("div", { class: "lgl-meta" }, el("span", {}, "Rule FIN-00"), el("span", {}, "Reviewer: Approver")),
        el("div", { class: "lgl-actions" }, el("span", { class: "lgl-btn" }, "Approve"), el("span", { class: "lgl-btn ghost" }, "Reject"))),
      el("ul", { class: "lgl-steps" },
        step("1", "Ask", "The application sends the action"),
        step("2", "Decide", "Allow, send for review, or deny"),
        step("3", "Prove", "Each decision is hash-chained"))));
  const card = el("section", { class: "lg-card" },
    el("img", { src: "images/logo.svg", alt: "", class: "lg-logo" }),
    el("span", { class: "lg-eyebrow dark" }, "TrustOps"),
    el("h1", {}, "Sign in"),
    el("p", { class: "lg-sub" }, "Use your organisation account."));
  if (state.cfg.mode === "oidc") {
    const o = state.cfg.oidc;
    const ready = [o.authorize_url, o.token_url, o.client_id, o.redirect_uri].every(Boolean);
    card.append(el("button", { class: "lg-btn", disabled: !ready, onclick: safe(oidcLogin) },
      o.provider === "google" ? "Sign in with Google" : "Continue with organisation sign-in"),
      ready ? "" : el("p", { class: "lg-note" }, "Sign-in is not configured yet. Contact your CloudSeals administrator."));
  } else {
    card.append(el("p", { class: "lg-note" }, "The local workspace could not be loaded. Check the API and seed data."));
  }
  const foot = el("p", { class: "lg-foot" }, "Invitation-only access · Your organisation manages users and roles");
  main.replaceChildren(el("div", { class: "lg-wrap" }, visual, el("div", { class: "lg-side" }, card, foot)));
}

// ---------- routing ----------
const routes = {};
registerApplications({ routes, main, el, state, toast, api });
function go(hash) { location.hash = hash; }
routes.register = async () => {
  const industries = ["Banking", "Investment", "Insurance", "Healthcare", "Logistics", "Industrial", "Government", "Other"];
  const jurisdictions = ["UK", "EU", "US", "Other"];
  const form = el("form", { class: "registration-form", onsubmit: safe(async (event) => {
    event.preventDefault(); const data = new FormData(form);
    await fetch("/v1/registration-requests", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ organisation_name: data.get("organisation"), work_email: data.get("email"), industry: data.get("industry"),
        jurisdiction: data.getAll("jurisdiction"), engagement_reference: data.get("engagement") }) }).then(async (response) => {
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.message || "Registration request could not be submitted.");
      main.replaceChildren(moduleFrame("ACCESS REQUEST", "Request received", "Your request is pending review. We will contact you through your organisation email when access is ready."));
    });
  }) },
  el("label", { for: "reg-organisation" }, "Organisation name"), el("input", { id: "reg-organisation", name: "organisation", required: true, maxlength: 200 }),
  el("label", { for: "reg-email" }, "Work email"), el("input", { id: "reg-email", name: "email", type: "email", required: true }),
  el("label", { for: "reg-industry" }, "Industry"), el("select", { id: "reg-industry", name: "industry" }, industries.map((industry) => el("option", { value: industry.toLowerCase() }, industry))),
  el("label", { for: "reg-jurisdiction" }, "Data jurisdictions"), el("select", { id: "reg-jurisdiction", name: "jurisdiction", multiple: true, required: true },
    jurisdictions.map((jurisdiction) => el("option", { value: jurisdiction, selected: jurisdiction === "UK" }, jurisdiction))),
  el("label", { for: "reg-engagement" }, "Engagement reference"), el("input", { id: "reg-engagement", name: "engagement", required: true, maxlength: 200 }),
  el("p", { class: "module-note" }, "Requests are reviewed before a tenant workspace is activated."),
  el("div", { class: "row" }, el("button", {}, "Submit access request"), el("a", { class: "secondary btn", href: "/portal/" }, "Back to sign in")));
  main.replaceChildren(moduleFrame("CLOUDSEALS · CUSTOMER ONBOARDING", "Request workspace access", "Tell us about your organisation and approved engagement.", form));
};
async function render() {
  if (!state.token) {
    if (location.hash === "#/register") return routes.register();
    return loginView();
  }
  if (!state.me) { try { state.me = await api("/v1/me"); } catch { return logout(); } }
  document.body.classList.add("workspace-ready"); document.body.classList.remove("login-page");
  const staff = state.me.is_staff;
  const roles = state.me.roles;
  const hasAnyRole = (...allowed) => roles.some((role) => allowed.includes(role));
  const canUseCases = hasAnyRole("cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer");
  const canUseAdminMetrics = hasAnyRole("cloudseals_admin", "cloudseals_platform_ops", "cloudseals_reviewer", "cloudseals_assessor");
  const [, name, arg] = (location.hash || "#/dashboard").split("/");
  const navIcons = { dashboard: "🏠", assessments: "📋", "use-cases": "◇", trustops: "⇄", "agent-flow": "◎", reports: "📊", approvals: "✓", demo: "▷", queue: "▣", "ledger-sight": "🔄", "ai-agents": "✦", "trust-boundary": "⛨", "governance-reviews": "✓", "run-exceptions": "⚠", "connected-systems": "⇄", "governance-evidence": "▤", "workflow-packs": "▦" };
  const activeRoute = name === "assessment" ? "assessments" : name === "approval" ? "approvals" : name;
  const NAV_SVG = { dashboard: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z", "approvals": "M9 11l3 3 8-8M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9",
    risk: "M12 3l9 16H3zM12 10v4M12 17h.01", decisions: "M4 6h16M4 12h10M4 18h6M17 15l3 3-3 3", policies: "M12 3l8 3v6c0 4.6-3.4 8.3-8 9-4.6-.7-8-4.4-8-9V6z", authority: "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1", cases: "M3 7h18v13H3zM8 7V4h8v3", queue: "M4 6h16M4 12h16M4 18h10", "governance-reports": "M4 20V10M10 20V4M16 20v-7M22 20H2", "trust-boundary": "M12 3l8 3v6c0 4.6-3.4 8.3-8 9-4.6-.7-8-4.4-8-9V6z", "ai-agents": "M6 6h12v12H6zM9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4",
    "evidence": "M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8M8 17h5", "workflow-packs": "M12 2l9 5-9 5-9-5zM3 12l9 5 9-5M3 17l9 5 9-5",
    "connected-systems": "M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1", "governance-team": "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8" };
  const navIco = (route) => { const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true");
    const pth = document.createElementNS(svg.namespaceURI, "path"); pth.setAttribute("d", NAV_SVG[route] || NAV_SVG.dashboard); svg.append(pth); return el("span", { class: "nav-icon" }, svg); };
  const link = ([route, label]) => el("a", { href: `#/${route}`, class: "module-menu-link", "aria-current": activeRoute === route || (route === "connected-systems" && activeRoute === "add-application") ? "page" : null }, navIco(route), label);
  const group = (label, items) => el("details", { class: "module-menu-group", open: label === "Resources" && items.some(([route]) => route === activeRoute) }, el("summary", {}, label, el("span", { "aria-hidden": "true" }, "⌄")),
    el("div", { class: "module-menu-popover" }, items.map(link)));
  const adminItems = [
    ...(canUseAdminMetrics ? [["admin", "Portfolio"]] : []),
    ["workspaces", "Customer workspaces"],
    ...(hasAnyRole("cloudseals_admin") ? [["users", "Users"], ["registrations", "Registrations"]] : []),
    ...(hasAnyRole("cloudseals_admin", "cloudseals_platform_ops", "auditor_readonly") ? [["activity", "Audit logs"], ["service-health", "Service health"]] : []),
    ...(hasAnyRole("cloudseals_admin") ? [["tenant-settings", "Tenant settings"]] : []),
  ];
  nav.replaceChildren(
    el("span", { class: "nav-section-label" }, "Workspace"),
    link(["dashboard", "Overview"]), link(["approvals", "Approvals"]), link(["decisions", "Decisions"]), link(["risk", "Risk"]),
    el("span", { class: "nav-section-label" }, "Governance"),
    link(["policies", "Policies"]), link(["authority", "Authority"]), link(["evidence", "Evidence"]),
    el("span", { class: "nav-section-label" }, "Outputs"),
    link(["governance-reports", "Reports"]),
    el("span", { class: "nav-section-label" }, "Admin"),
    link(["connected-systems", "Applications"]),
    hasAnyRole("customer_admin", "cloudseals_admin") ? link(["governance-team", "Team & access"]) : "",
    "");   // CloudSeals staff pages (cases, review queue, administration) stay reachable by URL only
  who.replaceChildren(state.cfg.mode === "dev"
    ? el("span", { class: "tag" }, state.me.tenant ? `${tenantLabel(state.me.tenant)} workspace` : "CloudSeals staff")
    : el("span", { class: "who-email" }, state.me.email || state.me.sub), state.cfg.mode === "dev" ? "" : el("button", { class: "secondary", onclick: logout }, "Sign out"));
  contextBar.replaceChildren(
    el("div", { class: "workspace-breadcrumb" }, el("span", {}, "Workspace"), el("span", { "aria-hidden": "true" }, "/"), el("strong", {}, ({dashboard:"Overview",assessments:"Assessments",assessment:"Assessment", "agent-flow":"Assessment process",trustops:"Overview",agents:"Assessment team",reports:"Reports",demo:"Demo Studio", "ledger-sight":"LedgerSight POC"})[name] || name.replaceAll("-", " "))),
    el("div", { class: "workspace-context-actions" }));
  contextBar.scrollLeft = 0;
  // Pages that only CloudSeals staff (or specific staff roles) may use: show a clear message instead of an empty shell.
  const CASE_ROLES = ["cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer"], AUDIT = ["cloudseals_admin", "cloudseals_platform_ops", "auditor_readonly"];
  const ROUTE_ROLES = { cases: CASE_ROLES, case: CASE_ROLES, activity: AUDIT, "service-health": AUDIT, workspaces: [...CASE_ROLES, ...AUDIT], workspace: [...CASE_ROLES, ...AUDIT],
    "ledger-sight": ["customer_admin", "customer_architect", "customer_risk", "customer_controller", "cloudseals_assessor", "cloudseals_admin"],
    queue: ["cloudseals_admin", "cloudseals_platform_ops", "cloudseals_reviewer", "cloudseals_assessor"], registrations: ["cloudseals_admin"], users: ["cloudseals_admin"], admin: ["cloudseals_admin", "cloudseals_platform_ops", "cloudseals_reviewer", "cloudseals_assessor"] };
  if (ROUTE_ROLES[name] && !roles.some((r) => ROUTE_ROLES[name].includes(r))) {
    main.replaceChildren(moduleFrame("ACCESS", "You do not have access to this page", "This page is for CloudSeals staff. If you need it, ask a CloudSeals administrator to change your role.", el("p", {}, el("a", { class: "btn", href: "#/dashboard" }, "Back to overview"))));
    return;
  }
  const view = routes[name] || routes.assessments;
  main.replaceChildren(el("p", {}, "Loading…"));
  try {
    await view(arg);
  } catch (e) { main.replaceChildren(el("div", { class: "card" }, el("h2", {}, "Something went wrong"), el("p", {}, e.message))); }
  main.focus();
}
window.addEventListener("hashchange", render);

const dl = async (url, name) => {
  const r = await api(url, { raw: true });
  if (!r.ok) return toast((await r.json()).message, true);
  const a = el("a", { href: URL.createObjectURL(await r.blob()), download: name }); a.click(); URL.revokeObjectURL(a.href);
};

// ---------- assessments ----------
const SAMPLE_AI_REGISTER = "SYNTHETIC SAMPLE ONLY — Example Bank, not a real customer.\nAI Register. Our credit scoring model assigns loan applicants a score and decides approvals automatically. The chatbot answers customer questions about accounts.\nCredit scoring owner: Lending team. Inputs: application details and repayment history. Human review: appeals only.\nChatbot owner: Customer support. Inputs: approved account FAQs. It gives information and cannot change accounts.\nUnknown: model test results, retention periods and approval records have not been supplied.\n";
const SAMPLE_AI_POLICY = "SYNTHETIC SAMPLE ONLY — Example Bank.\nAI policy example: customer support staff review chatbot complaints. Loan applicants may request a human review. Access is limited to authorised teams.\nMissing evidence: no signed model validation report, retention schedule or approval log is supplied in this sample. Missing evidence does not prove a control is absent.\n";
function sampleDownload(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const link = el("a", { href: url, download: name }); link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function assessmentGuide(canCreate = false) {
  return el("section", { class: "card assessment-guide" }, el("span", { class: "eyebrow" }, "WHY CLOUDSEALS"),
    el("h3", {}, "Understand your AI. Find the gaps. Know what to improve."),
    el("p", {}, "We help you understand how your organisation uses AI, which controls are evidenced, and what needs further review. You receive a reviewed assessment report and an improvement roadmap."),
    el("div", { class: "document-examples" },
      el("div", {}, el("strong", {}, "You share"), el("p", { class: "help" }, "Your AI list, system overview, policies and test or audit records. Start with what you have.")),
      el("div", {}, el("strong", {}, "We assess & review"), el("p", { class: "help" }, "Identify documented AI uses, check evidence and review potential gaps with a CloudSeals reviewer.")),
      el("div", {}, el("strong", {}, "You receive"), el("p", { class: "help" }, "Reviewed findings, maturity results and prioritised next actions. Final reports appear after approval."))),
    el("details", { class: "sample-drawer" }, el("summary", {}, "See sample documents"),
      el("p", { class: "help" }, "SAMPLE DATA: these examples explain the process. They are not customer results or a compliance certificate."),
      el("div", { class: "row" },
        el("button", { class: "secondary", type: "button", onclick: () => sampleDownload("SAMPLE-ai-register.txt", SAMPLE_AI_REGISTER) }, "Download sample AI register"),
        el("button", { class: "secondary", type: "button", onclick: () => sampleDownload("SAMPLE-ai-policy.txt", SAMPLE_AI_POLICY) }, "Download sample policy")),
      canCreate ? el("button", { type: "button", onclick: safe(async (e) => {
        const button = e.currentTarget; button.disabled = true; button.textContent = "Preparing sample assessment…";
        try {
          const a = await api("/v1/assessments", { method: "POST", idem: true, body: { ai_system_name: "SYNTHETIC SAMPLE — Example Bank", industry: "banking", questionnaire_version: "1.0.0" } });
          for (const [filename, text] of [["SAMPLE-ai-register.txt", SAMPLE_AI_REGISTER], ["SAMPLE-ai-policy.txt", SAMPLE_AI_POLICY]]) {
            const buf = new TextEncoder().encode(text).buffer;
            const g = await api(`/v1/assessments/${a.assessment_id}/evidence/upload-url`, { method: "POST", body: { filename, content_type: "text/plain", file_size_bytes: buf.byteLength, claimed_sha256: await sha256Hex(buf) } });
            const uploaded = await api(g.upload_url, { method: "PUT", body: buf, headers: { "Content-Type": "application/octet-stream" } });
            if (uploaded.state !== "clean") throw new Error("Sample upload did not pass the safety check. Open the sample assessment to retry.");
          }
          toast("Separate sample assessment created. Your customer assessments were not changed."); go(`#/assessment/${a.assessment_id}`);
        } finally { button.disabled = false; button.textContent = "Try sample data in a separate assessment"; }
      }) }, "Try sample data in a separate assessment") : ""));
}

routes.assessments = async () => {
  const { items } = await api("/v1/assessments");
  const canCreate = !state.me.is_staff && state.me.roles.some((r) => ["customer_admin", "customer_architect"].includes(r));
  const canStartCase = state.me.roles.some((r) => ["cloudseals_admin", "cloudseals_assessor"].includes(r));
  const startAction = canCreate
    ? el("a", { class: "btn", href: "#new-assessment", onclick: (e) => { e.preventDefault(); form.scrollIntoView({ behavior: "smooth", block: "center" }); $("#nm", form).focus({ preventScroll: true }); } }, "+ New assessment")
    : canStartCase ? el("a", { class: "btn", href: "#/cases" }, "+ Start customer case") : "";
  const rows = items.map((a) => el("tr", {}, el("td", {}, el("a", { href: `#/assessment/${a.assessment_id}` }, displayAISystemName(a.ai_system_name))), el("td", {}, a.industry), el("td", {}, el("span", { class: `tag ${a.status === "In progress" ? "medium" : "ok"}` }, a.status)), el("td", {}, a.questionnaire_version)));
  const form = el("form", { id: "assessment-create-form", class: "module-panel assessment-create-form", onsubmit: safe(async (e) => {
    e.preventDefault(); const f = new FormData(e.target);
    const a = await api("/v1/assessments", { method: "POST", idem: true, body: { ai_system_name: f.get("name"), industry: f.get("industry"), questionnaire_version: "1.0.0" } });
    go(`#/assessment/${a.assessment_id}`);
  }) }, el("h3", {}, "New assessment"),
  el("label", { for: "nm" }, "AI system name"), el("input", { id: "nm", name: "name", required: true, maxlength: 200 }),
  el("label", { for: "ind" }, "Industry"), el("select", { id: "ind", name: "industry" }, ["banking", "investment", "insurance", "healthcare", "logistics", "industrial", "government", "other"].map((i) => el("option", { value: i }, i))),
  el("p", {}, el("button", {}, "Create assessment")));
  main.replaceChildren(moduleFrame("YOUR WORKSPACE", "AI assessments", "Describe your AI system, share evidence and track your reviewed report.",
    el("details",{class:"module-panel"},el("summary",{},"What should I upload? See examples"),assessmentGuide(canCreate)),
    el("section", { class: "module-metrics compact" }, [["Assessments", items.length], ["In progress", items.filter((a) => a.status === "In progress").length], ["Submitted", items.filter((a) => a.status !== "In progress").length]].map(([label, value]) => el("article", {}, el("span", {}, label), el("strong", {}, String(value))))),
    !canCreate && state.me.is_staff ? el("section", { class: "assessment-start-note", "aria-label": "How CloudSeals staff start a customer assessment" },
      el("div", {}, el("strong", {}, canStartCase ? "Starting an assessment for a customer?" : "Need to start a customer assessment?"),
        el("p", {}, canStartCase ? "Open a customer case first. The customer then creates the assessment in their own workspace, keeping their answers and evidence in the right account." : "A CloudSeals assessor or administrator can open the customer case. The customer creates the assessment in their own workspace.")),
      canStartCase ? el("a", { class: "btn", href: "#/cases" }, "Go to Cases →") : "") : "",
    canCreate ? form : "",
    el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading assessment-list-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "YOUR WORKSPACE"), el("h3", {}, "Assessments")), startAction),
      rows.length ? el("div", { class: "table-wrap" }, el("table", { class: "module-table" }, el("thead", {}, el("tr", {}, ["AI system", "Industry", "Status", "Questionnaire"].map((h) => el("th", { scope: "col" }, h)))), el("tbody", {}, rows)))
        : el("div", { class: "empty-state" }, canCreate ? "Start by creating an assessment for an AI system." : "No assessments have been assigned to this workspace."))));
};

routes.assessment = async (aid) => {
  const a = await api(`/v1/assessments/${aid}`);
  const ctx = { aid, a, scopeType: "org", scopeId: "org", section: null, answers: {}, evidence: [] };
  const wrap = el("div", { class: "module-page assessment-page" });
  main.replaceChildren(wrap);
  const draw = async () => {
    ctx.a = await api(`/v1/assessments/${aid}`);
    ctx.evidence = (await api(`/v1/assessments/${aid}/evidence`)).items;
    ctx.answers = Object.fromEntries((await api(`/v1/assessments/${aid}/answers`)).items.map((x) => [`${x.scope_id}|${x.question_id}`, x]));
    const qs = (await api(`/v1/assessments/${aid}/questions?scope_id=${encodeURIComponent(ctx.scopeId)}&scope_type=${ctx.scopeType}`)).questions;
    const sections = [...new Set(qs.map((q) => q.section))];
    if (!sections.includes(ctx.section)) ctx.section = sections[0];
    const p = ctx.a.progress, frozen = ctx.a.status !== "In progress";
    const recommendedStep = frozen ? "review" : ctx.a.progress.required_answered > 0 ? "questions" : ctx.evidence.length ? "questions" : "details";
    if (!ctx.flowStep) ctx.flowStep = recommendedStep;
    if (frozen) ctx.flowStep = "review";
    const activeStep = ctx.flowStep;
    const setStep = (step) => { ctx.flowStep = step; draw(); window.scrollTo({ top: 0, behavior: "smooth" }); };
    wrap.replaceChildren(
      el("div", { class: "module-page-heading" }, el("span", { class: "eyebrow" }, "YOUR AI ASSESSMENT"), el("h2", {}, displayAISystemName(ctx.a.ai_system_name)),
        el("p", {}, "Share your documents, answer a few questions, then send your assessment for review."), el("span", { class: `tag ${frozen ? "ok" : "medium"}` }, ctx.a.status)),
      el("details", {class:"module-panel assessment-introduction"}, el("summary",{},"Assessment guide & sample documents"), assessmentGuide(!state.me.is_staff && state.me.roles.some((r) => ["customer_admin", "customer_architect"].includes(r)))),
      state.cfg.assessment_model === "demo" ? el("p", { class: "assessment-model-notice", role: "status" }, "AI analysis is not connected in this workspace. Connect an approved AI service to generate findings from uploaded evidence; reports require reviewer approval.")
        : state.cfg.assessment_model === "unavailable" ? el("p", { class: "assessment-model-notice", role: "status" }, "Document AI analysis is not connected yet. You can upload documents and complete the questionnaire for review; automatic document findings and the diagnostic roadmap require the AI service. Application evidence and its reviewed report are available separately.") : "",
      el("nav", { class: "assessment-steps", "aria-label": "Assessment steps" },
        [["details", "1", "Details", "AI system"], ["documents", "2", "Documents", "Share evidence"], ["questions", "3", "Questions", "Answer what you know"], ["review", "4", "Review & report", "Submit for review"]].map(([id, number, title, hint]) =>
          el("button", { class: `assessment-step ${activeStep === id ? "is-next" : ""}`, "aria-current": activeStep === id ? "step" : null, type: "button", onclick: () => setStep(id) }, el("span", { class: "step-number" }, number), el("span", {}, el("strong", {}, title), el("small", {}, hint))))),
      activeStep === "details" ? el("section", { id: "assessment-details", class: "card assessment-details" }, el("span", { class: "eyebrow" }, "STEP 1 · DETAILS"), el("h3", {}, "Your assessment at a glance"),
        el("dl", { class: "assessment-detail-list" }, [["AI system", displayAISystemName(ctx.a.ai_system_name)], ["Industry", ctx.a.industry], ["Status", ctx.a.status]].map(([label, value]) => el("div", {}, el("dt", {}, label), el("dd", {}, value || "Not specified")))),
        el("div", { class: "flow-step-actions" }, el("p", { class: "help" }, "Next, add any documents you already have. You can continue without documents."), el("button", { type: "button", onclick: () => setStep("documents") }, "Continue to documents →"))) : "",
      activeStep === "documents" ? el("section", { class: "assessment-step-content" }, evidencePanel(ctx, draw), await applicationEvidencePanel(ctx, draw),
        el("div", { class: "flow-step-actions" }, el("p", { class: "help" }, "No documents ready? You can still answer the questions."), el("button", { type: "button", onclick: () => setStep("questions") }, "Continue to questions →"))) : "",
      activeStep === "questions" ? el("section", { id: "assessment-questions", class: "assessment-question-step" },
      el("div", { class: "module-panel assessment-progress" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "STEP 3 · QUESTIONS"), el("h3", {}, `${p.required_answered} of ${p.required_total} required answers`)), el("strong", {}, `${p.required_total ? Math.round(p.required_answered / p.required_total * 100) : 0}%`)), el("progress", { id: "pg", max: p.required_total || 1, value: p.required_answered }), el("p", { class: "help" }, "Answers save automatically when you finish a field. Choose ‘I don't know’ when you are unsure.")),
      el("details", { class: "setup-panel" }, el("summary", {}, el("strong", {}, "Scope & team"), el("span", { class: "help" }, ctx.scopeType === "org" ? " Whole organisation · optional settings" : ` ${ctx.scopeType}: ${ctx.scopeId}`)),
        scopeBar(ctx, draw),
        state.me.roles.some((role) => ["customer_admin", "customer_architect"].includes(role)) ? assignmentPanel(ctx, sections, draw) : ""),
      el("div", { class: `layout ${sections.length === 1 ? "single-section" : ""}` },
        el("nav", { class: "sections", "aria-label": "Questionnaire sections" }, el("span", { class: "eyebrow" }, "SECTIONS"), sections.map((sec) => {
          const inSec = qs.filter((q) => q.section === sec), done = inSec.filter((q) => ctx.answers[`${ctx.scopeId}|${q.question_id}`]).length;
          return el("button", { "aria-current": sec === ctx.section, onclick: () => { ctx.section = sec; draw(); window.scrollTo({ top: 0 }); } },
            el("span", {}, sec), el("small", { class: done === inSec.length ? "done" : "" }, done === inSec.length ? "✓" : `${done}/${inSec.length}`));
        })),
        el("div", { class: "questions" }, el("h3", { class: "section-title" }, ctx.section), qs.filter((q) => q.section === ctx.section).map((q, i) => questionCard(ctx, q, frozen, draw, i + 1)))),
        el("div", { class: "flow-step-actions" }, el("button", { class: "secondary", type: "button", onclick: () => setStep("documents") }, "← Back to evidence"), el("button", { type: "button", onclick: () => setStep("review") }, "Continue to review →"))) : "",
      activeStep === "review" ? el("section", { id: "assessment-review" },
      !frozen && !state.me.is_staff ? submitPanel(ctx, draw) : "",
      await reportsPanel(ctx, draw)) : "");
  };
  await draw();
};

function assignmentPanel(ctx, sections, draw) {
  const member = el("input", { type: "email", required: true, maxlength: 200, placeholder: "colleague@organisation.com" });
  const sectionSelect = el("select", { multiple: true, required: true, "aria-label": "Sections to assign" },
    sections.map((section) => el("option", { value: section, selected: section === ctx.section }, section)));
  const assignments = ctx.a.assignments || {};
  const assigned = Object.entries(assignments).map(([sub, owned]) => el("li", {}, `${sub} · ${owned.join(", ")}`));
  const form = el("form", { class: "assignment-form", onsubmit: safe(async (event) => {
    event.preventDefault();
    const response = await api(`/v1/assessments/${ctx.aid}/assignments`, { method: "POST", body: {
      sub: member.value.trim(), sections: [...sectionSelect.selectedOptions].map((option) => option.value),
    } });
    ctx.a.assignments = { ...(ctx.a.assignments || {}), [response.sub]: response.sections };
    toast("Assessment sections assigned"); await draw();
  }) }, el("label", {}, "Colleague work email", member), el("label", {}, "Questionnaire sections", sectionSelect),
  el("button", {}, "Assign sections"));
  return el("section", { class: "card assignment-panel" }, el("div", { class: "section-heading" }, el("div", {},
    el("span", { class: "eyebrow" }, "COLLABORATION"), el("h3", {}, "Assign a colleague"))),
    el("p", { class: "help" }, "Only members of this tenant can be assigned."), form,
    assigned.length ? el("ul", { class: "assignment-list" }, assigned) : el("p", { class: "help" }, "No section assignments yet."));
}

function scopeBar(ctx, draw) {
  const t = el("select", { id: "st" }, [["org", "Organisation"], ["ai_system", "AI system"], ["agent", "Agent"], ["workflow", "Workflow"], ["system", "System"]].map(([v, l]) => el("option", { value: v, selected: v === ctx.scopeType }, l)));
  const n = el("input", { id: "sn", value: ctx.scopeType === "org" ? "" : ctx.scopeId, placeholder: "Name of scope", disabled: ctx.scopeType === "org" });
  t.addEventListener("change", () => { n.disabled = t.value === "org"; });
  return el("form", { class: "card row", onsubmit: (e) => { e.preventDefault(); ctx.scopeType = t.value; ctx.scopeId = t.value === "org" ? "org" : (n.value.trim() || "default"); draw(); } },
    el("div", {}, el("label", { for: "st" }, "Scope type"), t), el("div", {}, el("label", { for: "sn" }, "Scope name"), n), el("button", { class: "secondary" }, "Switch scope"));
}

function questionCard(ctx, q, frozen, draw, num = 0) {
  const key = `${ctx.scopeId}|${q.question_id}`, cur = ctx.answers[key];
  const id = `q-${q.question_id}`, status = el("span", {}, cur ? `✓ Saved` : "Not answered yet");
  let input;
  const dis = frozen || (state.me.is_staff && false);
  if (q.response_type === "select_one") {
    input = el("select", { id, disabled: dis }, el("option", { value: "" }, "Select…"), q.options.map((o) => el("option", { value: o, selected: cur?.value === o }, o)));
  } else if (q.response_type === "select_multi") {
    input = el("fieldset", { id }, el("legend", {}, "Select all that apply"), q.options.map((o) => el("label", {}, el("input", { type: "checkbox", value: o, checked: (cur?.value || []).includes(o), disabled: dis }), o)));
  } else if (q.response_type === "number") {
    input = el("input", { id, type: "number", value: cur?.value ?? "", disabled: dis });
  } else {
    input = el(q.response_type === "long_text" ? "textarea" : "input", { id, rows: 3, disabled: dis, maxlength: 10000 }, ...(q.response_type === "long_text" ? [cur?.value ?? ""] : []));
    if (q.response_type !== "long_text") input.value = cur?.value ?? "";
  }
  const read = () => q.response_type === "select_multi" ? [...input.querySelectorAll("input:checked")].map((i) => i.value)
    : q.response_type === "number" ? (input.value === "" ? null : Number(input.value)) : input.value;
  const unknown = el("input", { type: "checkbox", id: `${id}-u`, checked: cur?.answer_status === "unknown", disabled: dis });
  const ev = el("select", { id: `${id}-e`, multiple: true, "aria-label": "Attach evidence", disabled: dis }, ctx.evidence.filter((e) => e.state === "clean").map((e) => el("option", { value: e.evidence_id, selected: (cur?.evidence_refs || []).includes(e.evidence_id) }, e.filename)));
  const save = safe(async () => {
    const value = read(), isUnknown = unknown.checked;
    if (!isUnknown && (value === "" || value === null || (Array.isArray(value) && !value.length))) return;
    const body = { scope_id: ctx.scopeId, value: isUnknown ? null : value, answer_status: isUnknown ? "unknown" : "answered", evidence_refs: [...ev.selectedOptions].map((o) => o.value) };
    try {
      const res = await api(`/v1/assessments/${ctx.aid}/answers/${q.question_id}`, { method: "PUT", body, headers: { "If-Match": ctx.answers[key]?.etag || "0" }, raw: true });
      const data = await res.json();
      if (res.status === 409) { status.textContent = "Changed by someone else; reloading latest…"; say(status.textContent); return routes.assessment(ctx.aid); }
      if (!res.ok) throw new Error(data.message);
      ctx.answers[key] = data; status.textContent = "✓ Saved"; say(`Saved ${q.question_id}`);
      // Progress and conditional questions depend on persisted answers. Refresh after
      // each save so the submit gate and adaptive branches do not remain stale.
      await draw();
    } catch (e) { toast(e.message, true); }
  });
  [input, unknown, ev].forEach((n) => n.addEventListener("change", save));
  const swaskaOut = el("div", { class: "help", "aria-live": "polite" });
  const swaskaPrompt = el("textarea", { rows: 2, maxlength: 2000, placeholder: "Ask why this is needed or what evidence could help.", "aria-label": `Question for Swaska about ${q.question_id}` });
  const ask = el("button", { class: "secondary", type: "button", onclick: safe(async () => {
    const userMessage = swaskaPrompt.value.trim();
    if (!userMessage) return toast("Enter a question for Swaska", true);
    const t = await api(`/v1/assessments/${ctx.aid}/swaska/turns`, { method: "POST", body: { scope_id: ctx.scopeId, user_message: userMessage, parent_question_id: q.question_id } });
    swaskaOut.replaceChildren(el("strong", {}, "Swaska: "), t.clarification_text, t.needs_evidence ? ` Suggested evidence: ${t.evidence_type}.` : "", ` (${t.uncertainty})`);
  }) }, "Ask about this question");
  const swaskaDrawer = el("details", { class: "swaska-drawer" }, el("summary", {}, "Ask Swaska · question help"),
    el("p", { class: "help" }, "Swaska can explain this question and suggest evidence. Suggestions are not approvals."), swaskaPrompt, ask, swaskaOut);
  const answered = Boolean(cur);
  return el("article", { class: `q-card ${answered ? "is-answered" : ""}` },
    el("div", { class: "q-head" }, el("span", { class: "q-num" }, String(num)),
      el("div", {}, el("label", { for: id, class: "q-title" }, q.question),
        el("div", { class: "q-meta" }, el("span", { class: `tag ${q.required === "yes" ? "req" : ""}` }, q.required === "yes" ? "Required" : "If applicable"), state.me.is_staff ? el("span", { class: "q-id" }, q.question_id) : ""),
        q.guidance ? el("p", { class: "q-guidance" }, q.guidance) : "")),
    el("div", { class: "q-input" }, input),
    ctx.evidence.some((e) => e.state === "clean") ? el("div", { class: "q-evidence" }, el("span", { class: "help" }, "Attach evidence (optional)"), ev) : "",
    el("div", { class: "q-foot" },
      el("label", { class: "unknown-toggle", for: `${id}-u` }, unknown, el("span", {}, "I don't know")),
      q.evidence_request ? el("details", { class: "question-evidence-help" }, el("summary", {}, "What document could help?"), el("p", { class: "help" }, q.evidence_request)) : "",
      el("span", { class: `q-status ${answered ? "ok" : ""}`, id: `${id}-s` }, status)),
    swaskaDrawer);
}

function evidencePanel(ctx, draw) {
  const extractOut = el("div", { "aria-live": "polite" });
  const extractable = (e) => e.state === "clean" && ["text/plain", "text/csv", "application/json"].includes(e.content_type);
  const list = ctx.evidence.map((e) => el("li", {}, `${e.filename} - `, el("span", { class: `tag ${e.state === "clean" ? "ok" : "high"}` }, e.state), e.injection_flagged ? el("span", { class: "tag medium" }, "instruction-like text flagged") : "",
    extractable(e) ? agentButton("Suggest answers from this file", extractOut, async () => {
      const r = await api(`/v1/assessments/${ctx.aid}/agents/extraction`, { method: "POST", body: { evidence_id: e.evidence_id } });
      return r.items.length ? advisoryBox(`Candidate answers (${r.mode}) - unverified, enter them yourself if correct`, r.items.map((i) => `${i.question_id}: ${i.candidate_value}  [source: "${i.excerpt}"]`))
        : el("p", { class: "help" }, "No candidate answers found in this file.");
    }) : ""));
  const f = el("input", { type: "file", id: "ef", accept: ".pdf,.txt,.csv,.json,.docx,.xlsx" });
  return el("section", { class: "card assessment-documents", id: "assessment-documents" }, el("span", { class: "eyebrow" }, "STEP 2 · DOCUMENTS"), el("h3", {}, "Upload documents about your AI"),
    el("p", {}, "Start with any documents you already have. You can answer the questions even if you have no documents yet."),
    el("div", { class: "document-examples" }, [ ["AI register", "A list of your AI tools, their purpose and owners."], ["System overview", "How your AI works and which data or systems it uses."], ["Policies & test reports", "Your AI rules, approvals, risks or testing results."] ].map(([title, description]) => el("div", {}, el("strong", {}, title), el("p", { class: "help" }, description)))),
    el("details",{class:"document-example-guide"},el("summary",{},"What can a document look like?"),
      el("p",{},"Example AI register entry: ‘Customer support chatbot · Owner: Support team · Purpose: answer account FAQs · Cannot change customer accounts.’"),
      el("p",{},"Example policy entry: ‘Authorised support staff review customer complaints about the chatbot.’"),
      el("p",{class:"help"},"Use your existing files; this wording is only an example. Test and approval records help a reviewer check whether the stated controls are supported.")),
    list.length ? el("ul", {}, list) : el("p", { class: "help" }, "No files uploaded yet."), extractOut,
    el("label", { for: "ef" }, "Upload a document"), f,
    el("p", {}, el("button", { onclick: safe(async () => {
      const file = f.files[0]; if (!file) return toast("Choose a file first", true);
      const buf = await file.arrayBuffer();
      const g = await api(`/v1/assessments/${ctx.aid}/evidence/upload-url`, { method: "POST", body: { filename: file.name, content_type: file.type || "application/octet-stream", file_size_bytes: file.size, claimed_sha256: await sha256Hex(buf) } });
      const r = await api(g.upload_url, { method: "PUT", body: buf, headers: { "Content-Type": "application/octet-stream" } });
      toast(r.state === "clean" ? "Uploaded and scanned: clean" : `Upload ${r.state}: ${r.reason}`, r.state !== "clean"); draw();
    }) }, "Upload")),
    el("p", { class: "help" }, "PDF, Word, Excel, TXT, CSV or JSON. Files are checked for safety before use."),
    el("div", { class: "row" }, list.length ? el("a", { href: `#/use-cases/${ctx.aid}` }, "View AI use cases from documents →") : ""));
}

function submitPanel(ctx, draw) {
  const p = ctx.a.progress, ready = p.required_answered >= p.required_total;
  return el("section", { class: "card" }, el("span", { class: "eyebrow" }, "STEP 4 · REVIEW & REPORT"), el("h3", {}, "Send your assessment for review"), el("p", { class: "help" }, "CloudSeals reviews your assessment before publishing your report. Submitting freezes your answers. This cannot be undone."),
    el("button", { disabled: !ready, onclick: safe(async () => { if (!confirm("Submit and freeze all answers?")) return; await api(`/v1/assessments/${ctx.aid}/submit`, { method: "POST", idem: true }); toast("Submitted"); draw(); }) }, ready ? "Submit" : `Answer ${p.required_total - p.required_answered} more required question(s)`));
}

async function applicationEvidencePanel(ctx, draw) {
  const path = `/v1/assessments/${ctx.aid}/application-evidence`;
  const {items} = await api(path);
  const reviewer = state.me.roles.includes("cloudseals_reviewer");
  const canImport = state.me.roles.some(r => ["customer_admin", "customer_architect", "cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer"].includes(r));
  const file = el("input", {type:"file", accept:".json,application/json", "aria-label":"REA application capture JSON"});
  const attachBytes = async (buf, filename) => {
    const grant=await api(`/v1/assessments/${ctx.aid}/evidence/upload-url`,{method:"POST",body:{filename,content_type:"application/json",file_size_bytes:buf.byteLength,claimed_sha256:await sha256Hex(buf)}});
    const scan=await api(grant.upload_url,{method:"PUT",body:buf,headers:{"Content-Type":"application/octet-stream"}});
    if(scan.state!=="clean") throw new Error(`Capture is ${scan.state}; clean evidence is required.`);
    return api(path,{method:"POST",body:{evidence_id:grant.evidence_id}});
  };
  const website=el("input",{type:"text",inputmode:"url",autocomplete:"url",autocapitalize:"off",spellcheck:false,required:true,maxlength:1000,placeholder:"www.your-website.com","aria-label":"Website URL"});
  const authorized=el("input",{type:"checkbox",required:true});
  const inspectionStatus=el("p",{class:"help",role:"status","aria-live":"polite"});
  const inspectButton=el("button",{type:"submit"},"Inspect website");
  const websiteForm=el("form",{class:"website-inspection-form",onsubmit:safe(async e=>{
    e.preventDefault();
    if(!authorized.checked) return toast("Confirm you own this website or have permission to inspect it.",true);
    let target=website.value.trim();
    if(target.startsWith("//")) target="https:"+target;
    else if(!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(target) || /^[^/?#]+:\d+(?:[/#?]|$)/.test(target)) target="https://"+target;
    website.value=target;
    inspectButton.disabled=true;inspectButton.setAttribute("aria-busy","true");inspectionStatus.textContent="Inspecting public page…";
    try {
      const result=await api(`/v1/assessments/${ctx.aid}/website-inspection`,{method:"POST",body:{url:target,authorized:true}});
      const bytes=new TextEncoder().encode(JSON.stringify(result.capture,null,2)).buffer;
      inspectionStatus.textContent="Page inspected. Checking and attaching evidence…";
      await attachBytes(bytes,"website-inspection.json");
      toast("Website inspected. Observations attached for review.");await draw();
    } catch(error) {inspectionStatus.textContent=error.message;throw error;}
    finally {inspectButton.disabled=false;inspectButton.removeAttribute("aria-busy");}
  })},el("h4",{},"Inspect a website"),el("label",{},"Website URL",website),
    el("p",{class:"help"},"Enter a website name, for example www.cloudseals.com. HTTPS is added automatically."),
    el("p",{class:"help"},"Public HTML page and response metadata only. No login, JavaScript execution or chatbot interaction. Query strings are excluded."),
    el("label",{class:"website-permission"},authorized,"I own this website or have permission to inspect it."),inspectButton,inspectionStatus);
  const upload = el("button", {class:"secondary", type:"button", onclick:safe(async e => {
    const button=e.currentTarget, chosen=file.files[0];
    if(!chosen) return toast("Choose the capture JSON exported by the client collector",true);
    button.disabled=true;
    try {
      await attachBytes(await chosen.arrayBuffer(),chosen.name);
      toast("Capture attached. Evidence analysis is ready for reviewer validation.");await draw();
    } finally {button.disabled=false;}
  })},"Attach application capture");
  const cards=items.map(run => {
    const url=`${path}/${run.run_id}`, reason=el("textarea", {rows:2,maxlength:2000,"aria-label":"Application evidence review reason",placeholder:"Record what you checked and any scope limitations…"});
    const reviewButton=(label,decision) => el("button",{type:"button",class:decision==="rejected" ? "secondary" : "",onclick:safe(async e=>{
      const button=e.currentTarget;
      if(!reason.value.trim()) return toast("Add a review reason",true);
      button.disabled=true;
      try {await api(`${url}/review`,{method:"POST",body:{decision,reason:reason.value.trim(),source_digest:run.source_digest}});toast("Review recorded");await draw();}
      finally {button.disabled=false;}
    })},label);
    const published=run.published.length>0;
    return el("article",{class:"application-evidence-card"},
      el("div",{class:"module-panel-heading"},el("div",{},el("span",{class:"eyebrow"},"APPLICATION OBSERVATIONS"),el("h4",{},run.capture.target_url)),
        el("span",{class:`tag ${published ? "ok" : "medium"}`},published ? "Published" : run.status.replaceAll("_"," "))),
      el("p",{class:"help"},`${run.capture.producer === "trustops-http-inspector" ? "Public-page HTTP inspection" : "REA browser capture"} ${run.capture.producer_version} · ${new Date(run.capture.started_at).toLocaleString()} · ${run.capture.observation_ms / 1000}s observation window`),
      el("div",{class:"application-evidence-stats"},[[run.capture.dom_nodes,run.capture.producer === "trustops-http-inspector" ? "HTML elements" : "DOM nodes"],[run.capture.scripts.length,"Script records"],[run.capture.requests.length,"Network requests"]].map(([v,l])=>el("div",{},el("strong",{},String(v)),el("span",{},l)))),
      el("ol",{class:"application-evidence-flow","aria-label":"Completed workflow steps"},run.events.map(ev=>el("li",{},el("strong",{},({validate_capture:"Capture checked",analyse_metadata:"Observations prepared",human_review:"Reviewer decision",report_draft:"Report drafted"})[ev.step] || ev.step.replaceAll("_"," ")),el("small",{},`Completed ${new Date(ev.at*1000).toLocaleTimeString()}`)))),
      el("details",{},el("summary",{},"What was observed"),el("ul",{},run.observations.map(o=>el("li",{},o.text,el("small",{},` Source: ${o.source}`)))),
        el("h5",{},"Script metadata"),el("ul",{},run.capture.scripts.map(s=>el("li",{},s.url))),
        el("h5",{},"Network metadata"),run.capture.requests.length ? el("div",{class:"table-scroll"},el("table",{},el("thead",{},el("tr",{},["Method","URL","HTTP status"].map(t=>el("th",{},t)))),el("tbody",{},run.capture.requests.map(r=>el("tr",{},el("td",{},r.method),el("td",{},r.url),el("td",{},r.status ?? "Unknown")))))) : el("p",{class:"help"},"No requests retained in this window; earlier activity is unknown.")),
      run.findings.length ? el("details",{},el("summary",{},`Findings requiring attention (${run.findings.length})`),run.findings.map(f=>el("div",{},el("strong",{},f.title),el("p",{},f.detail),el("p",{},f.recommendation),el("small",{},f.evidence_refs.join(", "))))) : "",
      run.capture.page ? el("details",{},el("summary",{},"Page response details"),
        el("p",{},`Page title: ${run.capture.page.title || "Not present"} · HTTP ${run.capture.page.http_status}`),
        el("p",{class:"help"},"Selected response headers present on this response; effectiveness needs review."),
        el("pre",{},JSON.stringify(run.capture.page.security_headers,null,2))) : "",
      el("details",{},el("summary",{},"Missing information & next actions"),run.missing_information.map(m=>el("div",{class:"application-evidence-request"},el("strong",{},m.title),el("p",{class:"help"},m.reason),el("p",{},m.action)))),
      el("details",{},el("summary",{},"What could not be verified"),el("ul",{},run.limitations.map(l=>el("li",{},l)))),
      el("details",{},el("summary",{},"Source & file integrity"),el("small",{class:"application-evidence-digest"},`Capture evidence: ${run.capture.rea_evidence_id} · Attached-file SHA-256: ${run.evidence_sha256}`)),
      reviewer && run.status==="awaiting_review" ? el("div",{class:"application-evidence-review"},el("label",{},"Reviewer decision",reason),el("div",{class:"row"},reviewButton("Validate evidence & build report","validated"),reviewButton("Reject capture","rejected"))) : "",
      reviewer && run.status==="reviewed_draft" && !published ? el("div",{class:"application-evidence-review"},el("p",{},"Preview the report before releasing it to the customer."),reason,el("div",{class:"row"},
        el("button",{class:"secondary",onclick:safe(()=>dl(`${url}/report?preview=true`,"Application-evidence-preview.html"))},"Preview reviewed report"),
        el("button",{onclick:safe(async e=>{const button=e.currentTarget;if(!reason.value.trim()) return toast("Add a publication reason",true);button.disabled=true;try{await api(`${url}/publish`,{method:"POST",body:{source_digest:run.source_digest,reason:reason.value.trim()}});toast("Application evidence report published");await draw();}finally{button.disabled=false;}})},"Publish to customer"))) : "",
      published ? el("button",{class:"secondary",onclick:safe(()=>dl(`${url}/report`,"TrustOps-application-evidence.html"))},"Download published application report") : el("p",{class:"help"},"A customer report becomes available after reviewer validation and publication."));
  });
  return el("details",{class:"card application-evidence-panel",id:"application-evidence",open:canImport || items.length>0},el("summary",{},"Website inspection & application evidence",el("span",{class:"tag"},items.length ? `${items.length} captures` : "Optional")),el("h3",{},"Show how your application behaves"),
    el("p",{},"Enter a public website URL to collect page observations, or import a browser capture. Review findings before publishing a report."),
    el("details",{},el("summary",{},"How to collect application evidence"),el("p",{},"Your technical team runs the optional client-side REA collector against a selected application and exports the TrustOps capture JSON. Upload that file here. Browser metadata cannot verify backend permissions, retention or AI model execution.")),
    canImport ? websiteForm : "",
    canImport ? el("details",{class:"application-capture-import"},el("summary",{},"Advanced: import REA browser capture"),el("div",{class:"application-evidence-upload"},file,upload)) : "", ...cards,
    !items.length ? el("p",{class:"help"},"No application capture attached. This step is optional; documents and questionnaire answers remain available.") : "");
}

async function reportsPanel(ctx, draw) {
  const [{items},{items:library}]=await Promise.all([api(`/v1/assessments/${ctx.aid}/reports`),api("/v1/report-library")]);
  const applicationReports=library.filter(r=>r.assessment_id===ctx.aid && r.kind==="application_evidence");
  const staff = state.me.is_staff;
  const kids = [el("h3", {}, "Your reports"), el("p", { class: "help" }, "Reports use this assessment’s answers and evidence. Final downloads appear after reviewer approval and publication.")];
  for(const r of applicationReports) kids.push(el("div",{class:"published-application-report"},el("h4",{},"Application evidence report"),el("span",{class:"tag ok"},`Published · Version ${r.version}`),
    el("button",{class:"secondary",onclick:safe(()=>dl(r.download_urls.html,"TrustOps-application-evidence.html"))},"Download application evidence report")));
  if (!staff) {
    const inventory = await api(`/v1/assessments/${ctx.aid}/inventory`);
    if (inventory.delivery) kids.push(deliveredDiagnosticPanel(ctx.aid, inventory.delivery));
    else kids.push(el("p", { class: "help" }, "Document-based report and improvement roadmap: awaiting analysis, review and publication."));
  }
  if (!items.length && !applicationReports.length) kids.push(el("p", { class: "help" }, ctx.a.status === "In progress" ? "No published assessment report yet. Complete the assessment and send it for review." : "Your assessment report is awaiting review and publication."));
  for (const r of items) {
    const row = el("div", { class: "row" }, el("span", { class: `tag ${r.status === "published" ? "ok" : ""}` }, r.status), `v${r.version}`,
      ["pdf", "docx"].map((f) => el("button", { class: "secondary", onclick: safe(() => dl(`/v1/assessments/${ctx.aid}/reports/${r.report_id}/download?format=${f}`, `taad-report.${f}`)) }, f.toUpperCase())));
    kids.push(row);
    if (staff) kids.push(await reviewPanel(ctx, r, draw));
  }
  if (!staff) { const f = await api(`/v1/assessments/${ctx.aid}/findings`); if (f.items.length) kids.push(findingsTable(f.items)); }
  return el("section", { class: "card" }, kids);
}

function findingsTable(items, adjust) {
  return el("table", {}, el("caption", {}, "Findings (candidates for review, not legal determinations)"),
    el("thead", {}, el("tr", {}, ["Rule", "Severity", "Status", "Basis", adjust ? "Adjust" : ""].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, items.map((f) => el("tr", {}, el("td", {}, `${f.rule_id} ${f.title}`), el("td", {}, el("span", { class: `tag ${f.severity_hint}` }, f.severity_hint)),
      el("td", {}, f.status), el("td", {}, f.citations.map((c) => `${c.question_id}=${c.answer}`).join(", ")), el("td", {}, adjust ? adjust(f) : "")))));
}

// ---------- TrustOps workspace modules ----------
const moduleFrame = (eyebrow, title, description, ...content) => el("div", { class: "module-page" },
  el("div", { class: "module-page-heading" }, el("span", { class: "eyebrow" }, eyebrow), el("h2", {}, title), el("p", {}, description)), ...content);
const moduleCard = (title, description, status, route = null, variant = "") => el(route ? "a" : "article", {
  class: `module-card${route ? " module-card-link" : ""}${variant ? ` ${variant}` : ""}`,...(route ? { href: `#/${route}` } : {})
}, el("span", { class: "module-card-status" }, status), el("h3", {}, title), el("p", {}, description),
route ? el("span", { class: "module-card-open" }, "Open module →") : "");
const workspaceHeading = (eyebrow, title, description, action) => el("div", { class: "workspace-heading" },
  el("div", {}, el("span", { class: "eyebrow" }, eyebrow), el("h2", {}, title), el("p", {}, description)), action || "");
const workspaceStats = (items) => el("section", { class: "workspace-stats" }, items.map(([label, value, hint]) => el("article", {}, el("span", {}, label), el("strong", {}, String(value)), el("small", {}, hint))));
function customerExample(title, introduction, steps, action = null) {
  return el("section", {class:"customer-example", "aria-label":title},
    el("div", {class:"customer-example-heading"}, el("div",{},el("span",{class:"eyebrow"},"EXPLAINED WITH AN EXAMPLE"),el("h3",{},title),el("p",{},introduction)), action || ""),
    el("div", {class:"customer-example-steps"}, steps.map(([label, text], i)=>el("div",{},el("span",{class:"example-step-index","aria-hidden":"true"},String(i+1).padStart(2,"0")),el("strong",{},label),el("p",{},text)))));
}
function overviewExamples() {
  return el("details",{class:"module-panel assessment-example"},el("summary",{},"See an example assessment"),
    customerExample("A company wants to understand its support chatbot.","Illustrative example · Use the information the customer already has.",[
      ["Share evidence","Upload a system overview, AI register, policies or test results. Answer questions about ownership and how the system is used."],
      ["Assess and review","TrustOps links candidate findings to evidence. A reviewer checks them and requests missing information."],
      ["Receive a report","The published report explains reviewed findings, evidence limits and prioritised improvements."]],
      el("a",{class:"text-link",href:"#/assessments"},"Open assessments →")));
}
routes.dashboard = async () => {
  const [{items:assessments},{items:reports}] = await Promise.all([api("/v1/assessments"),api("/v1/report-library")]);
  const inProgress=assessments.filter(a=>a.status==="In progress"), publishedIds=new Set(reports.map(r=>r.assessment_id));
  const awaiting=assessments.filter(a=>a.status!=="In progress"&&!publishedIds.has(a.assessment_id));
  const activeAssessment=inProgress[0]?.assessment_id;
  const workflowStages = [
    ["01", "Define the AI system", "Name the system, purpose, owner and industry.", "YOUR TEAM"],
    ["02", "Share evidence", "Add documents and answer what your team knows.", "YOUR TEAM"],
    ["03", "Check evidence", "Organize submitted evidence and flag what is still unknown.", "TRUSTOPS"],
    ["04", "Human review", "A reviewer validates candidate findings and follows up on gaps.", "REVIEWER"],
    ["05", "Get the report", "Read reviewed findings, evidence limits and recommended actions.", "YOUR TEAM"],
  ];
  main.replaceChildren(el("div",{class:"module-page overview-page"},
    workspaceHeading("YOUR AI ASSESSMENTS","AI oversight. A clear next step.","Understand your AI system, share evidence and receive a reviewed report.",el("a",{class:"btn",href:"#/assessments"},"Start an assessment +")),
    workspaceStats([["Assessments",assessments.length,"AI systems in this workspace"],["In progress",inProgress.length,"Evidence and questions"],["Awaiting review",awaiting.length,"Submitted without a published report"],["Published reports",reports.length,"Reviewed and ready to download"]]),
    el("section",{class:"workflow-infographic","aria-labelledby":"workflow-infographic-title"},
      el("div",{class:"workflow-infographic-heading"},el("div",{},el("span",{class:"eyebrow"},"FROM AI SYSTEM TO ACTION"),el("h2",{id:"workflow-infographic-title"},"How a TrustOps assessment works")),
        el("span",{class:"workflow-proof-label"},"Evidence first · Human reviewed")),
      el("div",{class:"workflow-infographic-track"},workflowStages.map(([number,title,description,owner],index)=>
        el("article",{class:`workflow-infographic-stage${index===3?" reviewer-stage":""}`},
          el("div",{class:"workflow-stage-top"},el("span",{class:"workflow-stage-number"},number),index<workflowStages.length-1?el("span",{class:"workflow-stage-arrow","aria-hidden":"true"},"→"):""),
          el("span",{class:"workflow-stage-owner"},owner),el("h3",{},title),el("p",{},description)))),
      el("p",{class:"workflow-infographic-note"},"A missing document is recorded as missing evidence; it is not treated as proof that a control is absent.")),
    el("section",{class:"module-panel"},el("div",{class:"module-panel-heading"},el("h3",{},"Your assessments"),el("a",{class:"text-link",href:"#/assessments"},"View all →")),
      assessments.length ? el("div",{class:"table-wrap"},el("table",{class:"module-table"},el("thead",{},el("tr",{},["AI system","Industry","Status", ""].map(label=>el("th",{},label)))),el("tbody",{},assessments.slice(0,5).map(a=>el("tr",{},el("td",{},displayAISystemName(a.ai_system_name)),el("td",{},a.industry),el("td",{},a.status),el("td",{},el("a",{href:`#/assessment/${a.assessment_id}`},"Open assessment →")))))))
        : el("p",{class:"empty-state"},"Create your first assessment to get started.")),
    overviewExamples()));
};

routes.reports = async () => {
  const [{items:assessments},{items:published}] = await Promise.all([api("/v1/assessments"),api("/v1/report-library")]);
  const content=el("div",{class:"results-content"}), query=el("input",{type:"search",placeholder:"Search by AI system…","aria-label":"Search reports"});
  const publishedIds=new Set(published.map(r=>r.assessment_id));
  const draw=()=>{
    const term=query.value.trim().toLowerCase();
    const filtered=published.filter(r=>`${r.ai_system_name} ${r.kind}`.toLowerCase().includes(term));
    content.replaceChildren(el("div",{class:"report-library"},filtered.length ? filtered.map(r=>el("article",{class:"report-library-card"},
      el("div",{class:"report-cover","aria-hidden":"true"},el("span",{},"CLOUDSEALS"),el("strong",{},"AI assessment"),el("span",{},"REPORT"),el("div",{class:"report-cover-lines"})),
      el("div",{class:"report-library-copy"},el("span",{class:"tag ok"},"Published"),el("h3",{},displayAISystemName(r.ai_system_name)),el("p",{},`${r.industry} · Version ${r.version} · ${r.kind === "application_evidence" ? "Application evidence" : r.kind === "document_diagnostic" ? "Document diagnostic" : "Questionnaire assessment"}`),el("p",{class:"help"},r.kind === "application_evidence" ? "Reviewed application observations, scope limits and evidence requests." : r.kind === "document_diagnostic" ? "Reviewed AI inventory, framework gaps, maturity and improvement roadmap." : "Findings, supporting answers and prioritised improvement actions, released after review."),
        el("div",{class:"row"},Object.entries(r.download_urls).map(([format,url],index)=>el("button",{class:index ? "secondary" : "",onclick:safe(()=>dl(url,`TrustOps-${r.kind}-v${r.version}.${format}`))},`Download ${format === "docx" ? "Word" : format.toUpperCase()} ↓`))),
        el("a",{class:"text-link",href:`#/${r.kind === "document_diagnostic" ? "use-cases" : "assessment"}/${r.assessment_id}`},"View assessment & findings →")))) : el("div",{class:"module-panel empty-state"},"No published reports match your search. Reports appear here after review and publication.")),
      el("section",{class:"workspace-note"},el("p",{},"Looking for a report still in progress? Open its assessment to check the review status."),el("a",{href:"#/assessments"},"View assessments →")));
  };
  query.addEventListener("input",draw);draw();
  main.replaceChildren(el("div",{class:"module-page results-page"},workspaceHeading("REVIEWED OUTCOMES","Reports","Published assessment reports, application observations and improvement roadmaps."),
    workspaceStats([["Published reports",published.length,"Ready to download"],["Assessments",assessments.length,"AI systems in this workspace"],["Without a published report",assessments.filter(a=>!publishedIds.has(a.assessment_id)).length,"Continue the assessment or reviewer process"]]),
    el("div",{class:"results-toolbar"},query),content));
};

// ---------- LedgerSight Core POC walkthrough ----------
// A small, honest walkthrough of the documented AR/Cash workflow. The API
// remains authoritative for policy, approval, token and connector decisions.
const ledgerActionTokens = new Map();
routes["ledger-sight"] = async (selectedRunId) => {
  const [overview, { items: recentRuns }] = await Promise.all([api("/v1/agentops"), api("/v1/runs?limit=10")]);
  const roles = state.me.roles;
  const canStart = ["customer_admin", "customer_architect", "customer_risk", "customer_controller", "cloudseals_assessor", "cloudseals_admin"].some(r => roles.includes(r));
  const canApprove = roles.includes("customer_controller");
  const canExecute = canStart;
  const workflowId = overview.workflow_pack;
  const subtitle = "Match incoming receipts to invoices, apply the policy gate, and keep a reviewable record of each decision.";
  const safety = el("section", { class: "ledger-demo-safety", role: "note" },
    el("strong", {}, "SAMPLE DATA · CONTROLLED WORKFLOW"),
    el("p", {}, "Uses fictional receipts and the mock_sap connector. No bank account, real payment, or customer ERP is accessed or changed."));
  const stages = el("section", { class: "ledger-demo-stages", "aria-label": "How the workflow works" },
    [["1", "Check the input", "Receipt, amount, currency and reference are validated."],
      ["2", "Match the invoice", "Candidates are compared; unclear matches go to review."],
      ["3", "Apply policy", "High-value actions require a different controller to approve."],
      ["4", "Record evidence", "Prepare/execute steps are recorded and can be verified."]]
      .map(([n, title, text]) => el("article", {}, el("span", {}, n), el("strong", {}, title), el("p", {}, text))));
  const scenarioList = [
    ["exact", "Exact match", "One exact invoice match; policy may allow a proposal.", "Run exact-match scenario"],
    ["ambiguous", "Ambiguous match", "Two exact candidates; the workflow should escalate for review.", "Run ambiguous scenario"],
    ["high", "High-value match", "An exact match above the example limit; a separate controller must approve.", "Run high-value scenario"],
    ["unmatched", "No match", "No invoice matches the receipt; no proposal should be prepared.", "Run no-match scenario"]
  ];
  const scenarioCards = el("div", { class: "ledger-demo-scenarios" }, scenarioList.map(([key, title, text, label]) => {
    const button = el("button", { type: "button", disabled: !canStart || overview.mode !== "sandbox", onclick: safe(async () => {
      button.disabled = true;
      try {
        const receiptId = `SAMPLE-${key.toUpperCase()}-${crypto.randomUUID().slice(0, 8)}`;
        const reference = `REF-${receiptId.slice(-8)}`;
        const amount = key === "high" ? 150000 : 25000;
        const exact = { invoice_id: `INV-${receiptId.slice(-8)}-A`, amount_minor: amount, currency: "USD", reference };
        const invoices = key === "ambiguous" ? [exact, { ...exact, invoice_id: `INV-${receiptId.slice(-8)}-B` }]
          : key === "unmatched" ? [{ ...exact, amount_minor: amount + 100, reference: `OTHER-${reference}` }] : [exact];
        const run = await api(`/v1/workflows/${encodeURIComponent(workflowId)}/runs`, { method: "POST", idem: true,
          body: { receipt: { receipt_id: receiptId, amount_minor: amount, currency: "USD", reference }, invoices, remittance: { reference } } });
        toast(`Workflow finished: ${run.status.replaceAll("_", " ")}`);
        go(`#/ledger-sight/${run.run_id}`);
      } finally { button.disabled = false; }
    }) }, label);
    return el("article", { class: "ledger-demo-scenario" }, el("h3", {}, title), el("p", {}, text), button);
  }));
  const detail = el("section", { class: "ledger-demo-detail", id: "ledger-run-detail", "aria-live": "polite" });
  const drawRun = async (runId) => {
    if (!runId) { detail.replaceChildren(); return; }
    const run = await api(`/v1/runs/${encodeURIComponent(runId)}`);
    const decision = run.policy_decision || {};
    const statusText = (run.status || "unknown").replaceAll("_", " ");
    const decisionText = decision.decision === "ALLOW" ? "Policy allows preparation" : decision.decision === "ESCALATE" ? "Needs human review" : decision.decision || "Not available";
    const trace = el("ol", { class: "ledger-agent-trace" }, (run.agent_trace || []).map((step, index) => {
      const label = step.agent_id.split(".").at(-1).replaceAll("_", " ").replace(/\b\w/g, x => x.toUpperCase());
      const rec = step.recommendation || {};
      const note = rec.rationale || rec.explanation || rec.summary || step.reason_code?.replaceAll("_", " ") || "Completed with recorded input evidence.";
      return el("li", {}, el("span", {}, String(index + 1).padStart(2, "0")), el("div", {}, el("strong", {}, label), el("p", {}, note)), el("small", {}, (step.status || "completed").replaceAll("_", " ")));
    }));
    const actions = [];
    if (run.status === "approval_required" && canApprove) {
      const reason = el("input", { maxlength: 2000, placeholder: "Why are you approving or rejecting?", "aria-label": "Controller decision reason" });
      const decide = (decisionValue) => safe(async () => {
        if (!reason.value.trim()) return toast("Enter a decision reason first.", true);
        await api(`/v1/approvals/${run.run_id}/decision`, { method: "POST", idem: true, body: { decision: decisionValue, reason: reason.value.trim() } });
        toast(`Controller decision recorded: ${decisionValue}`); await drawRun(run.run_id);
      });
      actions.push(el("section", { class: "module-panel" }, el("h3", {}, "Controller approval required"),
        el("p", {}, "Only a different user with the customer_controller role can decide this request."), reason,
        el("div", { class: "row" }, el("button", { type: "button", onclick: decide("approve") }, "Approve proposal"),
          el("button", { class: "secondary", type: "button", onclick: decide("reject") }, "Reject proposal"))));
    } else if (run.status === "approval_required") {
      actions.push(el("p", { class: "ledger-demo-note" }, "Waiting for a separate customer controller. Open this run after signing in with the authorized controller account."));
    }
    if (canExecute && ["ready_to_prepare", "approved_to_prepare", "prepared"].includes(run.status)) {
      const prepare = el("button", { type: "button", onclick: safe(async () => {
        const prepared = await api("/v1/execution/prepare", { method: "POST", idem: true, body: { run_id: run.run_id } });
        if (prepared.action_token) ledgerActionTokens.set(run.run_id, prepared.action_token);
        toast("Pre-commit evidence recorded; one-use action token issued."); await drawRun(run.run_id);
      }) }, run.status === "prepared" ? "Issue a new one-use token" : "Prepare with evidence");
      const execute = run.status === "prepared" ? el("button", { type: "button", onclick: safe(async () => {
        const token = ledgerActionTokens.get(run.run_id);
        if (!token) return toast("The one-use token is not in this session. Issue a new token first.", true);
        await api("/v1/execution/execute", { method: "POST", idem: true, body: { run_id: run.run_id, action_token: token } });
        ledgerActionTokens.delete(run.run_id); toast("Controlled action completed through mock_sap."); await drawRun(run.run_id);
      }) }, "Run controlled action") : "";
      actions.push(el("section", { class: "module-panel" }, el("h3", {}, "Governed execution"),
        el("p", {}, "The API enforces the policy decision, approval and evidence pre-commit before this mock action."), el("div", { class: "row" }, prepare, execute)));
    }
    const verified = run.evidence_verified;
    const verifyButton = el("button", { type: "button", class: "secondary", onclick: safe(async () => {
      const result = await api(`/v1/evidence/${run.run_id}/verify`, { method: "POST" });
      toast(result.valid ? `Evidence verified (${result.integrity}).` : "Evidence verification failed.", !result.valid);
      await drawRun(run.run_id);
    }) }, verified ? "Verify evidence again" : "Verify run evidence");
    detail.replaceChildren(el("div", { class: "ledger-demo-detail-heading" },
      el("div", {}, el("span", { class: "eyebrow" }, "WORKFLOW RESULT"), el("h3", {}, `Receipt ${run.receipt_id}`),
        el("p", {}, `${run.currency} ${(run.amount_minor / 100).toFixed(2)} · ${statusText}`)),
      el("a", { class: "text-link", href: "#/ledger-sight" }, "Start another scenario →")),
      el("div", { class: "ledger-demo-result-cards" },
        el("article", {}, el("span", {}, "Policy"), el("strong", {}, decisionText), el("small", {}, (decision.reason_code || "").replaceAll("_", " "))),
        el("article", {}, el("span", {}, "Connector"), el("strong", {}, "mock_sap"), el("small", {}, "Synthetic only; no external write")),
        el("article", {}, el("span", {}, "Approval"), el("strong", {}, run.approval?.decision || (decision.approval_required ? "Required" : "Not required")), el("small", {}, run.approval?.by || ""))),
      run.proposal ? el("section", { class: "module-panel" }, el("h3", {}, "Proposed allocation"),
        el("p", {}, `${run.proposal.currency} ${(run.proposal.amount_minor / 100).toFixed(2)} → invoice ${run.proposal.invoice_id} · reference ${run.proposal.reference}`))
        : el("p", { class: "ledger-demo-note" }, "No allocation proposal was authorized for this result."),
      el("section", { class: "module-panel" }, el("h3", {}, "Six-step agent trace"), el("p", { class: "help" }, `${overview.agent_mode === "deterministic" ? "Deterministic mode: no model is configured; do not describe this run as model-generated." : `Configured analysis mode: ${overview.agent_mode}.`} Each step is constrained by the deterministic policy gate.`), trace),
      el("section", { class: "module-panel" }, el("h3", {}, "Run evidence"), el("p", {}, `Run ID: ${run.run_id}`),
        el("p", {}, `Input fingerprint: ${run.input_digest || "not available"}`), verifyButton), ...actions);
  };
  const historyRows = recentRuns.map(run => el("tr", {},
    el("td", {}, run.receipt_id),
    el("td", {}, `${run.currency} ${(run.amount_minor / 100).toFixed(2)}`),
    el("td", {}, (run.status || "").replaceAll("_", " ")),
    el("td", {}, run.policy_decision?.decision || "—"),
    el("td", {}, el("a", { href: `#/ledger-sight/${run.run_id}` }, "Open →"))));
  const history = recentRuns.length ? el("section", { class: "module-panel" }, el("h3", {}, "Recent runs"),
    el("div", { class: "table-wrap" }, el("table", { class: "module-table" },
      el("thead", {}, el("tr", {}, ["Receipt", "Amount", "Status", "Decision", ""].map(h => el("th", {}, h)))),
      el("tbody", {}, historyRows))))
    : el("p", { class: "empty-state" }, "No workflow runs yet. Choose a scenario to see the real API workflow.");
  main.replaceChildren(moduleFrame("TRUSTOPS CORE · LEDGERSIGHT", "LedgerSight AR/Cash", subtitle,
    safety,
    el("section", { class: "ledger-demo-status" }, el("strong", {}, overview.mode === "sandbox" ? "Controlled runtime ready" : "Runtime unavailable in this environment"),
      el("span", {}, `${overview.agents.length} bounded roles · ${overview.agent_mode === "deterministic" ? "deterministic checks" : overview.agent_mode} · ${overview.connector_status}`)),
    el("section", { class: "module-panel" }, el("h3", {}, "How this workflow works"),
      el("p", {}, "A receipt is compared with invoice candidates. TrustOps records the agent trace, applies a deterministic policy, routes ambiguity or high value for review, and only then allows a controlled proposal."), stages),
    el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "RUN A CONTROLLED EXAMPLE"), el("h3", {}, "Choose a scenario")),
      el("span", { class: "tag" }, "4 synthetic cases")),
      canStart ? scenarioCards : el("p", { class: "empty-state" }, "Your current role cannot start this workflow."),
      overview.mode !== "sandbox" ? el("p", { class: "module-note" }, "The governed runtime is enabled only in the local development environment.") : ""),
    history, detail));
  if (selectedRunId) await drawRun(selectedRunId);
};

const assessmentRoster = registry => registry.catalog.filter(agent => agent.group === "assessment" ||
  ["cloudseals.swaska.evidence_extractor", "cloudseals.swaska.findings_summarizer"].includes(agent.agent_id));
routes.agents = async () => {
  const registry = await api("/v1/agents");
  const catalog = assessmentRoster(registry);
  const groups = [
    ["assessment", "Assessment team", "Understand the AI system, assess the evidence and prepare a reviewed report."],
    ["assistant", "Assessment assistants", "Help people answer questions and understand findings."]
  ];
  const friendlyStatus = status => status.includes("Needs") || status.includes("unavailable") ? "medium" : "ok";
  main.replaceChildren(moduleFrame("ASSESSMENT SUPPORT", "Assessment team", "Specialists help prepare evidence-backed analysis. People review findings and publish the report.",
    el("div", {class:"agent-directory-summary"}, el("strong",{},"Evidence → Assessment → Review → Report"),
      el("span",{},"Use each specialist from the relevant assessment step."),
      el("a",{class:"btn secondary",href:"#/agent-flow"},"View assessment process")),
    ...groups.map(([id,title,description]) => el("section",{class:"agent-directory-team","aria-label":title},
      el("div",{class:"module-panel-heading"},el("div",{},el("h3",{},title),el("p",{class:"help"},description)),
        el("span",{class:"tag"},`${catalog.filter(a=>a.group===id).length} specialists`)),
      el("div",{class:"agent-directory-grid"},catalog.filter(a=>a.group===id).map(agent=>el("article",{class:"module-panel agent-directory-card"},
        el("span",{class:`tag ${friendlyStatus(agent.availability)}`},agent.availability),
        el("h4",{},agent.name),el("p",{},agent.purpose),
        el("details",{},el("summary",{},"Responsibilities & limits"),el("p",{class:"help"},agent.authority),el("code",{},agent.agent_id))))))),
    el("section",{class:"module-panel evidence-workflow-summary"},el("h3",{},registry.evidence_workflow.name),
      el("p",{},registry.evidence_workflow.description),el("a",{class:"text-link",href:"#/assessments"},"Open an assessment →"))));
};

routes["tenant-settings"] = async (tenantId) => {
  let tenant = state.me.tenant;
  if (state.me.roles.includes("cloudseals_admin")) {
    const { items } = await api("/v1/admin/tenants");
    tenant = items.find((item) => item.tenant_id === tenantId) || (items.length === 1 ? items[0] : null);
    if (!tenant) return main.replaceChildren(moduleFrame("ADMINISTRATION · TENANT", "Tenant settings", "Choose a tenant to review its settings.",
      el("section", { class: "module-card-grid" }, items.map((item) => moduleCard(item.name || item.tenant_id,
        `Industry: ${item.industry || "Not set"} · Residency: ${item.residency_profile || "Not set"}`, "TENANT", `tenant-settings/${item.tenant_id}`)))));
  }
  if (!tenant) return main.replaceChildren(moduleFrame("ADMINISTRATION · TENANT", "Tenant settings", "No tenant context is available for this identity.",
    el("p", { class: "empty-state" }, "Tenant settings are unavailable.")));
  const canManage = state.me.roles.includes("cloudseals_admin");
  const toggle = el("input", { type: "checkbox", id: "preliminary-report", checked: Boolean(tenant.allow_preliminary_report), disabled: !canManage });
  const save = el("button", { disabled: !canManage, onclick: safe(async () => {
    const updated = await api(`/v1/admin/tenants/${tenant.tenant_id}/settings`, { method: "PUT", body: { allow_preliminary_report: toggle.checked } });
    state.me.tenant = updated; toast("Tenant setting saved");
  }) }, "Save setting");
  main.replaceChildren(moduleFrame("ADMINISTRATION · TENANT", "Tenant settings", "Tenant identity and report visibility controls.",
    el("section", { class: "module-panel tenant-settings-panel" }, el("span", { class: "module-card-status" }, canManage ? "ADMIN ACCESS" : "READ ONLY"),
      el("h3", {}, tenantLabel(tenant)),
      el("dl", { class: "tenant-facts" }, el("div", {}, el("dt", {}, "Tenant ID"), el("dd", {}, tenant.tenant_id)),
        el("div", {}, el("dt", {}, "Industry"), el("dd", {}, tenant.industry || "Not provided")),
        el("div", {}, el("dt", {}, "Residency"), el("dd", {}, tenant.residency_profile || "Not configured"))),
      el("label", { class: "setting-toggle", for: "preliminary-report" }, toggle, "Allow preliminary report visibility"),
      el("p", { class: "module-note" }, "Preliminary reports remain visibly marked as draft; this setting does not approve or publish reports."), save)));
};

async function reviewPanel(ctx, r, draw) {
  const { items } = await api(`/v1/assessments/${ctx.aid}/findings`);
  const reason = el("textarea", { id: `rr-${r.report_id}`, rows: 2, placeholder: "Reviewer reason (required)" });
  reason.value = ctx.reason || "";                       // survive panel re-renders after each action
  reason.addEventListener("input", () => { ctx.reason = reason.value; });
  const published = r.status === "published";
  const adjust = (f) => { const s = el("select", { "aria-label": `Status for ${f.rule_id}`, disabled: published }, ["Confirmed gap", "Potential gap", "No gap evidenced", "Not applicable"].map((o) => el("option", { value: o, selected: o === f.status }, o)));
    s.addEventListener("change", safe(async () => { if (!reason.value.trim()) { toast("Enter a reviewer reason first", true); s.value = f.status; return; } await api(`/v1/assessments/${ctx.aid}/findings/${f.rule_id}/review`, { method: "POST", body: { status: s.value, reason: reason.value } }); toast("Finding updated"); draw(); })); return s; };
  const decide = (d) => safe(async () => { if (!reason.value.trim()) return toast("Enter a reviewer reason", true); await api(`/v1/assessments/${ctx.aid}/reviews/${r.report_id}/decision`, { method: "POST", idem: true, body: { decision: d, reviewer_reason: reason.value } }); toast(`Decision recorded: ${d}`); draw(); });
  const sumOut = el("div", { "aria-live": "polite" });
  const kids = [findingsTable(items, adjust), agentButton("Summarise findings (advisory)", sumOut, async () => {
    const r = await api(`/v1/assessments/${ctx.aid}/agents/findings-summary`, { method: "POST" });
    return advisoryBox(`Findings summary (${r.mode})`, r.items.map((i) => `${i.rule_id}: ${i.summary} (${i.uncertainty})`));
  }), sumOut];
  if (state.me.roles.includes("cloudseals_reviewer") && !published) kids.push(el("label", { for: reason.id }, "Reviewer reason"), reason,
    el("div", { class: "row" }, el("button", { onclick: decide("approve") }, "Approve & publish"), el("button", { class: "secondary", onclick: decide("request_clarification") }, "Request clarification"), el("button", { class: "danger", onclick: decide("reject") }, "Reject")));
  return el("div", {}, kids);
}

// ---------- customer team ----------
routes.team = async () => {
  const out = el("p", { class: "help", "aria-live": "polite" });
  const sel = el("select", { id: "role" }, ["customer_architect", "customer_risk", "customer_contributor"].map((r) => el("option", { value: r }, r)));
  main.replaceChildren(moduleFrame("WORKSPACE · PEOPLE", "Team", "Invite colleagues into this tenant workspace and assign the least access they need.",
    el("section", { class: "module-card-grid team-actions" },
      el("form", { class: "module-panel", onsubmit: safe(async (event) => { event.preventDefault(); const r = await api("/v1/tenant/invitations", { method: "POST", body: { role: sel.value } }); out.textContent = r.invitation_token ? `Invitation token (local development only): ${r.invitation_token}` : "Invitation created. Delivery depends on workspace email configuration."; }) },
        el("span", { class: "eyebrow" }, "INVITE MEMBER"), el("h3", {}, "Choose a workspace role"), el("label", { for: "role" }, "Role"), sel,
        el("p", { class: "help" }, "Administrators and architects can coordinate assessment work; contributors receive scoped access."), el("button", {}, "Create invitation"), out),
      el("form", { class: "module-panel", onsubmit: safe(async (event) => { event.preventDefault(); await api("/v1/invitations/accept", { method: "POST", body: { token: $("#tok").value.trim() } }); state.me = null; toast("Invitation accepted"); render(); }) },
        el("span", { class: "eyebrow" }, "JOIN WORKSPACE"), el("h3", {}, "Accept an invitation"), el("label", { for: "tok" }, "Invitation token"), el("input", { id: "tok", required: true }),
        el("p", { class: "help" }, "Use the invitation token provided by your workspace administrator."), el("button", { class: "secondary" }, "Accept invitation")))));
};

// ---------- staff ----------
routes.admin = async () => {
  const m = await api("/v1/admin/metrics");
  const labels = { registrations: "Registrations", assessments: "Assessments", submitted: "Submitted", review_queue: "In review queue", published_reports: "Published reports" };
  main.replaceChildren(moduleFrame("CLOUDSEALS · ADMINISTRATION", "Portfolio", "A cross-tenant operational overview for authorized CloudSeals staff.",
    el("section", { class: "module-metrics" }, Object.entries(labels).map(([key, label]) => el("article", {}, el("span", {}, label), el("strong", {}, String(m[key] ?? 0))))),
    el("section", { class: "module-card-grid" }, moduleCard("Review queue", "Open submitted assessments awaiting reviewer action.", `${m.review_queue ?? 0} IN QUEUE`, "queue"),
      moduleCard("Registrations", "Review organisation access requests and engagement verification.", `${m.registrations ?? 0} REQUESTS`, "registrations"),
      moduleCard("Activity", "Inspect recorded administrative and assessment events.", "AUDIT VIEW", "activity"))));
};
routes.queue = async () => {
  const { items } = await api("/v1/admin/review-queue");
  const rows = items.map((i) => el("tr", {},
    el("td", {}, i.assessment_id.slice(0, 8)), el("td", {}, String(i.finding_count)),
    el("td", {}, el("span", { class: "tag medium" }, i.status)),
    el("td", {}, el("a", { href: `#/assessment/${i.assessment_id}` }, "Review assessment →"))));
  const content = items.length
    ? el("div", { class: "table-wrap" }, el("table", { class: "module-table" },
      el("thead", {}, el("tr", {}, ["Assessment", "Findings", "Status", ""].map((h) => el("th", { scope: "col" }, h)))), el("tbody", {}, rows)))
    : el("p", { class: "empty-state" }, "Nothing is waiting for review.");
  main.replaceChildren(moduleFrame("CLOUDSEALS · REVIEW", "Review queue", "Review submitted assessment findings, record a decision, and publish only approved reports.",
    el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "ASSESSMENTS AWAITING REVIEW"), el("h3", {}, `${items.length} in queue`))), content)));
};
routes.registrations = async () => {
  const { items } = await api("/v1/admin/registrations");
  const act = (r, d) => safe(async () => { const x = await api(`/v1/admin/registrations/${r.registration_id}/decision`, { method: "POST", body: { decision: d, reason: "Portal decision" } }); toast(x.invitation_token ? `Approved. Local development invitation token: ${x.invitation_token}` : `Registration ${x.status}`); render(); });
  const rows = items.map((r) => el("tr", {},
    el("td", {}, r.organisation_name), el("td", {}, r.work_email),
    el("td", {}, el("span", { class: `tag ${r.engagement_verified ? "ok" : "medium"}` }, r.engagement_verified ? "Verified" : "Not verified")),
    el("td", {}, r.status), el("td", {}, r.status === "pending_approval"
      ? el("div", { class: "row" }, el("button", { disabled: !r.engagement_verified, onclick: act(r, "approve") }, "Approve"), el("button", { class: "secondary", onclick: act(r, "reject") }, "Reject")) : "—")));
  const content = items.length
    ? el("div", { class: "table-wrap" }, el("table", { class: "module-table" },
      el("thead", {}, el("tr", {}, ["Organisation", "Email", "Engagement", "Status", "Decision"].map((h) => el("th", { scope: "col" }, h)))), el("tbody", {}, rows)))
    : el("p", { class: "empty-state" }, "No workspace access requests.");
  main.replaceChildren(moduleFrame("CLOUDSEALS · CUSTOMER ONBOARDING", "Registrations", "Verify each organisation request and engagement before granting workspace access.",
    el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "ACCESS REQUESTS"), el("h3", {}, `${items.length} total`))), content)));
};
routes.activity = async () => {
  const q = { text: "", action: "", actor: "", from: "", to: "", offset: 0, limit: 50 };
  const out = el("div", {}), cats = el("div", { class: "case-filters", role: "group", "aria-label": "Filter by category" });
  const params = (extra = {}) => {
    const u = new URLSearchParams();
    if (q.text) u.set("q", q.text); if (q.action) u.set("action", q.action); if (q.actor) u.set("actor", q.actor);
    if (q.from) u.set("since", String(new Date(`${q.from}T00:00:00`).getTime() / 1000)); if (q.to) u.set("until", String(new Date(`${q.to}T23:59:59`).getTime() / 1000));
    for (const [k, v] of Object.entries(extra)) u.set(k, String(v)); return u.toString();
  };
  const load = safe(async () => {
    const r = await api(`/v1/admin/activity?${params({ limit: q.limit, offset: q.offset })}`);
    cats.replaceChildren(el("button", { class: `chip${q.action ? "" : " on"}`, onclick: () => { q.action = ""; q.offset = 0; load(); } }, "All", el("em", {}, String(Object.values(r.categories).reduce((a, b) => a + b, 0)))),
      ...Object.entries(r.categories).map(([c, n]) => el("button", { class: `chip${q.action === `${c}.` ? " on" : ""}`, onclick: () => { q.action = `${c}.`; q.offset = 0; load(); } }, c, el("em", {}, String(n)))));
    const from = r.total ? r.offset + 1 : 0, to = Math.min(r.offset + r.limit, r.total);
    out.replaceChildren(r.items.length ? el("div", { class: "table-wrap" }, el("table", { class: "module-table" },
      el("thead", {}, el("tr", {}, ["When", "Who", "Action", "Reference"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, r.items.map((a) => el("tr", {}, el("td", {}, new Date(a.at * 1000).toLocaleString()), el("td", {}, a.email || a.sub, a.email ? el("br") : "", a.email ? el("small", { class: "help" }, a.sub) : ""),
        el("td", {}, el("span", { class: "audit-action" }, a.action)), el("td", {}, String(a.ref).slice(0, 80))))))) : el("p", { class: "empty-state" }, "No events match these filters."),
      el("div", { class: "row audit-pager" }, el("span", { class: "help" }, `Showing ${from} to ${to} of ${r.total}`),
        el("button", { class: "secondary", disabled: q.offset === 0, onclick: () => { q.offset = Math.max(0, q.offset - q.limit); load(); } }, "← Newer"),
        el("button", { class: "secondary", disabled: to >= r.total, onclick: () => { q.offset += q.limit; load(); } }, "Older →")));
  });
  const field = (name, type, ph, key) => el("input", { type, placeholder: ph, "aria-label": ph, value: q[key], onchange: (e) => { q[key] = e.target.value.trim(); q.offset = 0; load(); } });
  main.replaceChildren(moduleFrame("CLOUDSEALS · AUDIT", "Audit logs", "Every administrative, review and agent event this environment has recorded. Filter, page through it, or export it.",
    el("section", { class: "module-panel" }, el("div", { class: "row case-tools" }, field("q", "search", "Search action, reference or person", "text"), field("actor", "text", "Person", "actor"),
      el("label", { class: "uc-picker" }, "From", field("from", "date", "From date", "from")), el("label", { class: "uc-picker" }, "To", field("to", "date", "To date", "to")),
      el("button", { class: "secondary", onclick: safe(async (e) => { e.currentTarget.disabled = true; await dl(`/v1/admin/activity/export?${params()}`, "activity-log.csv"); e.currentTarget.disabled = false; }) }, "Export CSV")),
      cats, out)));
  load();
};

routes["service-health"] = async () => {
  const draw = async (probe) => {
    const h = await api(`/v1/admin/health${probe ? "?probe=true" : ""}`);
    const dot = (s) => el("span", { class: `hdot ${s}`, "aria-hidden": "true" });
    const probeLine = (p) => p ? el("p", { class: p.ok ? "help" : "module-note" }, p.ok ? `Live check passed in ${p.ms} ms` : `Live check failed after ${p.ms} ms: ${p.error}`) : "";
    const card = (title, status, lines, extra = "") => el("article", { class: "module-panel health-card" }, el("div", { class: "health-head" }, dot(status), el("h3", {}, title)),
      el("dl", { class: "health-list" }, lines.filter(Boolean).map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, String(v))))), extra);
    const upt = (s) => s > 3600 ? `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min` : `${Math.floor(s / 60)} min`;
    const calls = Object.entries(h.agents.calls_last_24h);
    main.replaceChildren(moduleFrame("CLOUDSEALS · OPERATIONS", "Service health", "What this environment is running on and whether each part is working. Live checks make small real calls to the model and the signing key.",
      el("p", {}, el("button", { onclick: safe(async (e) => { e.currentTarget.disabled = true; e.currentTarget.textContent = "Checking…"; await draw(true); }) }, "Run live checks"), " ", el("button", { class: "secondary", onclick: () => draw(false) }, "Refresh")),
      el("section", { class: "module-card-grid health-grid" },
        card("Service", "ok", [["Revision", h.service.revision || "local"], ["Environment", h.service.environment], ["Sign-in", h.service.auth], ["Uptime", upt(h.service.uptime_seconds)]]),
        card("Application state", h.state.last_save_error ? "bad" : h.state.durable ? "ok" : "warn", [["Storage", h.state.backend], ["Durable", h.state.durable ? "Yes" : "No (lost on restart)"],
          ["Saves since start", h.state.saves], ["Last save", h.state.last_save_at ? new Date(h.state.last_save_at * 1000).toLocaleTimeString() : "none yet"], h.state.last_save_error ? ["Last error", h.state.last_save_error] : null]),
        card("Evidence storage", h.evidence_store.backend === "local-disk" ? "warn" : "ok", [["Backend", h.evidence_store.backend]]),
        card("Malware scanning", h.malware_scanner.probe ? (h.malware_scanner.probe.ok ? "ok" : "bad") : h.malware_scanner.configured ? "ok" : "warn",
          [["Engine", h.malware_scanner.engine || "Basic byte checks only (no scanner configured)"], ["Uploads", h.malware_scanner.configured ? "Scanned before use; rejected if the scanner is down" : "Checked for known signatures only"]], probeLine(h.malware_scanner.probe)),
        card("AI model", h.model.probe ? (h.model.probe.ok ? "ok" : "bad") : h.model.configured ? "warn" : "off", [["Provider", h.model.provider || "none (deterministic agents only)"], ["Model", h.model.model_id || "n/a"], ["Connection", h.model.probe ? h.model.probe.ok ? "Verified in this live check" : "Live check failed" : h.model.configured ? "Configured; live check not run" : "Not configured"]], probeLine(h.model.probe)),
        card("Evidence signing", h.evidence_signing.probe ? (h.evidence_signing.probe.ok ? "ok" : "bad") : h.evidence_signing.configured ? "ok" : "off",
          [["Signer", h.evidence_signing.configured ? "Cloud KMS" : "Local hash chain only"], ["Key version", h.evidence_signing.key_version ? h.evidence_signing.key_version.split("/").slice(-5).join("/") : "n/a"]], probeLine(h.evidence_signing.probe)),
        card("Agents, last 24 hours", calls.length ? "ok" : "off", [["Advisory agents registered", h.agents.advisory_agents], ...calls.map(([k, v]) => [k.replace("agent.", "").replaceAll("_", " "), v])]),
        card("Records", "ok", [["Users", h.counts.users], ["Assessments", h.counts.assessments], ["Cases", h.counts.cases], ["Audit events", h.counts.audit_events]]))));
  };
  await draw(false);
};


// ---------- Assessment process: actual evidence, review and publication status ----------
routes["agent-flow"] = async (aidArg) => {
  const {items:assessments}=await api("/v1/assessments");
  if(!assessments.length) return main.replaceChildren(moduleFrame("YOUR ASSESSMENT JOURNEY","Assessment process","Details → Evidence → Assessment → Review & report",
    el("p",{class:"empty-state"},"Create an assessment for an AI system to begin."),el("a",{class:"btn",href:"#/assessments"},"Create an assessment")));
  const aid=assessments.some(a=>a.assessment_id===aidArg)?aidArg:assessments[0].assessment_id;
  const [detail,evidence,inventory,{items:reports}]=await Promise.all([api(`/v1/assessments/${aid}`),api(`/v1/assessments/${aid}/evidence`),api(`/v1/assessments/${aid}/inventory`),api("/v1/report-library")]);
  const clean=evidence.items.filter(e=>e.state==="clean"), published=reports.filter(r=>r.assessment_id===aid);
  const picker=el("label",{class:"process-picker"},"Assessment",el("select",{onchange:e=>go(`#/agent-flow/${e.target.value}`)},assessments.map(a=>el("option",{value:a.assessment_id,selected:a.assessment_id===aid},displayAISystemName(a.ai_system_name)))));
  const stage=(number,title,status,text,href,label)=>el("article",{class:"module-panel assessment-process-stage"},
    el("div",{class:"module-panel-heading"},el("div",{},el("span",{class:"eyebrow"},`STEP ${number}`),el("h3",{},title)),el("span",{class:"tag"},status)),
    el("p",{},text),el("a",{class:"btn secondary",href},label));
  main.replaceChildren(moduleFrame("YOUR ASSESSMENT JOURNEY","Assessment process","Follow one AI system from evidence collection to a reviewed report.",picker,
    el("div",{class:"assessment-process-grid"},
      stage(1,"Details",detail.status,"Describe the AI system, its purpose, owners and how it is used.",`#/assessment/${aid}`,"Open assessment details"),
      stage(2,"Evidence",`${clean.length} clean evidence file${clean.length===1?"":"s"}`,"Upload available documents or attach application observations. Files are checked before analysis.",`#/assessment/${aid}`,"Add evidence & answer questions"),
      stage(3,"Assessment",`${detail.progress.required_answered} / ${detail.progress.required_total} required answers`,"Complete the relevant questions and analyse supporting documents. Candidate findings need reviewer validation.",`#/use-cases/${aid}`,"View document analysis"),
      stage(4,"Review & report",published.length?`${published.length} published report${published.length===1?"":"s"}`:detail.status==="In progress"?"Not submitted":detail.status,
        published.length?"Your reviewed report is available in Reports.":"A reviewer checks the evidence and findings before publishing your report.",published.length?"#/reports":`#/assessment/${aid}`,published.length?"View published reports":"Open assessment for review")),
    el("section",{class:"module-panel process-evidence-summary"},el("h3",{},"Evidence and analysis"),
      el("p",{},`${evidence.items.length} uploaded file(s) · ${inventory.use_cases.length} candidate AI use case(s).`),
      el("p",{class:"help"},"Missing information is recorded for follow-up. A missing document alone does not establish that a control is absent.")),
    el("a",{class:"text-link",href:"#/agents"},"See the assessment team →")));
};

// ---------- AI use cases: document inventory and framework gap analysis ----------
const REVIEW_ROLES = ["cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer"];
const TIER_LABEL = { prohibited: "Prohibited practice", high_risk: "High risk", limited_risk: "Limited risk", minimal_risk: "Minimal risk" };
const TIER_CLASS = { prohibited: "high", high_risk: "high", limited_risk: "medium", minimal_risk: "ok" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const STATUS_LABEL = { UNREVIEWED: "Needs review", VALIDATED: "Validated", REJECTED: "Rejected" };
let useCaseNote = "";

function statusChip(status) { return el("span", { class: `uc-status uc-${String(status).toLowerCase()}` }, STATUS_LABEL[status] || status); }
function reviewControls(label, onDecide) {
  const reason = el("input", { placeholder: "Reviewer reason (required)", maxlength: 2000, "aria-label": `${label}: reviewer reason` });
  const go_ = (status) => safe(async () => { if (!reason.value.trim()) return toast("Enter a reviewer reason first", true); await onDecide(status, reason.value.trim()); });
  return el("div", { class: "uc-review" }, reason, el("button", { onclick: go_("validated") }, "Validate"), el("button", { class: "secondary", onclick: go_("rejected") }, "Reject"));
}

function useCaseCard(aid, u, canReview, redraw) {
  const meta = [["Business owner", u.business_owner], ["Technical owner", u.technical_owner], ["Model type", u.model_type],
    ["Decision authority", u.decision_authority?.replaceAll("_", " ")], ["Foundation models", u.foundation_models_used?.join(", ")], ["Data sources", u.data_sources?.join(", ")]]
    .filter(([, v]) => v);
  return el("article", { class: `uc-card uc-card-${String(u.status).toLowerCase()}` },
    el("div", { class: "uc-head" }, el("h4", {}, u.name), el("span", { class: `tag ${TIER_CLASS[u.risk_tier] || ""}` }, TIER_LABEL[u.risk_tier] || u.risk_tier),
      statusChip(u.status), el("span", { class: "uc-conf", title: "How sure the agent is that this use case exists in the document" }, `${Math.round(u.extraction_confidence * 100)}% confidence`)),
    el("p", { class: "uc-desc" }, u.description),
    u.needs_validation && u.status === "UNREVIEWED" ? el("p", { class: "module-note" }, "Low confidence: check this against the source document before relying on it.") : "",
    u.injection_flagged ? el("p", { class: "module-note" }, "The source document contained instruction-like text. It was treated as data only.") : "",
    meta.length ? el("dl", { class: "uc-meta" }, meta.map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, v)))) : "",
    el("p", { class: "uc-why" }, el("strong", {}, "Why this risk tier (candidate, not a legal conclusion): "), u.risk_tier_rationale),
    el("div", { class: "uc-quotes" }, el("span", { class: "eyebrow" }, `EVIDENCE FROM ${u.source_filename}`), u.source_quotes.map((q) => el("blockquote", {}, q))),
    u.status !== "UNREVIEWED" ? el("p", { class: "help" }, canReview ? `${STATUS_LABEL[u.status]} by ${u.reviewed_by}: ${u.review_reason}` : `${STATUS_LABEL[u.status]} by CloudSeals`)
      : canReview ? reviewControls(u.name, async (status, reason) => { await api(`/v1/assessments/${aid}/inventory/use-cases/${u.use_case_id}`, { method: "PATCH", body: { status, reason } }); toast(`Use case ${status}`); redraw(); })
        : el("p", { class: "help" }, "Waiting for a CloudSeals reviewer to validate this use case."));
}

function gapCard(aid, g, canReview, redraw) {
  return el("article", { class: `uc-card uc-gap uc-sev-${g.severity}` },
    el("div", { class: "uc-head" }, el("h4", {}, g.title), el("span", { class: `tag sev-${g.severity}` }, g.severity.toUpperCase()), statusChip(g.status),
      el("span", { class: "uc-conf" }, `${g.framework_id.replaceAll("_", " ").toUpperCase()} · ${g.framework_clause.replaceAll("_", " ")}`)),
    el("p", { class: "uc-desc" }, g.description),
    el("p", { class: "uc-why" }, el("strong", {}, "Suggested action: "), g.recommendation, ` (about ${g.estimated_effort_days} person-days, ${g.suggested_timeline} days)`),
    g.evidence_quotes.length ? el("div", { class: "uc-quotes" }, el("span", { class: "eyebrow" }, "EVIDENCE"), g.evidence_quotes.map((q) => el("blockquote", {}, q))) : "",
    g.status !== "UNREVIEWED" ? el("p", { class: "help" }, canReview ? `${STATUS_LABEL[g.status]} by ${g.reviewed_by}: ${g.review_reason}` : `${STATUS_LABEL[g.status]} by CloudSeals`)
      : canReview ? reviewControls(g.title, async (status, reason) => { await api(`/v1/assessments/${aid}/gaps/${g.gap_id}`, { method: "PATCH", body: { status, reason } }); toast(`Gap ${status}`); redraw(); }) : "");
}


const PRINCIPLE_LABEL = { model_agnostic: "P1 Model Agnostic", neuro_symbolic: "P2 Neuro-Symbolic", digital_twin: "P3 Digital Twin", evidence_fabric: "P4 Evidence Fabric", model_welfare: "P5 Model Welfare" };
const BAND_LABEL = { "0-90": "0 to 90 days", "90-180": "90 to 180 days", "180-365": "180 to 365 days", "365+": "Beyond 365 days" };
function scoreBar(score) { const f = el("b", { role: "presentation" }); f.style.width = `${Math.round(score * 20)}%`; return el("i", { class: "mat-track" }, f); }

function maturityPanel(aid, inv, canReview, validatedUc, redraw) {
  const m = inv.maturity;
  const run = el("button", { disabled: !validatedUc, title: validatedUc ? "" : "Validate at least one use case first", onclick: safe(async (e) => {
    const button = e.currentTarget, label = button.textContent;
    button.disabled = true; button.setAttribute("aria-busy", "true"); button.textContent = "Scoring…";
    try {
      const r = await api(`/v1/assessments/${aid}/maturity/run`, { method: "POST" });
      useCaseNote = r.mode === "unavailable" ? r.note : r.maturity ? "Maturity score drafted for review." : r.note;
      await redraw();
    } finally { button.disabled = false; button.setAttribute("aria-busy", "false"); button.textContent = label; }
  }) }, m ? "Re-run maturity scoring" : "Run maturity scoring");
  const body = m ? el("div", {},
    el("div", { class: "mat-head" }, el("strong", { class: "mat-overall" }, `${m.overall_score}`), el("span", {}, " / 5 overall"), statusChip(m.status)),
    Object.keys(PRINCIPLE_LABEL).map((p) => el("div", { class: "mat-row" }, el("div", { class: "mat-line" }, el("span", {}, PRINCIPLE_LABEL[p]), scoreBar(m.scores[p]), el("em", {}, String(m.scores[p]))),
      el("p", { class: "uc-why" }, m.rationale[p], m.evidence_refs[p]?.length ? ` (${m.evidence_refs[p].length} cited item${m.evidence_refs[p].length === 1 ? "" : "s"})` : ""))),
    m.capped_for_missing_evidence?.length ? el("p", { class: "module-note" }, `Scores for ${m.capped_for_missing_evidence.join(", ")} were capped at 2.0 because no evidence was cited for a score of 3 or more.`) : "",
    m.improvement_priorities?.length ? el("div", {}, el("span", { class: "eyebrow" }, "IMPROVEMENT PRIORITIES"), el("ul", { class: "fw-controls" }, m.improvement_priorities.map((x) => el("li", {}, x)))) : "",
    m.notes_for_architect ? el("p", { class: "help" }, `Notes for the architect: ${m.notes_for_architect}`) : "",
    m.status !== "UNREVIEWED" ? el("p", { class: "help" }, `${STATUS_LABEL[m.status]} by ${m.reviewed_by}: ${m.review_reason}`)
      : canReview ? reviewControls("Maturity", async (status, reason) => { await api(`/v1/assessments/${aid}/maturity`, { method: "PATCH", body: { status, reason } }); toast(`Maturity ${status}`); redraw(); }) : "")
    : el("p", { class: "empty-state" }, validatedUc ? "No maturity score yet." : "Validate a use case to unlock maturity scoring.");
  return el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "STEP 3 · MATURITY SCORER"), el("h3", {}, "Governance maturity"))),
    el("p", { class: "help" }, "Five principles scored 1 to 5. A score of 3 or more needs cited evidence; otherwise it is capped at 2. The overall score is calculated here, not by the model."), el("div", { class: "row" }, run), body);
}

function roadmapPanel(aid, inv, canReview, ready, redraw) {
  const items = inv.roadmap || [];
  const run = el("button", { disabled: !ready, title: ready ? "" : "Validate a gap or the maturity score first", onclick: safe(async (e) => {
    const button = e.currentTarget, label = button.textContent;
    button.disabled = true; button.setAttribute("aria-busy", "true"); button.textContent = "Building roadmap…";
    try {
      const r = await api(`/v1/assessments/${aid}/roadmap/run`, { method: "POST" });
      useCaseNote = r.mode === "unavailable" ? r.note : `${r.items.length} roadmap item(s) drafted${r.rejected ? `; ${r.rejected} unusable item(s) were dropped` : ""}${r.uncovered_gaps?.length ? `; ${r.uncovered_gaps.length} critical or high gap(s) are not covered yet` : ""}.`;
      await redraw();
    } finally { button.disabled = false; button.setAttribute("aria-busy", "false"); button.textContent = label; }
  }) }, items.length ? "Re-run roadmap" : "Build roadmap");
  const card = (i) => el("article", { class: `uc-card uc-card-${String(i.status).toLowerCase()}` },
    el("div", { class: "uc-head" }, el("h4", {}, i.title), el("span", { class: "tag" }, i.responsible_role), el("span", { class: "tag" }, `${i.effort_days} person-days`), el("span", { class: "tag" }, `cost: ${i.estimated_cost_band}`), statusChip(i.status)),
    el("p", { class: "uc-desc" }, i.description),
    i.timeline_adjusted ? el("p", { class: "module-note" }, "Moved into the first 90 days because it addresses a critical gap.") : "",
    el("ul", { class: "fw-controls" }, i.success_criteria.map((c) => el("li", {}, c))),
    i.dependencies.length ? el("p", { class: "help" }, `Depends on ${i.dependencies.length} other item${i.dependencies.length === 1 ? "" : "s"} in this roadmap.`) : "",
    i.status !== "UNREVIEWED" ? el("p", { class: "help" }, `${STATUS_LABEL[i.status]} by ${i.reviewed_by}: ${i.review_reason}`)
      : canReview ? reviewControls(i.title, async (status, reason) => { await api(`/v1/assessments/${aid}/roadmap/${i.item_id}`, { method: "PATCH", body: { status, reason } }); toast(`Roadmap item ${status}`); redraw(); }) : "");
  const bands = ["0-90", "90-180", "180-365", "365+"].filter((b) => items.some((i) => i.timeline_band === b));
  return el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "STEP 4 · ROADMAP AGENT"), el("h3", {}, `${items.length} roadmap item${items.length === 1 ? "" : "s"}`))),
    el("p", { class: "help" }, "Built from validated gaps. Critical gaps always land in the first 90 days, dependencies are checked for loops, and effort totals are calculated here."),
    el("div", { class: "row" }, run), bands.length ? bands.map((b) => el("div", {}, el("h4", { class: "section-title" }, BAND_LABEL[b]), el("div", { class: "uc-list" }, items.filter((i) => i.timeline_band === b).map(card))))
      : el("p", { class: "empty-state" }, ready ? "No roadmap yet." : "Validate a gap or the maturity score to unlock the roadmap."));
}


function overlayPanel(aid, inv, canReview, validatedUc, redraw) {
  const o = inv.overlay;
  const run = el("button", { disabled: !validatedUc, title: validatedUc ? "" : "Validate at least one use case first", onclick: safe(async (e) => {
    const button = e.currentTarget, label = button.textContent;
    button.disabled = true; button.setAttribute("aria-busy", "true"); button.textContent = "Drawing…";
    try {
      const r = await api(`/v1/assessments/${aid}/overlay/run`, { method: "POST" });
      useCaseNote = r.mode === "unavailable" ? r.note : r.overlay ? "Architecture diagrams drafted for review." : r.note;
      await redraw();
    } finally { button.disabled = false; button.setAttribute("aria-busy", "false"); button.textContent = label; }
  }) }, o ? "Redraw architecture" : "Draw architecture");
  const img = (svg, alt) => el("img", { class: "overlay-img", alt, src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}` });
  const body = o ? el("div", {}, el("div", { class: "row" }, statusChip(o.status)),
    el("div", { class: "overlay-grid" }, el("figure", {}, img(o.current_svg, "Current architecture, drawn only from what the documents evidence"), el("figcaption", {}, "Current: dashed boxes are things the documents do not evidence")),
      el("figure", {}, img(o.target_svg, "Recommended target architecture organised around the five principles"), el("figcaption", {}, "Target: organised around the five TrustOps principles"))),
    o.principles_missing_from_target.length ? el("p", { class: "module-note" }, `The target diagram does not show: ${o.principles_missing_from_target.join(", ")}.`) : "",
    o.current.nodes.some((n) => n.kind === "unknown") ? el("p", { class: "help" }, "Items marked unknown are not evidenced in the documents and are drawn dashed. Confirm them with the customer or remove them.") : "",
    o.gap_commentary.split("\n\n").map((p) => el("p", { class: "uc-desc" }, p)),
    el("span", { class: "eyebrow" }, "KEY DIFFERENCES"), el("ul", { class: "fw-controls" }, o.key_differences.map((d) => el("li", {}, d))),
    o.status !== "UNREVIEWED" ? el("p", { class: "help" }, `${STATUS_LABEL[o.status]} by ${o.reviewed_by}: ${o.review_reason}`)
      : canReview ? reviewControls("Architecture overlay", async (status, reason) => { await api(`/v1/assessments/${aid}/overlay`, { method: "PATCH", body: { status, reason } }); toast(`Architecture ${status}`); redraw(); }) : "")
    : el("p", { class: "empty-state" }, validatedUc ? "No diagram yet." : "Validate a use case to unlock the architecture overlay.");
  return el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "OPTIONAL · ARCHITECTURE OVERLAY"), el("h3", {}, "Current and target architecture"))),
    el("p", { class: "help" }, "Two diagrams drawn by the platform from a structured description. Nothing is shown as existing unless the documents evidence it. It joins the report once validated."),
    el("div", { class: "row" }, run), body);
}

async function reportPanel(aid) {
  const st = await api(`/v1/assessments/${aid}/diagnostic-report?format=json`);
  const canPublish = state.me.roles.some((r) => ["cloudseals_admin", "cloudseals_reviewer"].includes(r));
  const alreadyPublished = st.published?.source_digest === st.source_digest;
  const reason = el("input", { "aria-label": "Final report review reason", placeholder: "Final report review reason", maxlength: 2000 });
  const publish = el("button", { disabled: Boolean(st.publication_blockers.length || alreadyPublished), onclick: safe(async (e) => {
    if (!reason.value.trim()) return toast("Enter a final review reason before publishing", true);
    const button = e.currentTarget; button.disabled = true;
    try {
      await api(`/v1/assessments/${aid}/diagnostic-report/publish`, { method: "POST", idem: true, body: { reason: reason.value.trim(), source_digest: st.source_digest } });
      toast("Report and roadmap published to the customer"); await routes["use-cases"](aid);
    } finally { button.disabled = false; }
  }) }, "Publish report to customer");
  const dlBtn = (label, qs, cls = "") => el("button", { class: cls, onclick: safe(async (e) => {
    const button = e.currentTarget; button.disabled = true;
    try { await dl(`/v1/assessments/${aid}/diagnostic-report${qs}`, `diagnostic-report-${st.status}.html`); } finally { button.disabled = false; }
  }) }, label);
  return el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "STEP 5 · REPORT"), el("h3", {}, "Diagnostic report"))),
    el("p", { class: "help" }, "Contains only items a reviewer has validated. The narrative is optional and AI-drafted; everything else is assembled without a model."),
    el("p", {}, el("span", { class: `tag ${st.status === "FINAL" ? "ok" : "medium"}` }, st.status), st.missing.length ? ` Still needed: ${st.missing.join("; ")}.` : " Ready to deliver after your final check."),
    el("div", { class: "row" }, dlBtn("Download report (HTML)", ""), dlBtn("Download with AI narrative", "?narrative=true", "secondary")),
    el("p", { class: "help" }, "Downloads are reviewer previews. Publish after checking the report to give the customer the reviewed report and roadmap. The published version uses reviewed material without an AI narrative."),
    st.publication_blockers.length ? el("p", { class: "module-note" }, `Before publication: ${st.publication_blockers.join("; ")}.`) : "",
    canPublish ? el("div", { class: "row" }, reason, publish) : el("p", { class: "help" }, "A CloudSeals reviewer or admin publishes the final report."),
    alreadyPublished ? el("p", { class: "help" }, "This reviewed material is already published to the customer.") : "",
    st.versions.length ? el("div", {}, el("h4", {}, "Published versions"), st.versions.map((r) => el("p", { class: "row" },
      `Version ${r.version} · ${when(r.published_at)} · ${r.published_by}`, el("button", { class: "secondary", onclick: safe(async () => {
        await dl(`/v1/assessments/${aid}/diagnostic-report?report_id=${r.report_id}`, `diagnostic-report-v${r.version}-FINAL.html`);
      }) }, `Download version ${r.version}`)))) : "");
}

function deliveredDiagnosticPanel(aid, delivery) {
  if (!delivery) return el("section", { class: "module-panel" }, el("h3", {}, "Your report and improvement roadmap"),
    el("p", { class: "empty-state" }, "CloudSeals is preparing your diagnostic results. The reviewed report and roadmap will appear here after publication."));
  const { snapshot: s, facts: f } = delivery;
  return el("section", { class: "module-panel" }, el("span", { class: "eyebrow" }, "PUBLISHED BY CLOUDSEALS"),
    el("h3", {}, "Your report and improvement roadmap"), el("p", { class: "help" }, `Version ${delivery.version} · ${when(delivery.published_at)}`),
    el("div", { class: "row" }, el("button", { onclick: safe(async () => {
      await dl(`/v1/assessments/${aid}/diagnostic-report?report_id=${delivery.report_id}`, `diagnostic-report-v${delivery.version}-FINAL.html`);
    }) }, "Download published report (HTML)")),
    el("p", {}, `${f.validated_use_cases} reviewed AI use case(s), ${f.validated_gaps} reviewed gap(s), maturity ${f.overall_maturity_score} / 5.`),
    el("h4", {}, "Reviewed gaps"), s.gaps.length ? el("div", { class: "uc-list" }, s.gaps.map((g) => gapCard(aid, g, false, () => {})))
      : el("p", { class: "help" }, "No reviewed gaps are included in this version."),
    el("h4", {}, "Improvement roadmap"), el("p", { class: "help" }, `${f.roadmap_items} action(s), approximately ${f.roadmap_effort_days} person-days in total.`),
    el("div", { class: "uc-list" }, s.roadmap.map((r) => el("article", { class: "uc-card" }, el("h4", {}, r.title),
      el("p", {}, r.description), el("p", { class: "help" }, `${BAND_LABEL[r.timeline_band]} · ${r.responsible_role} · ${r.effort_days} person-days`),
      el("ul", { class: "fw-controls" }, r.success_criteria.map((c) => el("li", {}, c)))))));
}

function pipelineStepper(inv) {
  const v = (xs) => (xs || []).some((x) => x.status === "VALIDATED");
  const steps = [["Inventory", v(inv.use_cases)], ["Gap analysis", v(inv.gaps)], ["Maturity", inv.maturity?.status === "VALIDATED"], ["Roadmap", v(inv.roadmap)]];
  const ov = inv.overlay?.status === "VALIDATED";
  return el("ol", { class: "pipe-steps", "aria-label": "Diagnostic pipeline" }, steps.map(([n, done], i) => el("li", { class: done ? "is-done" : "" }, el("span", {}, done ? "✓" : String(i + 1)), n)),
    el("li", { class: steps.every(([, d]) => d) ? "is-done" : "" }, el("span", {}, steps.every(([, d]) => d) ? "✓" : "5"), "Report"),
    el("li", { class: `optional${ov ? " is-done" : ""}` }, el("span", {}, ov ? "✓" : "+"), "Architecture (optional)"));
}

routes["use-cases"] = async (aidArg) => {
  const { items: assessments } = await api("/v1/assessments");
  if (!assessments.length) return main.replaceChildren(moduleFrame("DIAGNOSIS · AI INVENTORY", "AI use cases", "Read documents and list the AI use cases they evidence.",
    el("p", { class: "empty-state" }, "Create an assessment and upload documents first."), el("a", { class: "btn", href: "#/assessments" }, "Go to Diagnosis")));
  const aid = assessments.some((a) => a.assessment_id === aidArg) ? aidArg : assessments[0].assessment_id;
  const canReview = state.me.roles.some((r) => REVIEW_ROLES.includes(r));
  const [inv, evidence, fw] = await Promise.all([api(`/v1/assessments/${aid}/inventory`), api(`/v1/assessments/${aid}/evidence`), api("/v1/frameworks")]);
  const docTypes = ["application/pdf", "text/plain", "text/csv", "application/json", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"];
  const docs = evidence.items.filter((e) => e.state === "clean" && docTypes.includes(e.content_type));
  const redraw = () => routes["use-cases"](aid);
  const picker = el("label", { class: "uc-picker" }, "Assessment", el("select", { onchange: (e) => go(`#/use-cases/${e.target.value}`) },
    assessments.map((a) => el("option", { value: a.assessment_id, selected: a.assessment_id === aid }, `${displayAISystemName(a.ai_system_name)} (${a.status})`))));
  const runBtn = el("button", { disabled: !docs.length, title: docs.length ? "" : "Upload a clean PDF, Word or text document first", onclick: safe(async (e) => {
    const button = e.currentTarget, label = button.textContent;
    button.disabled = true; button.setAttribute("aria-busy", "true"); button.textContent = "Reading documents…";
    try {
      const r = await api(`/v1/assessments/${aid}/inventory/run`, { method: "POST", body: {} });
      useCaseNote = r.mode === "unavailable" ? r.note : `${r.status === "partial" ? "Partial analysis; previous results for incomplete documents were retained. " : ""}${r.items.length} candidate use case(s) found in ${r.documents_read} document(s)${r.rejected ? `; ${r.rejected} unverifiable candidate(s) were dropped` : ""}.`;
      await redraw();
    } finally { button.disabled = false; button.setAttribute("aria-busy", "false"); button.textContent = label; }
  }) }, "Find AI use cases in the documents");
  const useCasePanel = el("section", { class: "module-panel" },
    el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "STEP 1 · INVENTORY AGENT"), el("h3", {}, `${inv.use_cases.length} candidate use case${inv.use_cases.length === 1 ? "" : "s"}`))),
    el("p", { class: "help" }, `${docs.length} readable document${docs.length === 1 ? "" : "s"} in this assessment (PDF, Word, text). Every candidate must quote the document word for word; anything the agent cannot back with a quote is discarded.`),
    el("div", { class: "row" }, picker, runBtn), useCaseNote ? el("p", { class: "module-note" }, useCaseNote) : "",
    inv.use_cases.length ? el("div", { class: "uc-list" }, inv.use_cases.map((u) => useCaseCard(aid, u, canReview, redraw)))
      : el("p", { class: "empty-state" }, "No use cases yet. Upload documents in Diagnosis, then run the Inventory Agent."));
  const validated = inv.use_cases.filter((u) => u.status === "VALIDATED").length;
  const fwSel = el("select", { "aria-label": "Framework" }, fw.items.map((f) => el("option", { value: f.id }, `${f.short_name} (${f.requirement_count} requirements)`)));
  const gapRun = el("button", { disabled: !validated, title: validated ? "" : "Validate at least one use case first", onclick: safe(async (e) => {
    const button = e.currentTarget, label = button.textContent;
    button.disabled = true; button.setAttribute("aria-busy", "true"); button.textContent = "Analysing…";
    try {
      const r = await api(`/v1/assessments/${aid}/gap-analysis/run`, { method: "POST", body: { framework_id: fwSel.value } });
      useCaseNote = r.mode === "unavailable" ? r.note : `${r.items.length} candidate gap(s) for ${fwSel.selectedOptions[0].textContent.split(" (")[0]}${r.rejected ? `; ${r.rejected} unverifiable candidate(s) were dropped` : ""}.`;
      await redraw();
    } finally { button.disabled = false; button.setAttribute("aria-busy", "false"); button.textContent = label; }
  }) }, "Run gap analysis");
  const gaps = [...inv.gaps].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const gapPanel = canReview ? el("section", { class: "module-panel" },
    el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "STEP 2 · GAP ANALYSIS AGENT"), el("h3", {}, `${gaps.length} candidate gap${gaps.length === 1 ? "" : "s"}`))),
    el("p", { class: "help" }, "Compares validated use cases with a framework. Each gap cites a real requirement or control ID and stays unreviewed until a reviewer decides."),
    el("div", { class: "row" }, el("label", { class: "uc-picker" }, "Framework", fwSel), gapRun),
    gaps.length ? el("div", { class: "uc-list" }, gaps.map((g) => gapCard(aid, g, canReview, redraw))) : el("p", { class: "empty-state" }, validated ? "No gaps recorded yet. Run the analysis." : "Validate a use case to unlock gap analysis."))
    : el("section", { class: "module-panel" }, el("span", { class: "eyebrow" }, "STEP 2 · GAP ANALYSIS"), el("p", { class: "help" }, inv.gaps_note || "Gap analysis is prepared by CloudSeals reviewers."));
  const validatedGaps = inv.gaps.some((g) => g.status === "VALIDATED");
  const staffPanels = canReview ? [maturityPanel(aid, inv, canReview, validated > 0, redraw), roadmapPanel(aid, inv, canReview, validatedGaps || inv.maturity?.status === "VALIDATED", redraw), overlayPanel(aid, inv, canReview, validated > 0, redraw), await reportPanel(aid)] : [];
  main.replaceChildren(moduleFrame("DIAGNOSIS · AI GOVERNANCE STUDIO", "Diagnostic studio", "From documents to a reviewed inventory, framework gaps, maturity, roadmap and report. Every step is a draft until a CloudSeals reviewer validates it.",
    canReview ? pipelineStepper(inv) : deliveredDiagnosticPanel(aid, inv.delivery), useCasePanel, gapPanel, ...staffPanels));
};

routes.frameworks = async (fid) => {
  const { items } = await api("/v1/frameworks");
  const active = items.find((f) => f.id === fid)?.id;
  const detail = active ? await api(`/v1/frameworks/${active}`) : null;
  const cards = items.map((f) => el("a", { class: `module-card module-card-link${f.id === active ? " module-card-primary" : ""}`, href: `#/frameworks/${f.id}` },
    el("span", { class: "module-card-status" }, "PENDING LEGAL REVIEW"), el("h3", {}, f.short_name), el("p", {}, `${f.name} · ${f.jurisdiction}`),
    el("p", {}, `${f.requirement_count} requirements · ${f.control_count} controls`), el("span", { class: "module-card-open" }, "View requirements →")));
  const body = detail ? el("section", { class: "module-panel" },
    el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, detail.version || "FRAMEWORK"), el("h3", {}, detail.name))),
    el("p", { class: "module-note" }, detail.notice), el("p", { class: "help" }, detail.description),
    detail.requirements.map((r) => el("details", { class: "fw-req" }, el("summary", {}, el("strong", {}, r.title), el("span", { class: "q-id" }, ` ${r.id}`)),
      el("p", {}, r.text), el("ul", { class: "fw-controls" }, (r.controls || []).map((c) => el("li", {}, el("span", { class: "q-id" }, c.id), ` ${c.description}`,
        c.evidence_needed?.length ? el("small", {}, ` Evidence: ${c.evidence_needed.join("; ")}`) : ""))))))
    : el("p", { class: "empty-state" }, "Choose a framework to read its requirements and controls.");
  main.replaceChildren(moduleFrame("OPERATIONS · REFERENCE", "Frameworks", "The requirement and control definitions the gap analysis agent compares use cases against. Read-only.",
    el("section", { class: "module-card-grid fw-grid" }, cards), body));
};


// ---------- Users and access (CloudSeals admins) ----------
const ROLE_LABEL = { cloudseals_admin: "Admin", cloudseals_assessor: "Assessor", cloudseals_reviewer: "Reviewer", cloudseals_platform_ops: "Platform ops", auditor_readonly: "Auditor (read only)",
  customer_admin: "Customer admin", customer_architect: "Customer architect", customer_risk: "Customer risk", customer_controller: "Customer controller", customer_contributor: "Customer contributor" };
const STAFF_ROLE_IDS = ["cloudseals_admin", "cloudseals_assessor", "cloudseals_reviewer", "cloudseals_platform_ops"];
const CUSTOMER_ROLE_IDS = ["customer_admin", "customer_architect", "customer_risk", "customer_controller", "customer_contributor", "auditor_readonly"];
const OWNER_BADGE = (roles) => STAFF_ROLE_IDS.every((r) => roles.includes(r));
const roleChips = (roles) => OWNER_BADGE(roles) ? el("span", { class: "role-chips" }, el("span", { class: "role-chip staff" }, "Owner (all CloudSeals roles)")) : el("span", { class: "role-chips" }, roles.map((r) => el("span", { class: `role-chip${r.startsWith("cloudseals") ? " staff" : ""}` }, ROLE_LABEL[r] || r)));
function roleChecks(ids, selected, name) {
  return el("div", { class: "role-checks" }, ids.map((id) => el("label", { class: "role-check" }, el("input", { type: "checkbox", name, value: id, checked: selected.includes(id) }), ROLE_LABEL[id])));
}
const pickedRoles = (root, name) => [...root.querySelectorAll(`input[name="${name}"]:checked`)].map((i) => i.value);

routes.users = async () => {
  if (!state.me.roles.includes("cloudseals_admin")) return main.replaceChildren(moduleFrame("ADMINISTRATION", "Users", "Only CloudSeals admins manage access.", el("p", { class: "empty-state" }, "You do not have access to this page.")));
  const [{ items, pending, staff_email_domains: domains, sign_in: signIn }, { items: tenants }] = await Promise.all([api("/v1/admin/users"), api("/v1/admin/tenants")]);
  const redraw = () => routes.users();
  const kind = el("select", { "aria-label": "Type of user" }, el("option", { value: "staff" }, "CloudSeals staff"), el("option", { value: "customer" }, "Customer user"));
  const email = el("input", { type: "email", placeholder: "name@cloudseals.co.uk", required: true, maxlength: 254, "aria-label": "Email address" });
  const tenantSel = el("select", { "aria-label": "Customer workspace" }, tenants.map((t) => el("option", { value: t.tenant_id }, t.name || t.tenant_id)));
  const staffBox = roleChecks(STAFF_ROLE_IDS, ["cloudseals_reviewer"], "new-roles"), custBox = roleChecks(CUSTOMER_ROLE_IDS, ["customer_contributor"], "new-roles");
  const tenantRow = el("label", {}, "Customer workspace", tenantSel);
  const sync = () => { const staff = kind.value === "staff"; staffBox.hidden = !staff; custBox.hidden = staff; tenantRow.hidden = staff; };
  kind.addEventListener("change", sync);
  const form = el("form", { class: "module-panel user-form", onsubmit: safe(async (e) => {
    e.preventDefault(); const staff = kind.value === "staff"; const roles = pickedRoles(staff ? staffBox : custBox, "new-roles");
    if (!roles.length) return toast("Choose at least one role", true);
    await api("/v1/admin/users", { method: "POST", body: { email: email.value.trim(), roles, tenant_id: staff ? null : tenantSel.value } });
    toast("Added. Access starts when they first sign in with Google."); redraw();
  }) }, el("span", { class: "eyebrow" }, "ADD A USER"), el("h3", {}, "Give someone access"),
    signIn !== "google" ? el("p", { class: "module-note" }, "Adding people by email needs Google sign-in. Use workspace invitations for this environment.") : "",
    el("div", { class: "row" }, el("label", {}, "Type", kind), el("label", { class: "grow" }, "Email", email)), tenantRow,
    el("label", {}, "Roles"), staffBox, custBox,
    el("p", { class: "help" }, `They sign in with this Google email; access begins at their first sign-in.${domains.length ? ` CloudSeals roles are limited to ${domains.join(", ")}.` : ""}`),
    el("button", { disabled: signIn !== "google" }, "Add user"));
  sync();

  const row = (u) => {
    const editor = el("div", { class: "user-edit", hidden: true });
    const isStaff = u.roles.some((r) => r.startsWith("cloudseals"));
    const boxes = roleChecks(isStaff ? STAFF_ROLE_IDS : CUSTOMER_ROLE_IDS, u.roles, `r-${u.sub}`);
    editor.append(boxes, el("div", { class: "row" }, el("button", { onclick: safe(async () => {
      const roles = pickedRoles(editor, `r-${u.sub}`); if (!roles.length) return toast("Choose at least one role", true);
      await api(`/v1/admin/users/${encodeURIComponent(u.sub)}`, { method: "PATCH", body: { roles } }); toast("Roles updated"); redraw();
    }) }, "Save roles"), el("button", { class: "secondary", onclick: () => { editor.hidden = true; } }, "Cancel")));
    const remove = el("button", { class: "danger", disabled: u.is_self, title: u.is_self ? "You cannot remove yourself" : "", onclick: safe(async (e) => {
      if (e.currentTarget.dataset.armed !== "1") { e.currentTarget.dataset.armed = "1"; e.currentTarget.textContent = "Click again to remove"; return; }
      await api(`/v1/admin/users/${encodeURIComponent(u.sub)}`, { method: "DELETE" }); toast("User removed"); redraw();
    }) }, "Remove");
    return el("tr", {}, el("td", {}, el("strong", {}, u.email || u.sub), u.is_self ? el("span", { class: "tag ok" }, "you") : "", el("br"), el("small", { class: "help" }, u.email ? u.sub : "")),
      el("td", {}, roleChips(u.roles), editor), el("td", {}, u.tenant_name || (isStaff ? "CloudSeals" : u.tenant_id || "")),
      el("td", {}, el("div", { class: "row" }, el("button", { class: "secondary", onclick: () => { editor.hidden = !editor.hidden; } }, "Edit roles"),
        isStaff && !STAFF_ROLE_IDS.every((r) => u.roles.includes(r)) ? el("button", { class: "secondary", title: "Grant every CloudSeals role", onclick: safe(async () => {
          await api(`/v1/admin/users/${encodeURIComponent(u.sub)}`, { method: "PATCH", body: { roles: STAFF_ROLE_IDS } }); toast("Now an owner: all CloudSeals roles"); redraw();
        }) }, "Make owner") : "", remove)));
  };
  const table = (head, rows) => el("div", { class: "table-wrap" }, el("table", { class: "module-table" }, el("thead", {}, el("tr", {}, head.map((h) => el("th", { scope: "col" }, h)))), el("tbody", {}, rows)));
  const pend = pending.length ? el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "WAITING FOR FIRST SIGN-IN"), el("h3", {}, `${pending.length} pending`))),
    table(["Email", "Roles", "Workspace", ""], pending.map((p) => el("tr", {}, el("td", {}, p.email), el("td", {}, roleChips(p.roles)), el("td", {}, p.tenant_name || "CloudSeals"),
      el("td", {}, el("button", { class: "secondary", onclick: safe(async () => { await api(`/v1/admin/users/pending/${encodeURIComponent(p.email)}`, { method: "DELETE" }); toast("Invitation cancelled"); redraw(); }) }, "Cancel")))))) : "";
  main.replaceChildren(moduleFrame("ADMINISTRATION · ACCESS", "Users", "Who can sign in, with which roles. Changes are recorded in the activity log.", form,
    el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "MEMBERS"), el("h3", {}, `${items.length} user${items.length === 1 ? "" : "s"}`))),
      table(["User", "Roles", "Workspace", ""], items.map(row))), pend));
};


// ---------- Cases: CloudSeals engagement tracking ----------
const CASE_STATUS = ["draft", "intake", "inventory", "gap", "review", "report", "delivered", "archived"];
const CASE_STATUS_LABEL = { draft: "Draft", intake: "Intake", inventory: "Inventory", gap: "Gap analysis", review: "In review", report: "Report", delivered: "Delivered", archived: "Archived" };
const INDUSTRIES = ["financial_services", "pharma", "healthcare", "retail", "manufacturing", "energy", "public_sector", "technology", "other"];
const FRAMEWORK_SHORT = { eu_ai_act: "EU AI Act", iso_42001: "ISO 42001", nist_ai_rmf: "NIST AI RMF", sr_11_7: "SR 11-7", fda_samd: "FDA SaMD" };
const label = (v) => String(v).replaceAll("_", " ").replace(/^\w/, (c) => c.toUpperCase());
const caseStatusChip = (s) => el("span", { class: `case-status cs-${s}` }, CASE_STATUS_LABEL[s] || s);
const when = (t) => new Date(t * 1000).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
const staffName = (a) => a.email || a.sub;

routes.cases = async () => {
  const [{ items }, { items: staff }] = await Promise.all([api("/v1/cases"), api("/v1/staff")]);
  const canCreate = state.me.roles.some((r) => ["cloudseals_admin", "cloudseals_assessor"].includes(r));
  let tenants = []; try { tenants = (await api("/v1/admin/tenants")).items; } catch { /* only some staff roles may list workspaces */ }
  const view = { status: "all", q: "", sort: "newest" };
  const list = el("div", { class: "table-wrap" });
  const chips = el("div", { class: "case-filters", role: "group", "aria-label": "Filter by status" });
  const draw = () => {
    chips.replaceChildren(...["all", ...CASE_STATUS].map((s) => el("button", { class: `chip${view.status === s ? " on" : ""}`, onclick: () => { view.status = s; draw(); } },
      s === "all" ? "All" : CASE_STATUS_LABEL[s], el("em", {}, String(s === "all" ? items.length : items.filter((c) => c.status === s).length)))));
    const rows = items.filter((c) => (view.status === "all" || c.status === view.status) && (!view.q || `${c.title} ${c.customer_name}`.toLowerCase().includes(view.q.toLowerCase())))
      .sort((a, b) => view.sort === "customer" ? a.customer_name.localeCompare(b.customer_name) : view.sort === "oldest" ? a.created_at - b.created_at : b.created_at - a.created_at);
    list.replaceChildren(rows.length ? el("table", { class: "module-table" }, el("thead", {}, el("tr", {}, ["Case", "Frameworks", "Status", "Risk", "Maturity", "Updated", ""].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, rows.map((c) => el("tr", {}, el("td", {}, el("a", { href: `#/case/${c.case_id}` }, el("strong", {}, c.title)), el("br"), el("small", { class: "help" }, `${c.customer_name} · ${label(c.tier)}`)),
        el("td", {}, c.frameworks_in_scope.map((f) => el("span", { class: "tag" }, FRAMEWORK_SHORT[f] || f))), el("td", {}, caseStatusChip(c.status)),
        el("td", {}, c.progress.risk_level ? el("span", { class: `tag ${TIER_CLASS[c.progress.risk_level] || ""}` }, TIER_LABEL[c.progress.risk_level]) : "—"),
        el("td", {}, c.progress.maturity_score != null ? `${c.progress.maturity_score} / 5` : "—"), el("td", {}, when(c.updated_at)),
        el("td", {}, el("a", { href: `#/case/${c.case_id}` }, "Open →")))))) : el("p", { class: "empty-state" }, items.length ? "No cases match this filter." : "No cases yet. Create the first one."));
  };
  const form = el("form", { class: "module-panel user-form", hidden: true, onsubmit: safe(async (e) => {
    e.preventDefault(); const d = new FormData(form);
    const body = { title: d.get("title"), customer_name: d.get("customer"), industry: d.get("industry"), region: d.get("region"), tier: d.get("tier"),
      frameworks_in_scope: d.getAll("fw"), lead_architect: d.get("lead") || null, architects: d.getAll("arch"), target_delivery_date: d.get("due") || null, notes: d.get("notes") || "", tenant_id: d.get("tenant") || null };
    const c = await api("/v1/cases", { method: "POST", body }); toast("Case created"); go(`#/case/${c.case_id}`);
  }) }, el("span", { class: "eyebrow" }, "NEW CASE"), el("h3", {}, "Open a diagnostic engagement"),
    el("div", { class: "row" }, el("label", { class: "grow" }, "Case title", el("input", { name: "title", required: true, minlength: 3, maxlength: 200, placeholder: "e.g. Demo Bank AI governance review Q4" })),
      el("label", { class: "grow" }, "Customer", el("input", { name: "customer", required: true, minlength: 2, maxlength: 200, placeholder: "e.g. Demo Bank plc" }))),
    el("div", { class: "row" }, el("label", {}, "Industry", el("select", { name: "industry" }, INDUSTRIES.map((i) => el("option", { value: i }, label(i))))),
      el("label", {}, "Region", el("select", { name: "region" }, ["UK", "EU", "US", "APAC", "Other"].map((r) => el("option", { value: r }, r)))),
      el("label", {}, "Tier", el("select", { name: "tier" }, ["tier_1", "tier_2", "tier_3"].map((t) => el("option", { value: t }, label(t))))),
      el("label", {}, "Target delivery", el("input", { name: "due", type: "date" })),
      tenants.length ? el("label", {}, "Customer workspace (optional)", el("select", { name: "tenant" }, el("option", { value: "" }, "None yet"), tenants.map((t) => el("option", { value: t.tenant_id }, t.name || t.tenant_id)))) : ""),
    el("label", {}, "Frameworks in scope"), el("div", { class: "role-checks" }, Object.entries(FRAMEWORK_SHORT).map(([id, n]) => el("label", { class: "role-check" }, el("input", { type: "checkbox", name: "fw", value: id, checked: id === "eu_ai_act" }), n))),
    el("label", {}, "Lead architect", el("select", { name: "lead" }, staff.map((a) => el("option", { value: a.sub, selected: a.sub === state.me.sub }, staffName(a))))),
    el("label", {}, "Other architects"), el("div", { class: "role-checks" }, staff.map((a) => el("label", { class: "role-check" }, el("input", { type: "checkbox", name: "arch", value: a.sub }), staffName(a)))),
    el("label", {}, "Notes", el("textarea", { name: "notes", rows: 2, maxlength: 4000 })), el("div", { class: "row" }, el("button", {}, "Create case"), el("button", { type: "button", class: "secondary", onclick: () => { form.hidden = true; } }, "Cancel")));
  const search = el("input", { type: "search", placeholder: "Search cases or customers", "aria-label": "Search cases", oninput: (e) => { view.q = e.target.value; draw(); } });
  const sort = el("select", { "aria-label": "Sort", onchange: (e) => { view.sort = e.target.value; draw(); } }, [["newest", "Newest first"], ["oldest", "Oldest first"], ["customer", "Customer A to Z"]].map(([v, l]) => el("option", { value: v }, l)));
  const open = items.filter((c) => !["delivered", "archived"].includes(c.status)).length;
  main.replaceChildren(moduleFrame("CLOUDSEALS · ENGAGEMENTS", "Cases", "One case per customer engagement: who is assigned, which assessments belong to it, how far the review has got.",
    el("section", { class: "module-metrics compact" }, [["Cases", items.length], ["Open", open], ["Delivered", items.filter((c) => c.status === "delivered").length]].map(([k, v]) => el("article", {}, el("span", {}, k), el("strong", {}, String(v))))),
    canCreate ? el("p", {}, el("button", { onclick: () => { form.hidden = !form.hidden; } }, "+ New case")) : "", form,
    el("section", { class: "module-panel" }, el("div", { class: "row case-tools" }, search, sort), chips, list)));
  draw();
};

routes.case = async (cid) => {
  let tab = "overview";
  const draw = async () => {
    const [c, staff] = await Promise.all([api(`/v1/cases/${cid}`), api("/v1/staff")]);
    const isLead = state.me.roles.includes("cloudseals_admin") || c.lead_architect === state.me.sub;
    const tabs = el("div", { class: "case-tabs", role: "tablist" }, [["overview", "Overview"], ["assessments", `Assessments (${c.assessments.length})`], ["activity", "Activity"]].map(([id, l]) =>
      el("button", { role: "tab", class: `tab${tab === id ? " on" : ""}`, "aria-selected": String(tab === id), onclick: () => { tab = id; draw(); } }, l)));
    let body;
    if (tab === "overview") {
      const next = el("select", { "aria-label": "New status" }, CASE_STATUS.map((s) => el("option", { value: s, selected: s === c.status }, CASE_STATUS_LABEL[s])));
      const why = el("input", { placeholder: "Reason (required)", maxlength: 2000, "aria-label": "Reason for status change" });
      const p = c.progress;
      const steps = [["Use cases", p.validated_use_cases > 0], ["Gaps", p.validated_gaps > 0], ["Maturity", p.maturity_score != null], ["Roadmap", p.validated_roadmap_items > 0], ["Report", p.report === "final"]];
      const fields = [["Customer", c.customer_name], ["Industry", label(c.industry)], ["Region", c.region], ["Tier", label(c.tier)], ["Target delivery", c.target_delivery_date || "Not set"],
        ["Lead architect", staffName(c.architects.find((a) => a.is_lead) || { sub: c.lead_architect })], ["Architects", c.architects.map(staffName).join(", ")], ["Created", when(c.created_at)]];
      const edit = el("form", { class: "user-edit", hidden: true, onsubmit: safe(async (e) => {
        e.preventDefault(); const d = new FormData(edit);
        await api(`/v1/cases/${cid}`, { method: "PATCH", body: { tier: d.get("tier"), target_delivery_date: d.get("due") || null, notes: d.get("notes"), frameworks_in_scope: d.getAll("fw"), lead_architect: d.get("lead"), architects: d.getAll("arch") } });
        toast("Case updated"); draw();
      }) }, el("div", { class: "row" }, el("label", {}, "Tier", el("select", { name: "tier" }, ["tier_1", "tier_2", "tier_3"].map((t) => el("option", { value: t, selected: t === c.tier }, label(t))))),
        el("label", {}, "Target delivery", el("input", { name: "due", type: "date", value: c.target_delivery_date || "" })),
        el("label", {}, "Lead architect", el("select", { name: "lead" }, staff.items.map((a) => el("option", { value: a.sub, selected: a.sub === c.lead_architect }, staffName(a)))))),
        el("label", {}, "Frameworks"), el("div", { class: "role-checks" }, Object.entries(FRAMEWORK_SHORT).map(([id, n]) => el("label", { class: "role-check" }, el("input", { type: "checkbox", name: "fw", value: id, checked: c.frameworks_in_scope.includes(id) }), n))),
        el("label", {}, "Architects"), el("div", { class: "role-checks" }, staff.items.map((a) => el("label", { class: "role-check" }, el("input", { type: "checkbox", name: "arch", value: a.sub, checked: c.architects.some((x) => x.sub === a.sub) }), staffName(a)))),
        el("label", {}, "Notes", el("textarea", { name: "notes", rows: 3, maxlength: 4000 }, c.notes || "")), el("div", { class: "row" }, el("button", {}, "Save"), el("button", { type: "button", class: "secondary", onclick: () => { edit.hidden = true; } }, "Cancel")));
      body = el("div", {}, el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "PROGRESS"), el("h3", {}, "What a reviewer has validated"))),
        el("ol", { class: "pipe-steps" }, steps.map(([n, done], i) => el("li", { class: done ? "is-done" : "" }, el("span", {}, done ? "✓" : String(i + 1)), n))),
        el("p", { class: "help" }, `${p.validated_use_cases} use case(s), ${p.validated_gaps} gap(s), ${p.validated_roadmap_items} roadmap item(s). Risk level: ${p.risk_level ? TIER_LABEL[p.risk_level] : "not set"}. Maturity: ${p.maturity_score != null ? `${p.maturity_score} / 5` : "not scored"}. Report: ${p.report}.`)),
        el("section", { class: "module-panel" }, el("div", { class: "module-panel-heading" }, el("div", {}, el("span", { class: "eyebrow" }, "DETAILS"), el("h3", {}, "Engagement")),
          isLead ? el("button", { class: "secondary", onclick: () => { edit.hidden = !edit.hidden; } }, "Edit") : ""),
          el("dl", { class: "uc-meta" }, fields.map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, v)))), c.notes ? el("p", { class: "uc-why" }, c.notes) : "", edit),
        el("section", { class: "module-panel" }, el("span", { class: "eyebrow" }, "STATUS"), el("h3", {}, "Move the case on"),
          isLead ? el("div", { class: "row" }, next, why, el("button", { onclick: safe(async () => { if (!why.value.trim()) return toast("Enter a reason first", true);
            await api(`/v1/cases/${cid}/status`, { method: "POST", body: { status: next.value, reason: why.value.trim() } }); toast("Status updated"); draw(); }) }, "Update status"))
            : el("p", { class: "help" }, "Only the lead architect or an admin changes the status."),
          el("p", { class: "help" }, "Publish a diagnostic report to the customer before marking the case delivered."),
          el("ul", { class: "case-history" }, [...c.status_history].reverse().map((h) => el("li", {}, caseStatusChip(h.status), ` ${when(h.at)} · ${h.by} · ${h.reason}`)))));
    } else if (tab === "assessments") {
      const all = (await api("/v1/assessments")).items.filter((a) => !c.assessment_ids.includes(a.assessment_id) && (!c.tenant_id || a.tenant_id === c.tenant_id));
      const evidence = await Promise.all(c.assessments.map(async (a) => ({ a, ev: (await api(`/v1/assessments/${a.assessment_id}/evidence`)).items })));
      const pick = el("select", { "aria-label": "Assessment to link" }, all.map((a) => el("option", { value: a.assessment_id }, `${displayAISystemName(a.ai_system_name)} (${a.status})`)));
      body = el("div", {}, el("section", { class: "module-panel" }, el("span", { class: "eyebrow" }, "LINKED ASSESSMENTS"), el("h3", {}, `${c.assessments.length} assessment${c.assessments.length === 1 ? "" : "s"}`),
        evidence.length ? evidence.map(({ a, ev }) => el("article", { class: "uc-card" }, el("div", { class: "uc-head" }, el("h4", {}, displayAISystemName(a.ai_system_name)), el("span", { class: "tag" }, a.status),
          el("a", { href: `#/use-cases/${a.assessment_id}` }, "Diagnostic studio →"), el("a", { href: `#/assessment/${a.assessment_id}` }, "Assessment →"),
          isLead ? el("button", { class: "secondary", onclick: safe(async () => { await api(`/v1/cases/${cid}/assessments/${a.assessment_id}`, { method: "DELETE" }); toast("Unlinked"); draw(); }) }, "Unlink") : ""),
          el("p", { class: "help" }, "Documents"), ev.length ? el("ul", { class: "fw-controls" }, ev.map((e) => el("li", {}, `${e.filename} `, el("span", { class: `tag ${e.state === "clean" ? "ok" : "high"}` }, e.state)))) : el("p", { class: "help" }, "No documents uploaded yet.")))
          : el("p", { class: "empty-state" }, "No assessment is linked yet."),
        isLead ? el("div", { class: "row" }, all.length ? pick : el("span", { class: "help" }, "No other assessments are available to link."), all.length ? el("button", { onclick: safe(async () => {
          await api(`/v1/cases/${cid}/assessments`, { method: "POST", body: { assessment_id: pick.value } }); toast("Linked"); draw(); }) }, "Link assessment") : "") : ""));
    } else {
      const { items } = await api(`/v1/cases/${cid}/audit`);
      body = el("section", { class: "module-panel" }, el("span", { class: "eyebrow" }, "ACTIVITY"), el("h3", {}, `${items.length} recorded event${items.length === 1 ? "" : "s"}`),
        items.length ? el("div", { class: "table-wrap" }, el("table", { class: "module-table" }, el("thead", {}, el("tr", {}, ["When", "Who", "Action", "Reference"].map((h) => el("th", { scope: "col" }, h)))),
          el("tbody", {}, items.map((a) => el("tr", {}, el("td", {}, new Date(a.at * 1000).toLocaleString()), el("td", {}, a.email || a.sub), el("td", {}, a.action), el("td", {}, String(a.ref).slice(0, 44))))))) : el("p", { class: "empty-state" }, "Nothing recorded yet."));
    }
    main.replaceChildren(moduleFrame("CLOUDSEALS · CASE", c.title, `${c.customer_name} · ${label(c.tier)}`, el("p", {}, el("a", { href: "#/cases" }, "← All cases"), " ", caseStatusChip(c.status)), tabs, body));
  };
  await draw();
};


// ---------- Customer workspaces: read-only view for CloudSeals staff ----------
routes.workspaces = async () => {
  const { items } = await api("/v1/admin/workspaces");
  main.replaceChildren(moduleFrame("CLOUDSEALS · CUSTOMERS", "Customer workspaces", "See what each customer sees. This is a read-only view: customer actions are done by the customer's own users.",
    items.length ? el("section", { class: "module-card-grid" }, items.map((w) => el("a", { class: "module-card module-card-link", href: `#/workspace/${w.tenant_id}` },
      el("span", { class: "module-card-status" }, "WORKSPACE"), el("h3", {}, w.name),
      el("p", {}, `${w.assessments} assessment${w.assessments === 1 ? "" : "s"} · ${w.users} user${w.users === 1 ? "" : "s"}`), el("span", { class: "module-card-open" }, "View workspace →"))))
      : el("p", { class: "empty-state" }, "No customer workspace has been activated yet.")));
};

routes.workspace = async (tid) => {
  const w = await api(`/v1/admin/workspaces/${encodeURIComponent(tid)}`);
  const table = (head, rows, empty) => rows.length ? el("div", { class: "table-wrap" }, el("table", { class: "module-table" }, el("thead", {}, el("tr", {}, head.map((h) => el("th", { scope: "col" }, h)))), el("tbody", {}, rows))) : el("p", { class: "empty-state" }, empty);
  main.replaceChildren(moduleFrame("CLOUDSEALS · CUSTOMER WORKSPACE", w.tenant.name || w.tenant.tenant_id, [w.tenant.industry, w.tenant.residency_profile].filter(Boolean).join(" · ") || "Customer workspace",
    el("p", {}, el("a", { href: "#/workspaces" }, "← All workspaces")),
    el("p", { class: "module-note" }, "Read-only assessment view for CloudSeals staff. Customer answers stay with the customer’s own users."),
    el("section", { class: "module-panel" }, el("span", { class: "eyebrow" }, "ASSESSMENTS"), el("h3", {}, `${w.assessments.length} assessment${w.assessments.length === 1 ? "" : "s"}`),
      table(["AI system", "Status", "", ""], w.assessments.map((a) => el("tr", {}, el("td", {}, a.ai_system_name), el("td", {}, el("span", { class: "tag" }, a.status)),
        el("td", {}, el("a", { href: `#/assessment/${a.assessment_id}` }, "Open assessment →")), el("td", {}, el("a", { href: `#/use-cases/${a.assessment_id}` }, "Diagnostic studio →")))), "No assessments yet.")),
    el("section", { class: "module-panel" }, el("span", { class: "eyebrow" }, "PEOPLE"), el("h3", {}, `${w.members.length} user${w.members.length === 1 ? "" : "s"}`),
      table(["User", "Roles"], w.members.map((m) => el("tr", {}, el("td", {}, m.email || m.sub), el("td", {}, roleChips(m.roles)))), "No users yet."))));
};

// Finance prototypes are outside this assessment workspace. Preserve server records and old bookmarks safely.
for (const retired of ["trustops","approvals","reconciliation","exceptions","evidence","shadow-roi","readiness","demo","integrations","datasets","models","workflows","policies","authority","approval-matrix","agentops"]) {
  routes[retired] = async () => { history.replaceState({}, "", "#/dashboard"); return routes.dashboard(); };
}

// This workspace opens application governance. Diagnostic routes remain available
// for existing assessment bookmarks, outside the LedgerSight governance navigation.
routes["assessment-overview"] = routes.dashboard;   // CloudSeals AI readiness assessment home, kept reachable
registerTrustBoundary({ routes, main, el, api });
registerGovernanceConsole({ routes, main, el, api });

// ---------- boot ----------
async function boot() {
  state.cfg = await fetch("config.json", { cache: "no-store" }).then((r) => {
    if (!r.ok) throw new Error("Portal sign-in configuration could not be loaded.");
    return r.json();
  }).catch(() => ({ mode: "oidc", oidc: {} }));
  const q = new URLSearchParams(location.search);
  if (q.get("code")) { try { await oidcCallback(q); } catch (e) { toast(e.message, true); } }
  render();
}
boot();
