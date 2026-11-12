import { registerGovernanceTeam } from "./governance-team.js?v=access-2026-11-13b";
import { createDocumentReviews } from "./document-reviews.js?v=document-reviews-2026-11-12";
// Live application governance. Credentials and client-scope mappings remain server-side.
export function registerApplications({ routes, main, el, state, toast, api }) {
  registerGovernanceTeam({routes,main,el,api,state,toast});
  const tabs = ["Overview", "Runs", "Reviews", "Controls", "Evidence"];
  const paths = {
    grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    shield: "M12 3l8 3v6c0 5-8 9-8 9S4 17 4 12V6zM8 12l3 3 5-6",
    link: "M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-2 2M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l2-2",
    arrow: "M5 12h14M14 7l5 5-5 5", external: "M14 3h7v7M21 3l-9 9M10 3H4v17h17v-6",
    file: "M6 3h8l5 5v13H6zM14 3v6h5M9 13h7M9 17h5",
    people: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M18 8a3 3 0 0 1 0 6M22 21v-2a4 4 0 0 0-3-4",
    activity: "M3 12h4l3-8 4 16 3-8h4", download: "M12 3v12M7 10l5 5 5-5M4 17v4h16v-4",
    check: "M5 12l4 4L19 6", clock: "M12 8v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0",
  };
  function ico(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) svg.setAttribute(k, v);
    const p = document.createElementNS(svg.namespaceURI, "path"); p.setAttribute("d", paths[name] || paths.grid); svg.append(p); return svg;
  }
  const pill = (text, tone = "neutral") => el("span", { class: `gov-pill gov-${tone}` }, el("span", { class: "gov-dot" }), text);
  const button = (text, fn, secondary = false, icon = "link") => el("button", { class: `gov-button${secondary ? " gov-secondary" : ""}`, type: "button", onclick: fn }, ico(icon), text);
  const titles = {Overview: "Governance overview", Runs: "Workflow runs", Reviews: "Document reviews", Controls: "Policies & controls", Evidence: "Evidence & audit"};
  const routeFor = {Runs: "governance-runs", Reviews: "governance-reviews", Controls: "governance-controls", Evidence: "governance-evidence"};
  const pending = r => ["OPEN", "RETURNED", "PENDING", "PROPOSED"].includes(r.status);
  const nice = value => String(value || "—").replaceAll("_", " ").toLowerCase().replace(/^./, c => c.toUpperCase());
  const when = value => value ? new Date(value).toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"}) : "—";
  const tone = value => ["PASS", "COMPLETE", "ACCEPTED", "ALLOW"].includes(value) ? "green" : ["FAIL", "DENY", "REJECTED"].includes(value) ? "rose" : "amber";
  const sourceLink = (data, label = "Open LedgerSight", hash = "") => el("a", {class: "gov-button gov-secondary", href: (data?.service_url || "https://ledgersight-a6v24wp5eq-uk.a.run.app") + hash, target: "_blank", rel: "noopener noreferrer"}, label, ico("external"));
  const empty = (icon, title, copy) => el("div", {class:"gov-empty"}, el("div", {class:"gov-empty-icon"}, ico(icon)), el("h3", {}, title), el("p", {}, copy));
  function panel(title, subtitle, content, extra) {
    return el("section", {class:"gov-panel"}, el("div", {class:"gov-panel-head"}, el("div", {}, el("h3", {}, title), subtitle ? el("p", {}, subtitle) : ""), extra || ""), content);
  }
  function table(headings, rows) {
    return el("div", {class:"gov-table-wrap"}, el("table", {class:"gov-table"}, el("thead", {}, el("tr", {}, headings.map(h => el("th", {scope:"col"}, h)))), el("tbody", {}, rows)));
  }
  function modal(title, children) {
    const dialog = el("dialog", {class:"gov-dialog gov-detail-dialog", "aria-labelledby":"gov-detail-title"},
      el("div", {class:"gov-dialog-head"}, el("span", {class:"gov-kicker"}, "TRUSTOPS · LIVE GOVERNANCE"), el("button", {class:"gov-close", type:"button", "aria-label":"Close details", onclick:()=>dialog.close()}, "×")),
      el("h2", {id:"gov-detail-title"}, title), children);
    document.body.append(dialog); dialog.addEventListener("close", ()=>dialog.remove(), {once:true}); dialog.showModal();
  }
  function detailsList(items) {
    return el("dl", {class:"gov-details-list"}, items.map(([label,value])=>el("div", {}, el("dt", {}, label), el("dd", {}, value || "—"))));
  }
  function showRun(run, data) {
    modal(run.id, el("div", {}, detailsList([["Client",run.workspace_name],["Started",when(run.created_at)],["Started by",run.created_by],["Trace",run.trace_id],["Policy version",run.policy_version],["Pending reviews",String(run.pending_reviews)]]),
      el("h3", {}, "Agent trace"), table(["Agent", "Action", "Policy decision", "Result"], run.workflow.map(s=>el("tr", {}, el("td", {}, s.agent || s.agent_id || "—"), el("td", {}, s.action || s.label || "—"), el("td", {}, s.decision || s.policy_decision || "—"), el("td", {}, s.summary || s.status || "—")))),
      el("div", {class:"gov-dialog-actions"}, sourceLink(data, "Open LedgerSight", "#recon"))));
  }
  function reviewDetails(review, data) {
    modal(review.case_id || review.id, el("div", {}, pill(nice(review.status),tone(review.status)), el("p", {}, review.reason || "No reason supplied"),
      detailsList([["Client",review.workspace_name],["Run",review.run_id],["Policy",review.policy_id],["Required role",nice(review.required_role)],["Proposed by",review.proposed_by],["Reviewer",review.reviewer],["Reviewed",when(review.reviewed_at)],["Approval",review.approval_id],["Source references",review.evidence_refs.join(", ")]]),
      el("p", {}, "Decisions are made in LedgerSight. Select the client shown above before reviewing the case."), el("div", {class:"gov-dialog-actions"}, sourceLink(data,"Review in LedgerSight","#exceptions"))));
  }
  function showEvidence(event) {
    modal("Signed evidence event", detailsList([["Event",event.event_id],["Client",event.workspace_name],["Time",when(event.timestamp_utc)],["Actor",event.actor_id],["Action",event.action],["Decision",event.policy_decision],["Policy",event.policy_id],["Run",event.run_id],["Trace",event.trace_id],["Source references",(event.source_line_refs||[]).join(", ")],["Prior hash",event.prior_hash],["Event hash",event.event_hash],["Ed25519 signature",event.signature]]));
  }
  const metrics = items => el("section", {class:"gov-metrics", "aria-label":"Live governance summary"}, items.map(([label,value,note,icon])=>el("div", {class:"gov-metric"}, el("div", {class:"gov-metric-label"},label,ico(icon)), el("strong", {}, String(value)), el("span", {},note))));
  function activity(data) {
    return data.events.length ? table(["Time", "Actor & action", "Decision", "Evidence"], data.events.slice(0,8).map(e=>el("tr", {}, el("td", {},when(e.timestamp_utc)), el("td", {},el("strong", {},e.action),el("p", {},e.actor_id)),el("td", {},pill(String(e.policy_decision||"UNKNOWN").split(":")[0],tone(String(e.policy_decision||"").split(":")[0]))),el("td", {},button("View",()=>showEvidence(e),true,"file"))))) : empty("activity","No events recorded","The source has not recorded any governance events yet.");
  }
  routes["governance-overview"] = () => routes.applications(undefined, true);
  for (const [tab, route] of Object.entries(routeFor)) routes[route] = () => routes.applications("ledgersight", false, tab, true);
  routes.applications = async (id, overview = false, initialTab = "Overview", globalView = false) => {
    const root = el("div", {class:"gov"});
    main.replaceChildren(root);
    let live = null, error = "", tab = initialTab, busy = false;
    let selectedWorkspace = "all", reviewFilter = "all", selectedRun = "all";
    const current = ()=>root.isConnected;
    async function sync(force = false) {
      if (busy || !current()) return;
      busy = true;
      if (!live) root.replaceChildren(empty("link","Connecting to LedgerSight…","Reading Cloud Run runs, reviews and signed evidence. No files need to be uploaded again."));
      try {
        const result = await api(`/v1/applications/ledgersight/snapshot${force ? "?refresh=true" : ""}`);
        if (!current()) return;
        if (!live && initialTab === "Evidence") selectedRun = result.runs[0]?.id || "all";
        live = result; error = "";
      } catch (e) {
        if (!current()) return;
        live = null; error = e.status === 404 ? "This TrustOps workspace has no LedgerSight connection assigned." : "Live sync is unavailable. Check the server connection and service identity, then retry.";
      } finally { busy = false; if(current()) draw(); }
    }
    function scoped() {
      const match = item => selectedWorkspace === "all" || item.workspace_id === selectedWorkspace;
      return {runs:live.runs.filter(match), reviews:live.reviews.filter(match), events:live.events.filter(match), workspaces:live.workspaces.filter(w=>selectedWorkspace==="all" || w.id===selectedWorkspace)};
    }
    function draw() {
      if (!current()) return;
      root.replaceChildren();
      const connected = !!live;
      const badge = pill(connected ? "Connected · Cloud Run" : "Connection unavailable", connected ? "green" : "rose");
      const refresh = button("Refresh", ()=>sync(true), true, "clock"); refresh.disabled = busy;
      if (!id) {
        root.append(el("div", {class:"gov-page-heading"}, el("div", {},el("span", {class:"gov-kicker"},"GOVERNANCE WORKSPACE"),el("h2", {},overview ? "Governance overview" : "Applications"),el("p", {},"The controls, human decisions and evidence behind your application workflows.")),refresh));
        if (!connected) root.append(el("div",{class:"gov-notice",role:"status"},ico("alert"),el("p",{},error)));
        if (connected && overview) root.append(metrics([["Connected applications",1,"LedgerSight · Cloud Run","link"],["Workflow runs",live.total_runs,"Existing reconciliation runs","activity"],["Documents awaiting review",live.pending_document_reviews||0,"Uploaded in LedgerSight","people"],["Evidence verification",live.verification.state,`${live.verification.checked} signatures checked`,"shield"]]));
        root.append(el("a", {class:"gov-application-card",href:"#/applications/ledgersight"},el("div",{class:"gov-app-mark"},ico("activity")),el("div",{class:"gov-app-card-copy"},el("div",{class:"gov-row"},el("h3",{},"LedgerSight"),badge),el("p",{},"Bank-to-ledger reconciliation"),el("div",{class:"gov-card-tags"},el("span",{},connected ? `${live.workspaces.length} client workspaces` : "No live data available"),el("span",{},"Authenticated · Read-only"))),el("span",{class:"gov-card-open"},"View governance",ico("arrow"))),
          el("div",{class:"gov-portfolio-note"},ico("shield"),el("div",{},el("h3",{},"Reconcile in LedgerSight. Govern in TrustOps."),el("p",{},"Files and review decisions stay in LedgerSight. TrustOps reads the resulting runs, policy decisions and signed evidence."))));
        if (connected && overview) root.append(panel("Recent governance activity","Latest events from the mapped Cloud Run client workspaces",activity(live),el("a",{href:"#/governance-evidence"},"All evidence →")));
      } else {
        if(id!=="ledgersight") {root.append(empty("grid","Application not found","Choose an application from your workspace."));return;}
        const title = globalView ? titles[tab] : "LedgerSight";
        root.append(globalView ? "" : el("a",{class:"gov-back",href:"#/applications"},"← Applications"),
          el("header",{class:"gov-page-heading"},el("div",{class:"gov-app-title"},el("div",{class:"gov-app-mark"},ico(globalView ? {Runs:"activity",Reviews:"people",Controls:"shield",Evidence:"file"}[tab] : "activity")),el("div",{},el("div",{class:"gov-row"},el("h2",{},title),badge),el("p",{},globalView ? "LedgerSight · Existing Cloud Run application data" : "Bank-to-ledger reconciliation, governed by TrustOps."))),el("div",{class:"gov-actions"},sourceLink(live),refresh)));
        if (!connected) {
          if(tab==="Reviews")root.append(createDocumentReviews({el,api,state,toast}));
          root.append(panel("Live data unavailable","No cached data is being presented as current.",empty("link","Connection needs attention",error)));return;
        }
        const data=scoped();
        const workspaceSelect=el("select",{"aria-label":"Filter client workspace",onchange:e=>{selectedWorkspace=e.target.value;selectedRun="all";draw();}},el("option",{value:"all",selected:selectedWorkspace==="all"},"All client workspaces"),live.workspaces.map(w=>el("option",{value:w.id,selected:selectedWorkspace===w.id},w.name)));
        root.append(el("div",{class:"gov-live-bar"},el("span",{},pill("Cloud Run: read-only","green"),` Updated ${when(live.synced_at)} · Auto-refresh 30s`),workspaceSelect));
        if(!globalView) root.append(el("nav",{class:"gov-tabs","aria-label":"LedgerSight sections"},tabs.map(t=>el("button",{type:"button","aria-current":tab===t?"page":null,onclick:()=>{tab=t;if(t==="Evidence")selectedRun=live.runs[0]?.id||"all";draw();}},t))));
        if(tab==="Overview") {
          root.append(metrics([["Workflow runs",data.runs.length,"Latest 25 per client","activity"],["Documents awaiting review",live.pending_document_reviews||0,"Approve or reject in Reviews","people"],["Signed events",data.workspaces.reduce((n,w)=>n+w.events,0),"Full chains checked before display","file"],["Verification",data.workspaces.some(w=>w.verification.state==="FAIL")?"FAIL":data.workspaces.every(w=>w.verification.state==="PASS")?"PASS":"UNKNOWN","Ed25519 + SHA-256","shield"]]),
            el("div",{class:"gov-overview-grid"},el("div",{class:"gov-main-column"},panel("Recent governance activity","Policy decisions and human reviews, read from LedgerSight",activity({...live,events:data.events}))),
              el("aside",{class:"gov-aside"},panel("Connected client workspaces","Explicit server-side access mapping",el("div",{class:"gov-workspace-list"},data.workspaces.map(w=>el("div",{},el("strong",{},w.name),el("span",{},`${w.run_count} runs · ${w.events} signed events`),pill(w.verification.state,tone(w.verification.state)))))),panel("Connection scope","Cloud Run · Authenticated reads",el("div",{class:"gov-boundaries"},el("p",{},"Uploads, reconciliation and approvals stay in LedgerSight."),el("p",{},"Runs, review status, controls and signed audit references are visible here."))))));
        } else if(tab==="Runs") {
          root.append(panel("Reconciliation runs",live.run_window,data.runs.length?table(["Run / client","Started","Status","Reviews","Trace"],data.runs.map(r=>el("tr",{},el("td",{},el("strong",{},r.id),el("p",{},r.workspace_name)),el("td",{},when(r.created_at)),el("td",{},pill(nice(r.status),tone(r.status))),el("td",{},`${r.pending_reviews} pending / ${r.exceptions}`),el("td",{},button("View trace",()=>showRun(r,live),true,"activity"))))):empty("activity","No runs in this scope","Run reconciliation in LedgerSight. It will appear here on the next refresh.")));
        } else if(tab==="Reviews") {
          root.append(createDocumentReviews({el,api,state,toast,workspaces:live.workspaces}));
          const filtered=data.reviews.filter(r=>reviewFilter==="all" || (reviewFilter==="pending"?pending(r):!pending(r)));
          const filter=el("select",{"aria-label":"Filter review status",onchange:e=>{reviewFilter=e.target.value;draw();}},...[ ["all","All reviews"],["pending","Pending"],["decided","Decided"] ].map(([value,label])=>el("option",{value,selected:reviewFilter===value},label)));
          root.append(el("details",{class:"gov-panel doc-exceptions"},el("summary",{},"Reconciliation exceptions · Separate from document approval"),panel("Reconciliation exception decisions","These decisions remain in LedgerSight.",filtered.length?table(["Case / client","Reason","Status","Reviewer / policy","Details"],filtered.map(r=>el("tr",{},el("td",{},el("strong",{},r.case_id||r.id),el("p",{},r.workspace_name)),el("td",{},el("strong",{},nice(r.type)),el("p",{},r.reason)),el("td",{},pill(nice(r.status),tone(r.status))),el("td",{},r.reviewer||nice(r.required_role),el("p",{},r.policy_id||"—")),el("td",{},button("View case",()=>reviewDetails(r,live),true,"people"))))):empty("people","No reviews match this filter","Choose another client or review status."),filter)));
        } else if(tab==="Controls") {
          const body=el("tbody");const search=el("input",{class:"gov-search",type:"search",placeholder:"Search policies…","aria-label":"Search live policies",oninput:()=>filter()});
          const filter=()=>{const matches=live.policies.filter(p=>`${p.id} ${p.name} ${p.rule}`.toLowerCase().includes(search.value.toLowerCase()));body.replaceChildren(...matches.map(p=>el("tr",{},el("td",{},el("span",{class:"gov-code"},p.id)),el("td",{},el("strong",{},nice(p.name)),el("p",{},p.rule)),el("td",{},pill(p.effect,tone(p.effect))),el("td",{},p.version))));if(!matches.length)body.append(el("tr",{},el("td",{colspan:4},"No policies match your search.")));};
          const policyTable=table(["Policy","Control & purpose","Effect","Version"],[]);policyTable.querySelector("tbody").replaceWith(body);filter();
          root.append(panel("Active in LedgerSight",`Deployed source configuration · ${live.policy_version}`,policyTable,search));
        } else if(tab==="Evidence") {
          const proof=data.workspaces.map(w=>el("div",{class:"gov-proof"},ico("shield"),el("div",{},el("strong",{},`${w.name} · ${w.verification.state}`),el("p",{},`${w.verification.checked} events checked · ${w.verification.reason}`)),pill(w.verification.state,tone(w.verification.state))));
          const runFilter=el("select",{"aria-label":"Filter evidence by run",onchange:e=>{selectedRun=e.target.value;draw();}},el("option",{value:"all",selected:selectedRun==="all"},"All runs and workspace activity"),data.runs.map(r=>el("option",{value:r.id,selected:selectedRun===r.id},`${r.id} · ${r.workspace_name}`)));
          const events=data.events.filter(e=>selectedRun==="all" || (e.run_id===selectedRun && !["workspace.read","export.read"].includes(e.action)));
          root.append(el("div",{class:"gov-proof-list"},proof),panel("Signed audit trail",`${live.event_window}. Verification checks the full source chains.`,events.length?table(["Time / client","Actor & action","Decision / policy","Run","Evidence"],events.map(e=>el("tr",{},el("td",{},when(e.timestamp_utc),el("p",{},e.workspace_name)),el("td",{},el("strong",{},e.action),el("p",{},e.actor_id)),el("td",{},pill(String(e.policy_decision||"UNKNOWN").split(":")[0],tone(String(e.policy_decision||"").split(":")[0])) ,el("p",{},e.policy_id||"—")),el("td",{},el("span",{class:"gov-code"},e.run_id||"Workspace activity")),el("td",{},button("Inspect",()=>showEvidence(e),true,"file"))))):empty("file","No evidence in this view","Choose another run or client scope."),runFilter));
        }
      }
      root.append(el("footer",{class:"gov-footer"},el("span",{},ico("shield"),connected ? "Authenticated Cloud Run reads · No financial actions from TrustOps" : "Live sync unavailable"),el("span",{},connected ? `Last read ${when(live.synced_at)}` : "No current data")));
    }
    await sync();
    const poll=()=>setTimeout(async()=>{if(!current())return;if(!document.hidden)await sync();poll();},30000);
    poll();
  };
}
