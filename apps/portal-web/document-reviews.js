const documentViews=new Map();
export function createDocumentReviews({el,api,state,toast,workspaces=[]}) {
  const base="/v1/applications/ledgersight/documents";
  const root=el("section",{class:"gov-panel doc-workspace","aria-label":"Document approvals"});
  const viewKey=`${state.me?.sub}:${state.me?.tenant?.tenant_id}`;
  let data=null,view=documentViews.get(viewKey)||"PENDING";
  const time=value=>value?new Date(value).toLocaleString(undefined,{dateStyle:"medium",timeStyle:"short"}):"Not supplied";
  const label=value=>String(value||"").replaceAll("_"," ").toLowerCase().replace(/^./,c=>c.toUpperCase());
  const button=(text,fn,primary=false)=>el("button",{type:"button",class:`gov-button${primary?"":" gov-secondary"}`,onclick:async()=>{try{await fn();}catch(e){toast(e.message,true);}}},text);
  const badge=status=>el("span",{class:`gov-pill gov-${status==="APPROVED"?"green":status==="REJECTED"?"rose":"amber"}`},label(status));
  const table=(headers,rows)=>el("div",{class:"gov-table-wrap"},el("table",{class:"gov-table"},el("thead",{},el("tr",{},headers.map(h=>el("th",{scope:"col"},h)))),el("tbody",{},rows)));
  async function load() {
    try{data=await api(base);if(root.isConnected)draw();}
    catch(e){if(root.isConnected)root.replaceChildren(el("div",{class:"cp-empty",role:"status"},el("h3",{},"Could not load uploaded documents"),el("p",{},e.message),button("Retry",load)));}
  }
  function detail(doc) {
    const dialog=el("dialog",{class:"gov-dialog gov-detail-dialog","aria-labelledby":"doc-review-title"});
    const close=()=>dialog.close();
    const information=el("dl",{class:"gov-details-list"},...[ ["Client",doc.workspace_name],["Uploaded by",doc.uploaded_by],["Uploaded",time(doc.uploaded_at)],["Document type",label(doc.kind)],["File fingerprint (SHA-256)",doc.sha256],["LedgerSight state",label(doc.source_state)] ].map(([title,value])=>el("div",{},el("dt",{},title),el("dd",{},value||"Not supplied"))));
    const preview=doc.header?.length&&doc.preview?.length?el("div",{},el("h3",{},"Source preview · First 6 rows"),table(doc.header,doc.preview.map(row=>el("tr",{},row.map(value=>el("td",{},String(value??""))))))):Object.keys(doc.fields||{}).length?el("div",{},el("h3",{},"Extracted document fields"),el("pre",{class:"doc-source-text"},JSON.stringify(doc.fields,null,2))):el("p",{},"No extracted preview is available from the source API. Open this client's Sources page in LedgerSight to inspect the file.");
    const source=el("a",{class:"gov-button gov-secondary",href:"https://ledgersight-a6v24wp5eq-uk.a.run.app/#import",target:"_blank",rel:"noopener noreferrer"},"Open LedgerSight Sources ↗");
    dialog.append(el("div",{class:"gov-dialog-head"},el("span",{class:"gov-kicker"},"LEDGERSIGHT DOCUMENT REVIEW"),button("Close",close)),el("h2",{id:"doc-review-title"},doc.filename),badge(doc.review_status),information,preview);
    if(doc.unsafe_content?.length)dialog.append(el("p",{class:"cp-stage-note"},`Source flags: ${doc.unsafe_content.map(String).join("; ")}`));
    if(doc.review) {
      dialog.append(el("div",{class:"doc-decision-reason"},el("h3",{},`${label(doc.review.decision)} · Review reason`),el("p",{},doc.review.reason),el("p",{class:"cp-meta"},`${doc.review.reviewer} · ${time(doc.review.at)}`)),
        el("details",{class:"cp-source"},el("summary",{},"Signed decision evidence"),el("pre",{class:"doc-source-text"},JSON.stringify(doc.decision_evidence,null,2))));
    } else if(doc.can_review) {
      const reason=el("textarea",{id:"doc-review-reason",required:true,minlength:3,maxlength:2000,rows:4,placeholder:"Explain why the document is accepted or rejected"});
      const error=el("p",{class:"gov-form-error",role:"alert"});
      const approve=el("button",{type:"submit",name:"decision",value:"APPROVED",class:"gov-button"},"Approve document");
      const reject=el("button",{type:"submit",name:"decision",value:"REJECTED",class:"gov-button doc-reject"},"Reject document");
      const form=el("form",{onsubmit:async event=>{
        event.preventDefault();const decision=event.submitter?.value;
        if(!decision)return;
        if(reason.value.trim().length<3){error.textContent="Enter a clear reason before approving or rejecting.";return;}
        approve.disabled=true;reject.disabled=true;
        try{await api(`${base}/${doc.document_key}/decision`,{method:"POST",body:{decision,reason:reason.value.trim(),sha256:doc.sha256,revision:0}});close();toast(`Document ${label(decision).toLowerCase()}; reason and reviewer saved.`);await load();}
        catch(e){error.textContent=e.message;}finally{approve.disabled=false;reject.disabled=false;}
      }},el("label",{for:"doc-review-reason"},"Approval / rejection reason (required)"),reason,
        !data.runtime_gate_enforced?el("p",{class:"cp-stage-note"},"The decision is recorded in TrustOps. The current Cloud Run runtime gate is not enabled, so this action cannot yet block processing in LedgerSight."):"",error,
        el("div",{class:"gov-dialog-actions"},source,reject,approve));
      dialog.append(form);
    } else dialog.append(el("p",{class:"cp-stage-note"},doc.review_block_reason||"An assigned Reviewer can approve or reject here. Customer Admins manage reviewer access at Settings → Team & access."));
    if(!doc.can_review)dialog.append(el("div",{class:"gov-dialog-actions"},source,button("Close",close)));
    document.body.append(dialog);dialog.addEventListener("close",()=>dialog.remove(),{once:true});dialog.showModal();
  }
  function draw() {
    const docs=data.items.filter(doc=>view==="ALL"||doc.review_status===view);
    root.replaceChildren(el("div",{class:"gov-panel-head"},el("div",{},el("span",{class:"gov-kicker"},"UPLOADED IN LEDGERSIGHT"),el("h3",{},"Document approvals"),el("p",{},"Review the file, then approve or reject with a required reason. No re-upload in TrustOps.")),button("Refresh documents",load)),
      !data.runtime_gate_enforced?el("div",{class:"doc-gate-notice",role:"status"},el("strong",{},"Cloud Run processing gate: not enabled"),el("p",{},"Documents and TrustOps decisions are visible here. Blocking unapproved processing requires the LedgerSight runtime gate deployment.")):el("p",{class:"doc-gate-notice"},"Processing gate active · Only approved document fingerprints can be processed."),
      el("nav",{class:"gov-tabs cp-stage-tabs","aria-label":"Document review status"},...[ ["PENDING","Pending"],["APPROVED","Approved"],["REJECTED","Rejected"],["ALL","All documents"] ].map(([value,title])=>el("button",{type:"button","aria-current":view===value?"page":null,onclick:()=>{view=value;documentViews.set(viewKey,value);draw();}},title,el("span",{},data.items.filter(d=>value==="ALL"||d.review_status===value).length)))));
    if(!docs.length)root.append(el("div",{class:"cp-empty"},el("h4",{},"No documents in this view"),el("p",{},"Files uploaded in LedgerSight appear after sync. Select another review status to see previous decisions.")));
    else root.append(table(["Document / client","Uploaded by","Review status","Review reason","Action"],docs.map(doc=>el("tr",{},
      el("td",{},el("strong",{},doc.filename),el("p",{},`${doc.workspace_name} · ${label(doc.kind)}`)),el("td",{},doc.uploaded_by||"Not supplied",el("p",{},time(doc.uploaded_at))),
      el("td",{},badge(doc.review_status)),el("td",{},doc.review?el("div",{class:"doc-row-reason"},el("p",{},doc.review.reason),el("p",{class:"cp-meta"},`${doc.review.reviewer} · ${time(doc.review.at)}`)):"Awaiting reviewer decision"),
      el("td",{},button(doc.can_review?"Review document":"View details",()=>detail(doc),doc.can_review))))));
  }
  root.append(el("p",{class:"cp-empty"},"Loading uploaded documents…"));queueMicrotask(load);return root;
}
