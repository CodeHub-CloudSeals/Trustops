export function registerGovernanceTeam({routes,main,el,api,state,toast}) {
  const base="/v1/governance/team";
  const definitions=[
    ["Customer Admin","Add users and manage access to the customer workspace."],
    ["User / Submitter","Upload documents in LedgerSight and see their TrustOps review status."],
    ["Reviewer","Review documents uploaded in LedgerSight. Approve or reject with a required reason; cannot review own uploads."],
    ["Viewer / Auditor","Read runs, reviews, policies and evidence. Cannot change or approve documents."]
  ];
  const button=(text,fn,primary=false)=>el("button",{type:"button",class:`gov-button${primary?"":" gov-secondary"}`,onclick:async()=>{try{await fn();}catch(e){toast(e.message,true);}}},text);
  const table=(headers,rows)=>el("div",{class:"gov-table-wrap"},el("table",{class:"gov-table"},el("thead",{},el("tr",{},headers.map(h=>el("th",{scope:"col"},h)))),el("tbody",{},rows)));
  function modal(title,build) {
    const d=el("dialog",{class:"gov-dialog cp-dialog","aria-labelledby":"team-dialog-title"});
    d.append(el("div",{class:"gov-dialog-head"},el("span",{class:"gov-kicker"},"TEAM & ACCESS"),button("Close",()=>d.close())),el("h2",{id:"team-dialog-title"},title),build(d));
    document.body.append(d);d.addEventListener("close",()=>d.remove(),{once:true});d.showModal();
  }
  routes["governance-team"]=async()=>{
    const data=await api(base);
    const reload=()=>routes["governance-team"]();
    const options=selected=>data.role_options.map(r=>el("option",{value:r.id,selected:r.id===selected},r.label));
    function addUser() {
      modal("Add a team member",d=>{
        const email=el("input",{id:"team-email",type:"email",required:true,placeholder:"colleague@company.com",maxlength:200});
        const role=el("select",{id:"team-role"},options("viewer"));
        const error=el("p",{class:"gov-form-error",role:"alert"});
        const submit=el("button",{type:"submit",class:"gov-button"},"Register access");
        return el("form",{onsubmit:async e=>{
          e.preventDefault();submit.disabled=true;
          try{await api(base+"/invites",{method:"POST",body:{email:email.value.trim(),role:role.value}});d.close();toast("Access registered. No invitation email was sent.");await reload();}
          catch(e){error.textContent=e.message;}finally{submit.disabled=false;}
        }},el("p",{},"Register their work email and responsibility in this customer workspace. They use their own organisation sign-in; administrators do not set passwords."),
          el("label",{for:"team-email"},"Work email"),email,el("label",{for:"team-role"},"TrustOps role"),role,
          el("p",{class:"cp-form-note"},data.local_preview?"Local preview: after registration, activate a preview membership from the pending list. Hosted users join after verified sign-in.":"Access is registered here. The user joins when they sign in with this verified work email. Email delivery is not configured in this flow."),error,
          el("div",{class:"gov-dialog-actions"},button("Cancel",()=>d.close()),submit));
      });
    }
    function changeRole(member) {
      modal("Change team role",d=>{
        const selected=member.roles.includes("customer_admin")?"admin":member.roles.some(r=>["customer_operator","customer_architect"].includes(r))?"submitter":member.roles.some(r=>["customer_risk","customer_controller"].includes(r))?"reviewer":"viewer";
        const role=el("select",{id:"team-change-role"},options(selected));
        const error=el("p",{class:"gov-form-error",role:"alert"});
        return el("form",{onsubmit:async e=>{e.preventDefault();try{await api(`${base}/members/${encodeURIComponent(member.sub)}/role`,{method:"PUT",body:{revision:member.revision,role:role.value}});d.close();toast("Team role updated");if(member.sub===data.actor){state.me=null;location.reload();}else await reload();}catch(e){error.textContent=e.message;}}},el("p",{},member.email),
          el("label",{for:"team-change-role"},"New TrustOps role"),role,el("p",{class:"cp-form-note"},"Role changes take effect on the next API request. At least one customer administrator must remain."),error,
          el("div",{class:"gov-dialog-actions"},button("Cancel",()=>d.close()),el("button",{class:"gov-button",type:"submit"},"Save role")));
      });
    }
    function revoke(member) {
      modal("Revoke workspace access?",d=>el("div",{},el("p",{},`${member.email} will lose TrustOps access to this customer workspace. Their previous policy and review history is retained.`),
        el("div",{class:"gov-dialog-actions"},button("Cancel",()=>d.close()),button("Revoke access",async()=>{await api(`${base}/members/${encodeURIComponent(member.sub)}/revoke`,{method:"POST",body:{revision:member.revision}});d.close();toast("Workspace access revoked");await reload();},true))));
    }
    async function previewAs(member) {
      const users=await fetch("/v1/dev/users").then(r=>r.json());
      const token=users.items.find(u=>u.sub===member.sub)?.token;
      if(!token)throw new Error("Preview identity is unavailable");
      sessionStorage.setItem("taad_token",token);location.reload();
    }
    const rows=data.members.map(m=>el("tr",{},el("td",{},el("strong",{},m.email),m.sub===data.actor?el("p",{},"You"):""),
      el("td",{},m.role_labels.join(", ")),el("td",{},el("span",{class:"gov-pill gov-green"},"Active")),
      el("td",{},el("div",{class:"gov-actions"},button("Change role",()=>changeRole(m)),m.sub!==data.actor?button("Revoke",()=>revoke(m)):"",data.local_preview&&m.sub!==data.actor?button("Preview as",()=>previewAs(m)):""))));
    const pending=data.pending.map(p=>el("tr",{},el("td",{},p.email),el("td",{},p.role_labels.join(", ")),el("td",{},"Pending first sign-in"),
      el("td",{},el("div",{class:"gov-actions"},data.local_preview?button("Activate local preview",async()=>{await api(base+"/preview-activate",{method:"POST",body:{email:p.email,role:"viewer"}});toast("Local preview membership activated with the registered role");await reload();}):"User signs in with verified work email",button("Cancel registration",async()=>{await api(base+"/pending/cancel",{method:"POST",body:{email:p.email,role:"viewer"}});toast("Pending registration cancelled");await reload();})))));
    const root=el("div",{class:"gov"},
      el("header",{class:"gov-page-heading"},el("div",{},el("span",{class:"gov-kicker"},"SETTINGS"),el("h2",{},"Team & access"),el("p",{},"Add colleagues and separate uploading, document review and administration.")),button("Add user",addUser,true)),
      el("section",{class:"gov-panel cp-workspace"},el("div",{class:"gov-panel-head"},el("div",{},el("h3",{},"Where approvals happen"),el("p",{},"Document approval: Reviews → Document approvals → Review document. Approve or reject with a required reason."))),
        el("div",{class:"cp-role-grid"},definitions.map(([title,copy])=>el("article",{},el("h4",{},title),el("p",{},copy))))),
      el("section",{class:"gov-panel cp-workspace"},el("div",{class:"gov-panel-head"},el("div",{},el("h3",{},"Team members"),el("p",{},"Only customer administrators can change team access."))),table(["User","TrustOps responsibility","Status","Actions"],rows)),
      el("section",{class:"gov-panel"},el("div",{class:"gov-panel-head"},el("div",{},el("h3",{},"Pending access registrations"),el("p",{},"Registration does not send an invitation email or create a password."))),pending.length?table(["Work email","Role","Status","Next step"],pending):el("p",{class:"cp-empty"},"No pending access registrations.")),
      el("p",{class:"cp-stage-note"},"These roles control TrustOps document reviews. LedgerSight upload access is managed in LedgerSight."));
    main.replaceChildren(root);
  };
}
