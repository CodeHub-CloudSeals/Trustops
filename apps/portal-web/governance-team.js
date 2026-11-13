export function registerGovernanceTeam({routes,main,el,api,state,toast}) {
  const base="/v1/governance/team";
  const definitions=[
    ["Admin","Adds applications and people, changes policies, suspends agents, and can approve."],
    ["Approver","Approves or rejects items in Approvals. Can never approve something they submitted."],
    ["Viewer / Auditor","Sees everything and downloads reports. Cannot change or approve anything."],
    ["Preparer","Works only in connected applications (for example uploads and runs in LedgerSight). Cannot open TrustOps."]
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
    const apps=data.applications||[];
    const appName=id=>(apps.find(a=>a.id===id)||{}).name||id;
    const appRoleOf=role=>({admin:"Reviewer",approver:"Reviewer",none:"Preparer"})[role]||"";
    const roleIdOf=roles=>roles.includes("customer_admin")?"admin":roles.includes("customer_controller")?"approver":roles.includes("customer_app_user")?"none":"viewer";
    const accessText=m=>{const r=appRoleOf(roleIdOf(m.roles||[]));if(!r)return "—";
      const ex=Object.entries(m.app_access||{});if(m.apps==null&&ex.length)return ex.map(([id,v])=>`${appName(id)}: ${v==="reviewer"?"Reviewer":"Preparer"}`).join(" · ");
      const list=m.apps==null?apps:apps.filter(a=>m.apps.includes(a.id));return list.length?list.map(a=>`${a.name}: ${r}`).join(" · "):"No applications";};
    // Which applications this person may use. Their role inside each one follows the TrustOps role.
    const accessFields=(current,roleSel)=>{
      const boxes=apps.map(a=>el("input",{type:"checkbox",id:`app-${a.id}`,value:a.id,checked:current==null||current.includes(a.id)}));
      const note=el("p",{class:"cp-form-note"});
      const sync=()=>{const r=appRoleOf(roleSel.value);boxes.forEach(b=>b.disabled=!r);
        note.textContent=!apps.length?"No applications are connected yet. Add one in Applications.":r?`In the applications they tick, they work as ${r}. They sign in there with the same work email.`:"Viewers have no application access. Choose Admin, Approver or Preparer to give application access.";};
      roleSel.addEventListener("change",sync);sync();
      const nodes=apps.length?[el("label",{},"Application access"),el("div",{class:"cp-app-boxes"},apps.map((a,i)=>el("label",{class:"cp-app-box",for:`app-${a.id}`},boxes[i],` ${a.name}`))),note]:[note];
      return {nodes,read:()=>appRoleOf(roleSel.value)?boxes.filter(b=>b.checked).map(b=>b.value):[]};
    };
    function addUser() {
      modal("Add a team member",d=>{
        const email=el("input",{id:"team-email",type:"email",required:true,placeholder:"colleague@company.com",maxlength:200});
        const role=el("select",{id:"team-role"},options("viewer"));
        const error=el("p",{class:"gov-form-error",role:"alert"});
        const submit=el("button",{type:"submit",class:"gov-button"},"Register access");
        const acc=accessFields(null,role);
        return el("form",{onsubmit:async e=>{
          e.preventDefault();submit.disabled=true;
          try{await api(base+"/invites",{method:"POST",body:{email:email.value.trim(),role:role.value,apps:acc.read()}});d.close();toast("Access registered. No invitation email was sent.");await reload();}
          catch(e){error.textContent=e.message;}finally{submit.disabled=false;}
        }},el("p",{},"Register their work email and responsibility in this customer workspace. They use their own organisation sign-in; administrators do not set passwords."),
          el("label",{for:"team-email"},"Work email"),email,el("label",{for:"team-role"},"TrustOps role"),role,...acc.nodes,
          el("p",{class:"cp-form-note"},data.local_preview?"Local preview: after registration, activate a preview membership from the pending list. Hosted users join after verified sign-in.":"Access is registered here. The user joins when they sign in with this verified work email. Email delivery is not configured in this flow."),error,
          el("div",{class:"gov-dialog-actions"},button("Cancel",()=>d.close()),submit));
      });
    }
    function changeRole(member) {
      modal("Change access",d=>{
        const selected=member.roles.includes("customer_admin")?"admin":member.roles.includes("customer_controller")?"approver":member.roles.includes("customer_app_user")?"none":"viewer";
        const role=el("select",{id:"team-change-role"},options(selected));
        const acc=accessFields(member.apps,role);
        const error=el("p",{class:"gov-form-error",role:"alert"});
        return el("form",{onsubmit:async e=>{e.preventDefault();try{await api(`${base}/members/${encodeURIComponent(member.sub)}/role`,{method:"PUT",body:{revision:member.revision,role:role.value,apps:acc.read()}});d.close();toast("Access updated");if(member.sub===data.actor){state.me=null;location.reload();}else await reload();}catch(e){error.textContent=e.message;}}},el("p",{},member.email),
          el("label",{for:"team-change-role"},"TrustOps role"),role,...acc.nodes,el("p",{class:"cp-form-note"},"Changes take effect on the next API request. At least one customer administrator must remain."),error,
          el("div",{class:"gov-dialog-actions"},button("Cancel",()=>d.close()),el("button",{class:"gov-button",type:"submit"},"Save")));
      });
    }
    function changePending(p) {
      modal("Change access",d=>{
        const sel=p.roles.includes("customer_admin")?"admin":p.roles.includes("customer_controller")?"approver":p.roles.includes("customer_app_user")?"none":"viewer";
        const role=el("select",{id:"team-change-role"},options(sel));
        const acc=accessFields(p.apps,role);
        const error=el("p",{class:"gov-form-error",role:"alert"});
        return el("form",{onsubmit:async e=>{e.preventDefault();try{await api(`${base}/pending/${encodeURIComponent(p.email)}/access`,{method:"PUT",body:{role:role.value,apps:acc.read()}});d.close();toast("Access updated");await reload();}catch(e){error.textContent=e.message;}}},
          el("p",{},p.email),el("label",{for:"team-change-role"},"TrustOps role"),role,...acc.nodes,error,
          el("div",{class:"gov-dialog-actions"},button("Cancel",()=>d.close()),el("button",{class:"gov-button",type:"submit"},"Save")));
      });
    }
    function revoke(member) {
      modal("Remove team member?",d=>el("div",{},el("p",{},`${member.email} will be removed. They lose access to TrustOps and to every connected application (for example LedgerSight) at their next request. What they did before stays in the evidence record.`),
        el("div",{class:"gov-dialog-actions"},button("Cancel",()=>d.close()),button("Remove",async()=>{await api(`${base}/members/${encodeURIComponent(member.sub)}/revoke`,{method:"POST",body:{revision:member.revision}});d.close();toast("Team member removed");await reload();},true))));
    }
    async function previewAs(member) {
      const users=await fetch("/v1/dev/users").then(r=>r.json());
      const token=users.items.find(u=>u.sub===member.sub)?.token;
      if(!token)throw new Error("Preview identity is unavailable");
      sessionStorage.setItem("taad_token",token);location.reload();
    }
    const rows=data.members.map(m=>el("tr",{},el("td",{},el("strong",{},m.email),m.sub===data.actor?el("p",{},"You"):""),
      el("td",{},m.role_labels.join(", ")),el("td",{},accessText(m)),el("td",{},el("span",{class:"gov-pill gov-green"},"Active")),
      el("td",{},el("div",{class:"gov-actions"},button("Change access",()=>changeRole(m)),m.sub!==data.actor?button("Remove",()=>revoke(m)):"",data.local_preview&&m.sub!==data.actor?button("Preview as",()=>previewAs(m)):""))));
    const pending=data.pending.map(p=>el("tr",{},el("td",{},p.email),el("td",{},p.role_labels.join(", ")),el("td",{},accessText(p)),el("td",{},p.roles.includes("customer_app_user")?"Ready: signs in to the application":"Pending first sign-in"),
      el("td",{},el("div",{class:"gov-actions"},button("Change access",()=>changePending(p)),data.local_preview?button("Activate local preview",async()=>{await api(base+"/preview-activate",{method:"POST",body:{email:p.email,role:"viewer"}});toast("Local preview membership activated with the registered role");await reload();}):"User signs in with verified work email",button("Remove",async()=>{if(!confirm(`Remove ${p.email}? They lose access to TrustOps and connected applications.`))return;await api(base+"/pending/cancel",{method:"POST",body:{email:p.email,role:"viewer"}});toast("Team member removed");await reload();})))));
    const root=el("div",{class:"gov"},
      el("header",{class:"gov-page-heading"},el("div",{},el("span",{class:"gov-kicker"},"SETTINGS"),el("h2",{},"Team & access"),el("p",{},"Who can change TrustOps, who approves, and who can only look.")),button("Add user",addUser,true)),
      el("section",{class:"gov-panel cp-workspace"},el("div",{class:"gov-panel-head"},el("div",{},el("h3",{},"Roles"),el("p",{},"Approvals happen in TrustOps → Approvals. People who submit work in an application do not need a TrustOps login."))),
        el("div",{class:"cp-role-grid"},definitions.map(([title,copy])=>el("article",{},el("h4",{},title),el("p",{},copy))))),
      el("section",{class:"gov-panel cp-workspace"},el("div",{class:"gov-panel-head"},el("div",{},el("h3",{},"Team members"),el("p",{},"Only customer administrators can change team access."))),table(["User","TrustOps role","Applications","Status","Actions"],rows)),
      el("section",{class:"gov-panel"},el("div",{class:"gov-panel-head"},el("div",{},el("h3",{},"Registered, not yet signed in to TrustOps"),el("p",{},"People with application access only never need to sign in to TrustOps."))),pending.length?table(["Work email","TrustOps role","Applications","Status","Actions"],pending):el("p",{class:"cp-empty"},"No pending access registrations.")),
      el("p",{class:"cp-stage-note"},"Application access is managed here too. Applications check it each time someone signs in."));
    main.replaceChildren(root);
  };
}
