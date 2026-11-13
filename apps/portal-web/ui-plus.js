/* TrustOps UI layer (presentation only; no data, API or logic changes). Port of LedgerSight's ui-plus.js.
   Uses the vendored MIT library Motion (motion.dev, served from /portal/vendor; the CSP allows only same-origin scripts):
   1. the sliding active pill in the sidebar,  2. sidebar collapse to an icon rail with labels beside the icons,
   3. page entrance (title letters, subtitle words, then cards rise),  4. press physics on buttons and tiles.
   If Motion is missing or the user prefers reduced motion, the console works and looks the same, without the movement. */
(function () {
  "use strict";
  const M = window.Motion;
  const REDUCED = !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);
  const motionOn = !!(M && M.animate && !REDUCED);
  const spring = (visualDuration, bounce) => (M ? { type: M.spring, visualDuration, bounce } : {});
  if (motionOn) document.documentElement.classList.add("has-motion");
  const nav = document.getElementById("nav"), main = document.getElementById("main");
  const side = document.querySelector("header.top");
  const wide = matchMedia("(min-width:761px)");

  // Motion leaves inline transform/opacity behind; clear it so cards never become containing blocks for popups.
  const settle = (els, anim) => {
    const clear = () => els.forEach((e) => { e.style.transform = ""; e.style.opacity = ""; e.style.filter = ""; });
    const t = setTimeout(clear, 1600);
    const p = anim && (anim.finished || (anim.then ? anim : null));
    if (p) p.then(() => { clearTimeout(t); clear(); }, () => {});
  };

  /* ---------- 1. sliding active pill (liquid glide: the leading edge springs first, the trailing edge follows) ---------- */
  let pill = null, pillAnims = [];
  const cur = { x: 0, top: 0, bottom: 0, w: 0 };
  const railMoving = () => !!(side && side.dataset.railMoving);
  const paint = () => { pill.style.transform = `translate(${cur.x}px, ${cur.top}px)`; pill.style.width = `${cur.w}px`; pill.style.height = `${Math.max(0, cur.bottom - cur.top)}px`; };
  const stopPill = () => { pillAnims.forEach((a) => { try { a.stop(); } catch (_) { /* finished */ } }); pillAnims = []; };
  function placePill(instant) {
    if (!pill || !nav) return;
    if (!pill.isConnected) nav.prepend(pill);
    nav.classList.add("has-pill");
    const a = nav.querySelector(".module-menu-link[aria-current=page]");
    if (!a || !a.offsetParent || !wide.matches) { pill.style.opacity = "0"; return; }
    pill.style.opacity = "1";
    const box = { x: a.offsetLeft, y: a.offsetTop, width: a.offsetWidth, height: a.offsetHeight };
    // the dark marker sits at the menu's left edge (the menu has 12px / 10px of room each side, like LedgerSight's)
    pill.style.setProperty("--pl", `${a.offsetLeft}px`);
    const same = Math.abs(cur.top - box.y) < 0.5 && Math.abs(cur.bottom - (box.y + box.height)) < 0.5 && Math.abs(cur.x - box.x) < 0.5 && Math.abs(cur.w - box.width) < 0.5;
    if (!motionOn || instant || railMoving() || !cur.w) {
      stopPill(); Object.assign(cur, { x: box.x, top: box.y, bottom: box.y + box.height, w: box.width }); paint(); return;
    }
    if (same) return;
    stopPill();
    const down = box.y >= cur.top, lead = spring(0.3, 0.12), trail = spring(0.5, 0.16);
    const go = (k, to, opts) => pillAnims.push(M.animate(cur[k], to, { ...opts, onUpdate: (v) => { cur[k] = v; paint(); } }));
    go("top", box.y, down ? trail : lead);
    go("bottom", box.y + box.height, down ? lead : trail);
    go("x", box.x, lead); go("w", box.width, lead);
  }
  if (nav) {
    pill = document.createElement("span");
    pill.className = "nav-pill"; pill.setAttribute("aria-hidden", "true");
    // app.js rebuilds the menu on every page change: put the pill back and glide from where it was.
    new MutationObserver(() => { if (!pill.isConnected) nav.prepend(pill); requestAnimationFrame(() => placePill(false)); })
      .observe(nav, { childList: true, subtree: true, attributes: true, attributeFilter: ["aria-current"] });
    let raf = 0;
    if (window.ResizeObserver) new ResizeObserver(() => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => placePill(true)); }).observe(nav);
    window.addEventListener("load", () => placePill(true));
    wide.addEventListener && wide.addEventListener("change", () => placePill(true));
  }

  /* ---------- 2. sidebar collapses to an icon rail; a dark label appears beside the icon under the pointer ---------- */
  const toggle = document.getElementById("sideToggle");
  if (toggle && side) {
    let saved = null; try { saved = localStorage.getItem("to-side-mini"); } catch (_) { /* storage blocked */ }
    let on = saved === null ? matchMedia("(min-width:761px) and (max-width:1100px)").matches : saved === "1";
    const tip = document.createElement("div");
    tip.className = "rail-tip"; tip.setAttribute("role", "tooltip"); tip.setAttribute("aria-hidden", "true");
    document.body.append(tip);
    const hideTip = () => tip.classList.remove("on");
    const apply = () => {
      document.body.classList.toggle("side-mini", on);
      toggle.title = toggle.ariaLabel = on ? "Expand menu" : "Collapse menu";
      toggle.setAttribute("aria-label", toggle.title); toggle.setAttribute("aria-expanded", String(!on));
      side.dataset.railMoving = "1"; placePill(true);
      setTimeout(() => { delete side.dataset.railMoving; placePill(true); }, 480);
    };
    apply();
    toggle.addEventListener("click", () => { on = !on; hideTip(); apply(); try { localStorage.setItem("to-side-mini", on ? "1" : "0"); } catch (_) { /* storage blocked */ } });
    const showTip = (link) => {
      if (!on || !wide.matches || !link) return hideTip();
      const label = link.querySelector(".lbl-t"); if (!label) return hideTip();
      tip.textContent = label.textContent.trim();
      const r = link.getBoundingClientRect();
      tip.style.left = `${Math.round(r.right + 14)}px`; tip.style.top = `${Math.round(r.top + r.height / 2)}px`;
      tip.classList.add("on");
    };
    side.addEventListener("mouseover", (e) => { const l = e.target.closest && e.target.closest(".module-menu-link"); if (l) showTip(l); });
    side.addEventListener("mouseout", (e) => { const l = e.target.closest && e.target.closest(".module-menu-link"); if (l && !l.contains(e.relatedTarget)) hideTip(); });
    side.addEventListener("focusin", (e) => { const l = e.target.closest && e.target.closest(".module-menu-link"); if (l && l.matches(":focus-visible")) showTip(l); });
    side.addEventListener("focusout", hideTip);
    side.addEventListener("click", hideTip);
    if (nav) nav.addEventListener("scroll", hideTip, { passive: true });
  }

  /* ---------- 3. page entrance, in three beats (about 0.5s in all, so it never slows work down) ----------
     1. the title rises letter by letter, the subtitle word by word, each from under its own clip line,
     2. the header actions rise with a short blur-to-sharp,
     3. the page sections, then the cards inside them, rise one after another.
     It runs only when a page is opened (hash change or first load), never when a page refreshes its own data. */
  const UNIT = ".gov-pill, code, kbd, svg, button, input, select, img, .gov-code, .tag";
  function splitWords(node, chars) {
    const inners = [];
    const walk = (parent) => {
      for (const n of [...parent.childNodes]) {
        if (n.nodeType === 3) {
          const parts = n.textContent.split(/(\s+)/);
          if (parts.every((s) => !s.trim())) continue;
          const frag = document.createDocumentFragment();
          for (const s of parts) {
            if (!s) continue;
            if (!s.trim()) { frag.appendChild(document.createTextNode(s)); continue; }
            const w = document.createElement("span");
            if (chars) {
              w.className = "ls-w ls-wc";
              for (const ch of Array.from(s)) { const i = document.createElement("span"); i.className = "ls-wi"; i.textContent = ch; w.appendChild(i); inners.push(i); }
            } else {
              const i = document.createElement("span"); w.className = "ls-w"; i.className = "ls-wi"; i.textContent = s; w.appendChild(i); inners.push(i);
            }
            frag.appendChild(w);
          }
          n.replaceWith(frag);
        } else if (n.nodeType === 1) {
          if (n.matches(UNIT)) {
            const w = document.createElement("span"), i = document.createElement("span");
            w.className = "ls-w"; i.className = "ls-wi"; n.replaceWith(w); i.appendChild(n); w.appendChild(i); inners.push(i);
          } else walk(n);
        }
      }
    };
    walk(node); node.dataset.lsSplit = "1";
    return inners;
  }
  function unsplit(node) {
    if (!node || !node.dataset.lsSplit) return;
    node.querySelectorAll(".ls-w").forEach((w) => {
      if (w.classList.contains("ls-wc")) return w.replaceWith(document.createTextNode(w.textContent));
      const i = w.firstChild; w.replaceWith(...(i ? i.childNodes : []));
    });
    delete node.dataset.lsSplit; node.normalize();
  }
  function revealWords(nodes) {
    let t = 0;
    nodes.forEach((node) => {
      const chars = node.matches("h2");
      const words = splitWords(node, chars);
      if (!words.length) return;
      const step = chars ? Math.min(0.065, 1.0 / words.length) : Math.min(0.045, 0.42 / words.length);
      words.forEach((w) => { w.style.transform = "translateY(110%)"; if (chars) w.style.opacity = "0"; });
      const anim = chars
        ? M.animate(words, { y: ["110%", "0%"], opacity: [0, 1] }, { duration: 0.8, ease: [0.22, 1, 0.36, 1], delay: M.stagger(step, { startDelay: t }) })
        : M.animate(words, { y: ["110%", "0%"] }, { duration: 0.55, ease: [0.22, 1, 0.36, 1], delay: M.stagger(step, { startDelay: t }) });
      const done = () => unsplit(node);
      (anim.finished || anim).then(done, done);
      setTimeout(() => { if (node.dataset.lsSplit) done(); }, (t + step * words.length + 0.8) * 1000 + 400);
      t += Math.min(0.18, step * words.length * 0.5);
    });
  }
  const CARDS = ".tb-stat, .tb-card .ap-item, .tb-card .au-agent, .tb-card .rk-row, .cp-role-grid > article, .tb-two > *, .tb-grid > *, .au-apps > *";
  function enterPage() {
    if (!motionOn || !main) return;
    const page = main.firstElementChild; if (!page) return;
    const head = page.querySelector(".gov-page-heading");
    const texts = head ? [...head.querySelectorAll("h2, p")].filter((e) => e.offsetParent && e.textContent.trim()) : [];
    const headRest = head ? [...head.querySelectorAll(".gov-actions, .gov-back")].filter((e) => e.offsetParent) : [];
    const cards = [...page.querySelectorAll(CARDS)].filter((e) => e.offsetParent).slice(0, 18);
    const nested = new Set(cards);
    const outer = [...page.children].filter((e) => e.offsetParent && e !== head && !e.contains(head) && !nested.has(e));
    revealWords(texts);
    headRest.forEach((e) => { e.style.opacity = "0"; });
    settle(headRest, M.animate(headRest, { opacity: [0, 1], y: [14, 0], filter: ["blur(6px)", "blur(0px)"] },
      { duration: 0.5, ease: [0.22, 1, 0.36, 1], delay: M.stagger(0.06, { startDelay: 0.22 }) }));
    [...outer, ...cards].forEach((e) => { e.style.opacity = "0"; });
    if (outer.length) settle(outer, M.animate(outer, { opacity: [0, 1], y: [28, 0] }, { ...spring(0.55, 0.1), delay: M.stagger(0.06, { startDelay: 0.24 }) }));
    if (cards.length) settle(cards, M.animate(cards, { opacity: [0, 1], y: [22, 0], scale: [0.985, 1] }, { ...spring(0.55, 0.1), delay: M.stagger(0.04, { startDelay: 0.3 }) }));
  }
  if (main && motionOn) {
    let openUntil = performance.now() + 4000, lastHash = location.hash, timer = 0;
    window.addEventListener("hashchange", () => {
      // Only a change of page counts (#/decisions → #/risk); filters inside a page (#/decisions/deny) do not.
      const pageOf = (h) => (h || "#/dashboard").split("/")[1];
      if (pageOf(location.hash) !== pageOf(lastHash)) openUntil = performance.now() + 2500;
      lastHash = location.hash;
    });
    // app.js fills <main> asynchronously after the data arrives; animate once the new page has settled for a frame.
    new MutationObserver((recs) => {
      if (performance.now() > openUntil) return;
      if (!recs.some((r) => r.target === main)) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        const page = main.firstElementChild;
        if (!page || !page.querySelector(".gov-page-heading")) return;   // still loading
        openUntil = 0; enterPage();
      }, 30);
    }).observe(main, { childList: true });
  }

  /* ---------- 4. press physics on buttons, chips and tiles ---------- */
  if (motionOn) {
    const PRESS = "button:not(:disabled), a.gov-button, .tb-stat, .tb-seg, .ws-pill, .period-chip, .role-pill, .avatar";
    document.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      const el = ev.target.closest && ev.target.closest(PRESS);
      if (!el) return;
      const s = el.matches(".tb-stat") ? 0.985 : 0.96;
      M.animate(el, { scale: s }, { type: M.spring, stiffness: 700, damping: 32 });
      const up = () => {
        ["pointerup", "pointercancel", "pointerleave"].forEach((k) => el.removeEventListener(k, up));
        settle([el], M.animate(el, { scale: 1 }, { type: M.spring, stiffness: 520, damping: 16 }));
      };
      ["pointerup", "pointercancel", "pointerleave"].forEach((k) => el.addEventListener(k, up));
    }, true);
  }
})();
