// certwatch — melhorias opcionais (a aplicação funciona sem JavaScript).
document.addEventListener("DOMContentLoaded", () => {
  // "Selecionar todos" numa tabela com checkboxes (name="cn" ou o indicado em data-check-all)
  document.querySelectorAll("input[data-check-all]").forEach((all) => {
    const form = all.closest("form");
    const name = all.dataset.checkAll || "cn";
    const boxes = () => Array.from(form.querySelectorAll(`input[type=checkbox][name="${name}"]`));
    const count = form.querySelector("[data-sel-count]");
    const sync = () => {
      const n = boxes().filter((b) => b.checked).length;
      if (count) count.textContent = n;
      all.checked = n > 0 && n === boxes().length;
      all.indeterminate = n > 0 && n < boxes().length;
    };
    all.addEventListener("change", () => { boxes().forEach((b) => (b.checked = all.checked)); sync(); });
    boxes().forEach((b) => b.addEventListener("change", sync));
    sync();
  });

  // Tabelas no telemóvel: cada linha passa a cartão. O nome de cada coluna vem do cabeçalho (data-label).
  document.querySelectorAll("table").forEach((table) => {
    if (table.classList.contains("no-stack") || table.classList.contains("matrix")) return;
    const head = table.tHead && table.tHead.rows[0];
    if (!head) return;
    const labels = [];
    Array.from(head.cells).forEach((th) => {
      const text = (th.getAttribute("aria-label") || th.textContent || "").trim().replace(/\s+/g, " ");
      for (let i = 0; i < (th.colSpan || 1); i++) labels.push(text);
    });
    Array.from(table.tBodies).forEach((tb) => Array.from(tb.rows).forEach((tr) => {
      let col = 0;
      Array.from(tr.cells).forEach((td) => {
        if (td.colSpan > 1 && td.colSpan >= labels.length) td.classList.add("full");
        else {
          if (!td.hasAttribute("data-label")) td.setAttribute("data-label", labels[col] || "");
          // conteúdo num só bloco, para ficar à direita do nome da coluna no telemóvel (display: contents no computador)
          if (td.childNodes.length && !(td.childNodes.length === 1 && td.firstChild.classList && td.firstChild.classList.contains("cv"))) {
            const cv = document.createElement("div");
            cv.className = "cv";
            while (td.firstChild) cv.appendChild(td.firstChild);
            td.appendChild(cv);
          }
        }
        col += td.colSpan || 1;
      });
    }));
    table.classList.add("stack");
    // primeira coluna com texto (normalmente o nome): ocupa mais espaço no modo cartão
    Array.from(table.tBodies).forEach((tb) => Array.from(tb.rows).forEach((tr) => {
      const lead = Array.from(tr.cells).find((td) => !td.classList.contains("full") && td.textContent.trim() && !td.querySelector("input[type=checkbox]"));
      if (lead) lead.classList.add("lead");
    }));
    fitTable(table);
  });

  // Adaptar cada tabela à largura que tem (ecrã, coluna ou cartão onde está) e voltar a adaptar quando muda
  function fitTable(table) {
    const wrap = table.parentElement;
    if (!wrap) return;
    const width = wrap.clientWidth;
    if (!width || table.dataset.fitWidth === String(width)) return;
    table.dataset.fitWidth = String(width);
    table.classList.remove("is-stacked", "hide-opt");
    if (window.innerWidth <= 760) return;                     // telemóvel: o CSS já faz cartões
    const over = () => table.getBoundingClientRect().width > wrap.clientWidth + 1;
    if (!over()) return;
    if (table.querySelector(".opt")) {
      table.classList.add("hide-opt");
      if (!over()) return;
      table.classList.remove("hide-opt");
    }
    table.classList.add("is-stacked");
  }
  if ("ResizeObserver" in window) {
    const ro = new ResizeObserver((entries) => entries.forEach((en) => {
      const t = en.target.querySelector(":scope > table.stack");
      if (t) fitTable(t);
    }));
    document.querySelectorAll("table.stack").forEach((t) => t.parentElement && ro.observe(t.parentElement));
  }
  // Relatório por email: editar o email diretamente (escrever, apagar, tirar linhas e colunas das tabelas)
  const editors = Array.from(document.querySelectorAll("[data-email]"));
  let editing = null;
  window.addEventListener("beforeunload", (e) => {
    if (editing && editing.dirty()) { e.preventDefault(); e.returnValue = ""; }
  });
  editors.forEach((card) => {
    const frame = card.querySelector("iframe");
    const form = card.querySelector("[data-edit-form]");
    const start = card.querySelector("[data-edit-start]");
    const del = card.querySelector("[data-row-del]");
    if (!frame || !form || !start || !del) return;
    start.hidden = false;
    let doc = null, initial = [], history = [], row = null, lastPush = 0, on = false;
    const sections = () => (doc ? Array.from(doc.querySelectorAll("[data-cw-part]")) : []);
    const snap = () => sections().map((x) => x.innerHTML);
    const push = () => { history.push(snap()); if (history.length > 200) history.shift(); lastPush = Date.now(); };
    const fit = () => { if (doc && doc.body) frame.style.height = Math.max(240, Math.ceil(doc.body.getBoundingClientRect().height) + 40) + "px"; };
    const el = (n) => (n && n.nodeType === 1 ? n : n && n.parentElement);
    const rowOf = (n) => {
      const e = el(n);
      const tr = e && e.closest("tr");
      return tr && tr.querySelector("td") && tr.closest("[data-cw-part]") ? tr : null;
    };
    const cellOf = (n) => { const e = el(n); return e && e.closest("td, th"); };
    const place = (tr) => {
      row = tr && tr.isConnected ? tr : null;
      if (!row) { del.hidden = true; return; }
      const r = row.getBoundingClientRect();
      del.hidden = false;
      del.style.top = (frame.offsetTop + r.top + r.height / 2 - 14) + "px";
      del.style.left = (frame.offsetLeft + Math.min(r.right + 6, frame.clientWidth - 34)) + "px";
    };
    const dropRows = (rows) => {
      rows.forEach((tr) => {
        const table = tr.closest("table");
        tr.remove();
        if (table && !table.querySelector("td")) table.remove();
      });
      place(null); fit();
    };
    const delRow = (tr) => { if (tr) { push(); dropRows([tr]); } };
    const delCol = () => {
      const sel = doc.getSelection();
      const cell = sel && sel.rangeCount ? cellOf(sel.getRangeAt(0).startContainer) : null;
      if (!cell) { alertBox("Clique primeiro numa célula da coluna a apagar."); return; }
      const table = cell.closest("table"), idx = cell.cellIndex;
      push();
      Array.from(table.rows).forEach((tr) => { if (tr.cells.length > idx) tr.deleteCell(idx); });
      if (!table.querySelector("td, th")) table.remove();
      place(null); fit();
    };
    const undo = () => {
      const prev = history.pop();
      if (!prev) return;
      sections().forEach((x, i) => { if (prev[i] !== undefined) x.innerHTML = prev[i]; });
      place(null); fit();
    };
    const note = form.querySelector(".email-note") || document.createElement("p");
    const alertBox = (msg) => { note.className = "small note warn email-note"; note.textContent = msg; form.append(note); };
    const setOthers = (disabled) => editors.forEach((c) => {
      const b = c.querySelector("[data-edit-start]");
      if (c !== card && b) b.disabled = disabled;
    });
    const stop = () => {
      on = false; editing = null; doc = null; history = [];
      frame.src = card.dataset.preview; frame.style.height = "";
      form.hidden = true; start.hidden = false; del.hidden = true;
      card.querySelectorAll("[data-edit-hide]").forEach((x) => (x.hidden = false));
      card.classList.remove("is-editing"); setOthers(false);
    };
    frame.addEventListener("load", () => {
      if (!on) return;
      doc = frame.contentDocument;
      if (!doc) return;
      const st = doc.createElement("style");
      st.textContent = "[data-cw-part]{outline:1px dashed #b8bfcc;outline-offset:4px;margin:0 0 16px;min-height:1em}" +
        "[data-cw-part]:focus{outline:2px solid #3b5bdb}[data-cw-part] tr:hover td{box-shadow:inset 0 0 0 9999px rgba(220,38,38,.08)}";
      doc.head.append(st);
      sections().forEach((x) => { x.contentEditable = "true"; x.spellcheck = true; });
      initial = snap(); history = [];
      doc.addEventListener("mouseover", (e) => place(rowOf(e.target)));
      doc.addEventListener("click", (e) => place(rowOf(e.target)));
      doc.addEventListener("keyup", () => { const s = doc.getSelection(); place(s && s.rangeCount ? rowOf(s.anchorNode) : null); });
      doc.addEventListener("scroll", () => place(row));
      doc.addEventListener("beforeinput", () => { if (Date.now() - lastPush > 800) push(); });
      doc.addEventListener("input", fit);
      doc.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && !e.shiftKey && e.key.toLowerCase() === "z") { e.preventDefault(); undo(); return; }
        if (e.key !== "Backspace" && e.key !== "Delete") return;
        const sel = doc.getSelection();
        if (!sel || !sel.rangeCount || sel.isCollapsed) return;
        const rg = sel.getRangeAt(0);
        const a = cellOf(rg.startContainer), b = cellOf(rg.endContainer);
        if (!a || !b || a === b) return;                 // dentro de uma célula ou fora das tabelas: apagar normal
        const rows = Array.from(doc.querySelectorAll("[data-cw-part] tr")).filter((tr) => tr.querySelector("td") && rg.intersectsNode(tr));
        if (!rows.length) return;
        e.preventDefault(); push(); dropRows(rows); sel.removeAllRanges();
      });
      fit();
      const first = sections()[0];
      if (first) first.focus();
    });
    start.addEventListener("click", () => {
      if (editing) return;
      on = true;
      editing = { dirty: () => doc && snap().some((h, i) => h !== initial[i]) };
      frame.src = card.dataset.editor;
      form.hidden = false; start.hidden = true;
      card.querySelectorAll("[data-edit-hide]").forEach((x) => (x.hidden = true));
      card.classList.add("is-editing"); setOthers(true);
    });
    del.addEventListener("click", () => delRow(row));
    form.querySelector("[data-edit-cancel]").addEventListener("click", () => {
      if (editing && editing.dirty() && !window.confirm("Descartar as alterações a este email?")) return;
      stop();
    });
    form.querySelectorAll("[data-cmd]").forEach((b) => b.addEventListener("click", () => {
      if (!doc) return;
      const cmd = b.dataset.cmd;
      if (cmd === "undo") return undo();
      if (cmd === "delcol") return delCol();
      if (cmd === "delrow") {
        const s = doc.getSelection();
        const tr = row || (s && s.rangeCount ? rowOf(s.anchorNode) : null);
        return tr ? delRow(tr) : alertBox("Clique primeiro na linha da tabela a apagar.");
      }
      frame.contentWindow.focus(); push(); doc.execCommand(cmd);
    }));
    form.addEventListener("submit", (e) => {
      if (!doc) { e.preventDefault(); return; }
      // linhas que ficaram vazias (todas as células apagadas) saem da tabela
      dropRows(Array.from(doc.querySelectorAll("[data-cw-part] tr")).filter((tr) => tr.querySelector("td") && !tr.textContent.trim()));
      form.querySelectorAll("input[data-sec]").forEach((x) => x.remove());
      sections().forEach((x, i) => {
        if (x.innerHTML === initial[i]) return;
        const inp = document.createElement("input");
        inp.type = "hidden"; inp.name = "sec_" + x.dataset.cwPart; inp.value = x.innerHTML; inp.dataset.sec = "1";
        form.append(inp);
      });
      editing = null;
    });
  });
  // Botões que pedem confirmação antes de enviar (ex.: aplicar na UCMDB)
  document.querySelectorAll("button[data-confirm]").forEach((b) => b.addEventListener("click", (e) => {
    if (!window.confirm(b.dataset.confirm)) e.preventDefault();
  }));
});

// O foco da vigia sai do logótipo e varre a página enquanto se espera: a página seguinte a carregar, um ficheiro a
// enviar, ou trabalho em curso no servidor (execuções, reconciliações, pedidos, escritas na UCMDB). O feixe bate nas
// margens da janela e reflete-se. Não intercepta cliques e não corre se a animação do logótipo estiver parada.
document.addEventListener("DOMContentLoaded", () => {
  const logos = Array.from(document.querySelectorAll("svg.atalaia"));
  if (!logos.length || !document.body.animate) return;
  const visible = () => logos.find((l) => l.getClientRects().length && l.getBoundingClientRect().width > 0);
  const animated = (l) => l && l.getAnimations({ subtree: true }).length > 0;
  const LOOK = new Set(["atl-foco", "atl-braco", "atl-cabeca", "atl-cara", "atl-nariz", "atl-pala", "atl-pupilas"]);
  const setRate = (r) => logos.forEach((l) => l.getAnimations({ subtree: true }).forEach((a) => {
    if (LOOK.has(a.animationName)) a.updatePlaybackRate(r);
  }));

  const NS = "http://www.w3.org/2000/svg";
  const mk = (tag, attrs, parent) => {
    const e = document.createElementNS(NS, tag);
    Object.entries(attrs || {}).forEach(([k, v]) => e.setAttribute(k, v));
    if (parent) parent.appendChild(e);
    return e;
  };
  const svg = mk("svg", { class: "foco-pagina", "aria-hidden": "true", focusable: "false" });
  const defs = mk("defs", {}, svg);
  const MAXSEG = 4;
  const layers = [{ spread: 0.12, alpha: 0.16 }, { spread: 0.05, alpha: 0.3 }].map((ly, li) => {
    ly.parts = [];
    for (let i = 0; i < MAXSEG; i++) {
      const g = mk("linearGradient", { id: `foco-g${li}${i}`, gradientUnits: "userSpaceOnUse" }, defs);
      const s0 = mk("stop", { offset: "0", "stop-color": "#ffeaa6" }, g);
      const s1 = mk("stop", { offset: "1", "stop-color": "#ffeaa6" }, g);
      const poly = mk("polygon", { fill: `url(#foco-g${li}${i})` }, svg);
      ly.parts.push({ g, s0, s1, poly });
    }
    return ly;
  });
  const rg = mk("radialGradient", { id: "foco-brilho" }, defs);
  mk("stop", { offset: "0", "stop-color": "#fff3c4", "stop-opacity": "1" }, rg);
  mk("stop", { offset: "1", "stop-color": "#fff3c4", "stop-opacity": "0" }, rg);
  const glows = [];
  for (let i = 0; i < MAXSEG - 1; i++) glows.push(mk("circle", { fill: "url(#foco-brilho)", r: "0" }, svg));
  document.body.appendChild(svg);

  const center = (el) => { const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; };
  function draw() {
    const logo = visible();
    const hand = logo && logo.querySelector(".atl-mao .atl-punho");
    const lens = logo && logo.querySelector(".atl-mao .atl-lente");
    if (!hand || !lens) return;
    const W = window.innerWidth, H = window.innerHeight;
    const L = center(lens), P = center(hand);
    let dx = L.x - P.x, dy = L.y - P.y;
    const n = Math.hypot(dx, dy) || 1;
    dx /= n; dy /= n;
    const total = 1.25 * Math.hypot(W, H);
    const segs = [];
    let p = { x: L.x, y: L.y }, s = 0;
    for (let i = 0; i < MAXSEG && s < total - 1; i++) {
      const tx = dx > 0 ? (W - p.x) / dx : dx < 0 ? -p.x / dx : Infinity;
      const ty = dy > 0 ? (H - p.y) / dy : dy < 0 ? -p.y / dy : Infinity;
      const t = Math.max(0, Math.min(tx, ty, total - s));
      const q = { x: p.x + dx * t, y: p.y + dy * t };
      segs.push({ p, q, dx, dy, s0: s, s1: s + t, bounce: t === tx || t === ty });
      if (t === tx) dx = -dx;
      if (t === ty) dy = -dy;
      p = q; s += t;
    }
    const fade = (d) => Math.pow(Math.max(0, 1 - d / total), 1.4);
    layers.forEach((ly) => ly.parts.forEach((part, i) => {
      const sg = segs[i];
      if (!sg) { part.poly.setAttribute("points", ""); return; }
      const w0 = 3 + sg.s0 * Math.tan(ly.spread), w1 = 3 + sg.s1 * Math.tan(ly.spread);
      const nx = -sg.dy, ny = sg.dx;
      part.poly.setAttribute("points", [
        [sg.p.x + nx * w0, sg.p.y + ny * w0], [sg.q.x + nx * w1, sg.q.y + ny * w1],
        [sg.q.x - nx * w1, sg.q.y - ny * w1], [sg.p.x - nx * w0, sg.p.y - ny * w0]].map((c) => c.join(",")).join(" "));
      ["x1", "y1", "x2", "y2"].forEach((k, j) => part.g.setAttribute(k, [sg.p.x, sg.p.y, sg.q.x, sg.q.y][j]));
      part.s0.setAttribute("stop-opacity", (ly.alpha * fade(sg.s0)).toFixed(3));
      part.s1.setAttribute("stop-opacity", (ly.alpha * fade(sg.s1)).toFixed(3));
    }));
    glows.forEach((c, i) => {
      const sg = segs[i];
      if (!sg || !sg.bounce || !segs[i + 1]) { c.setAttribute("r", "0"); return; }
      c.setAttribute("cx", sg.q.x); c.setAttribute("cy", sg.q.y);
      c.setAttribute("r", (30 + sg.s1 * Math.tan(0.12)).toFixed(1));
      c.setAttribute("opacity", (0.45 * fade(sg.s1)).toFixed(3));
    });
  }

  let on = false, raf = 0, offTimer = 0;
  const loop = () => { draw(); raf = requestAnimationFrame(loop); };
  const reasons = new Set();
  function start(reason) {
    if (!animated(visible())) return;
    reasons.add(reason);
    if (on) return;
    on = true;
    clearTimeout(offTimer);
    logos.forEach((l) => l.classList.add("atl-solto"));
    setRate(3);
    svg.classList.add("on");
    if (!raf) loop();
  }
  function stop(reason) {
    reasons.delete(reason);
    if (!on || reasons.size) return;
    on = false;
    svg.classList.remove("on");
    offTimer = setTimeout(() => {
      cancelAnimationFrame(raf); raf = 0;
      logos.forEach((l) => l.classList.remove("atl-solto"));
      setRate(1);
    }, 450);
  }

  // 1) navegação: a página seguinte a carregar (só se demorar mais de 250 ms) e envio de formulários/ficheiros
  const KEY = "atl-foco";
  const mark = () => { try { sessionStorage.setItem(KEY, String(Date.now())); } catch (e) { /* sem armazenamento */ } };
  let navTimer = 0;
  const leaving = (delay) => {
    clearTimeout(navTimer);
    navTimer = setTimeout(() => { start("nav"); mark(); setTimeout(() => stop("nav"), 45000); }, delay);
  };
  // descargas não mudam de página: o foco não as acompanha
  const isDownload = (url) => /\.(csv|xlsx|pem|crt|cer|zip|json)(\?|$)|\/(csv|excel)(\?|$)|\/ficheiro\/|\/marca\//i.test(url);
  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("a[href]");
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (a.target && a.target !== "_self") return;
    if (a.hasAttribute("download") || a.hasAttribute("data-sem-foco") || a.origin !== location.origin || isDownload(a.pathname)) return;
    if (a.pathname === location.pathname && a.search === location.search && a.hash) return;
    leaving(250);
  });
  document.addEventListener("submit", (e) => {
    const f = e.target;
    if (e.defaultPrevented || f.hasAttribute("data-sem-foco") || (f.target && f.target !== "_self") || isDownload(f.getAttribute("action") || "")) return;
    leaving(f.enctype === "multipart/form-data" ? 0 : 250);       // um ficheiro a enviar: logo
  });
  window.addEventListener("pageshow", (e) => { if (e.persisted) { clearTimeout(navTimer); stop("nav"); } });
  // a página nova chegou: o feixe que vinha da anterior recolhe ao logótipo
  try {
    const t = Number(sessionStorage.getItem(KEY) || 0);
    sessionStorage.removeItem(KEY);
    if (t && Date.now() - t < 60000) { start("chegada"); setTimeout(() => stop("chegada"), 900); }
  } catch (e) { /* sem armazenamento */ }

  // 2) trabalho em curso no servidor: varre até acabar (pergunta a cada 5 s, só com a página visível)
  const note = document.querySelector("[data-ocupado]");
  if (note && note.dataset.ocupado !== "") {
    start("servidor");
    const poll = () => {
      if (document.visibilityState !== "visible") return setTimeout(poll, 5000);
      fetch("/estado/ocupado", { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => {
          if (!d) return setTimeout(poll, 15000);
          if (d.ocupado.length) { note.querySelector("span").textContent = d.ocupado.join(" · "); setTimeout(poll, 5000); }
          else { note.hidden = true; stop("servidor"); }
        })
        .catch(() => setTimeout(poll, 15000));
    };
    setTimeout(poll, 5000);
  }
  window.addEventListener("resize", () => { if (on) draw(); });
});
