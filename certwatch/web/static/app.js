// Atalaia Cert — melhorias opcionais (a aplicação funciona sem JavaScript).
document.documentElement.classList.add("js");
document.addEventListener("DOMContentLoaded", () => {
  // Escolher um ficheiro já o envia (o botão "Carregar" só aparece sem JavaScript); arrastar realça a zona
  document.querySelectorAll("input[type=file][data-autosubmit]").forEach((inp) => {
    inp.addEventListener("change", () => { if (inp.files && inp.files.length) inp.form.requestSubmit ? inp.form.requestSubmit() : inp.form.submit(); });
    const zone = inp.closest(".rc-drop");
    if (zone) {
      ["dragenter", "dragover"].forEach((ev) => inp.addEventListener(ev, () => zone.classList.add("is-over")));
      ["dragleave", "drop"].forEach((ev) => inp.addEventListener(ev, () => zone.classList.remove("is-over")));
    }
  });

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
  // Campos só de leitura para copiar (ex.: o link de um convite): selecionar tudo ao clicar
  document.querySelectorAll("input[data-select-all]").forEach((inp) => inp.addEventListener("focus", () => inp.select()));
  // Botões que pedem confirmação antes de enviar (ex.: aplicar na UCMDB)
  document.querySelectorAll("button[data-confirm]").forEach((b) => b.addEventListener("click", (e) => {
    if (!window.confirm(b.dataset.confirm)) e.preventDefault();
  }));
});

// Trabalho em curso no servidor: a barra de cima diz o quê; atualiza a cada 5 s (só com a página visível) e
// desaparece quando acaba.
document.addEventListener("DOMContentLoaded", () => {
  const note = document.querySelector("[data-ocupado]");
  if (!note) return;
  const poll = () => {
    if (document.visibilityState !== "visible") return setTimeout(poll, 5000);
    fetch("/estado/ocupado", { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!d) return setTimeout(poll, 15000);
        if (d.ocupado.length) { note.querySelector("span").textContent = d.ocupado.join(" · "); setTimeout(poll, 5000); }
        else note.hidden = true;
      })
      .catch(() => setTimeout(poll, 15000));
  };
  setTimeout(poll, 5000);
});

// Painel: organizar os cartões. Em "Organizar o painel" cada cartão ganha uma pega (arrastar para mudar de sítio, ou
// setas do teclado), botões de largura e um canto para puxar a largura e a altura (duplo clique no canto: altura do
// conteúdo). A disposição fica guardada para cada pessoa (POST /painel/disposicao); "Repor" volta à de origem.
document.addEventListener("DOMContentLoaded", () => {
  const grid = document.querySelector("[data-pn-grid]");
  const bar = document.querySelector("[data-pn-arrange]");
  if (!grid || !bar || !window.fetch) return;
  bar.hidden = false;
  const toggle = bar.querySelector("[data-pn-toggle]");
  const reset = bar.querySelector("[data-pn-reset]");
  const hint = bar.querySelector("[data-pn-hint]");
  const STEP = 40, MINH = 4, MAXH = 30;
  const cells = () => Array.from(grid.children).filter((c) => c.classList.contains("pn-cell"));
  let editing = false, timer = 0;

  const send = (body) => fetch("/painel/disposicao", {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": grid.dataset.csrf || "" },
    body: JSON.stringify(body),
  });
  const persist = () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const w = {}, h = {};
      cells().forEach((c) => { w[c.dataset.card] = +c.dataset.w; h[c.dataset.card] = +c.dataset.h; });
      send({ order: cells().map((c) => c.dataset.card), w, h });
    }, 350);
  };
  const label = (c) => {
    const s = c.querySelector(".pn-size");
    if (s) s.textContent = c.dataset.w + "/12" + (+c.dataset.h ? " · " + (+c.dataset.h * STEP) + " px" : "");
    const auto = c.querySelector("[data-auto]");
    if (auto) auto.hidden = !+c.dataset.h;
  };
  const setW = (c, w) => {
    w = Math.max(3, Math.min(12, Math.round(w)));
    if (w === +c.dataset.w) return false;
    c.classList.remove("w-" + c.dataset.w); c.dataset.w = w; c.classList.add("w-" + w); label(c);
    return true;
  };
  const setH = (c, h) => {
    h = h ? Math.max(MINH, Math.min(MAXH, Math.round(h))) : 0;
    if (h === +c.dataset.h) return false;
    c.classList.remove("h-" + c.dataset.h); c.dataset.h = h; c.classList.add("h-" + h); label(c);
    return true;
  };
  const btn = (text, aria, cls) => {
    const b = document.createElement("button");
    b.type = "button"; b.textContent = text; b.setAttribute("aria-label", aria);
    if (cls) b.className = cls;
    return b;
  };

  cells().forEach((c) => {
    const name = c.dataset.label || c.dataset.card;
    const tools = document.createElement("div");
    tools.className = "pn-tools";
    const grip = btn("⠿", `Mudar ${name} de sítio (arrastar, ou setas do teclado)`, "pn-grip");
    const less = btn("−", `${name}: mais estreito`);
    const size = document.createElement("span"); size.className = "pn-size";
    const more = btn("+", `${name}: mais largo`);
    const auto = btn("Auto", `${name}: altura do conteúdo`); auto.dataset.auto = "1";
    tools.append(grip, less, size, more, auto);
    const corner = document.createElement("span");
    corner.className = "pn-resize"; corner.title = "Puxar para mudar o tamanho; duplo clique: altura do conteúdo";
    c.append(tools, corner);
    label(c);

    less.addEventListener("click", () => { if (setW(c, +c.dataset.w - 1)) persist(); });
    more.addEventListener("click", () => { if (setW(c, +c.dataset.w + 1)) persist(); });
    auto.addEventListener("click", () => { if (setH(c, 0)) persist(); });

    // mudar de sítio com as setas
    grip.addEventListener("keydown", (e) => {
      const back = e.key === "ArrowLeft" || e.key === "ArrowUp", fwd = e.key === "ArrowRight" || e.key === "ArrowDown";
      if (!back && !fwd) return;
      e.preventDefault();
      const sib = back ? c.previousElementSibling : c.nextElementSibling;
      if (!sib) return;
      grid.insertBefore(c, back ? sib : sib.nextElementSibling);
      grip.focus(); persist();
    });
    // mudar de sítio a arrastar: o cartão vai para antes ou depois daquele que está debaixo do ponteiro
    grip.addEventListener("pointerdown", (e) => {
      if (!editing || e.button !== 0) return;
      e.preventDefault();
      c.classList.add("is-moving");          // segue-se o ponteiro na janela: mudar o cartão de sítio no DOM larga a captura
      let lastX = e.clientX, lastY = e.clientY;
      const move = (ev) => {
        if (Math.abs(ev.clientX - lastX) + Math.abs(ev.clientY - lastY) < 6) return;
        const t = cells().find((o) => {
          if (o === c) return false;
          const r = o.getBoundingClientRect();
          return ev.clientX >= r.left && ev.clientX <= r.right && ev.clientY >= r.top && ev.clientY <= r.bottom;
        });
        if (!t) return;
        const r = t.getBoundingClientRect();
        const after = ev.clientX > r.left + r.width / 2;
        const ref = after ? t.nextElementSibling : t;
        if (ref !== c && ref !== c.nextElementSibling) {                   // senão já está nesse sítio
          grid.insertBefore(c, ref);
          lastX = ev.clientX; lastY = ev.clientY;
        }
      };
      const up = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
        window.removeEventListener("pointercancel", up);
        c.classList.remove("is-moving");
        persist();
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
      window.addEventListener("pointercancel", up);
    });
    // mudar o tamanho a puxar o canto: a largura encaixa nas 12 colunas, a altura em passos de 40 px
    corner.addEventListener("pointerdown", (e) => {
      if (!editing || e.button !== 0) return;
      e.preventDefault();
      c.classList.add("is-resizing");
      const r0 = c.getBoundingClientRect(), x0 = e.clientX, y0 = e.clientY;
      const gap = parseFloat(getComputedStyle(grid).columnGap) || 16;
      const col = (grid.clientWidth - 11 * gap) / 12;
      let changed = false;
      const move = (ev) => {
        const w = (r0.width + (ev.clientX - x0) + gap) / (col + gap);
        changed = setW(c, w) || changed;
        if (Math.abs(ev.clientY - y0) > 8) changed = setH(c, (r0.height + (ev.clientY - y0)) / STEP) || changed;
      };
      const up = () => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerup", up);
        window.removeEventListener("pointercancel", up);
        c.classList.remove("is-resizing");
        if (changed) persist();
      };
      window.addEventListener("pointermove", move);
      window.addEventListener("pointerup", up);
      window.addEventListener("pointercancel", up);
    });
    corner.addEventListener("dblclick", () => { if (setH(c, 0)) persist(); });
  });

  toggle.addEventListener("click", () => {
    editing = !editing;
    grid.classList.toggle("is-editing", editing);
    toggle.setAttribute("aria-pressed", String(editing));
    toggle.textContent = editing ? "Concluído" : "Organizar o painel";
    hint.hidden = reset.hidden = !editing;
  });
  reset.addEventListener("click", () => {
    if (!window.confirm("Voltar à disposição de origem dos cartões?")) return;
    send({ reset: true }).then(() => location.reload());
  });
});

// Avisos por cima da página (ex.: "não tem permissões"): fecham no × ou sozinhos ao fim de 10 s. Numa conta só de
// consulta, carregar num botão que altera algo mostra logo o aviso, sem sair da página (o servidor recusa na mesma).
window.atalaiaToast = (msg) => {
  const box = document.querySelector("[data-toasts]");
  if (!box) return;
  const t = document.createElement("div");
  t.className = "toast"; t.setAttribute("role", "alert");
  const span = document.createElement("span"); span.textContent = msg;
  const x = document.createElement("button"); x.type = "button"; x.className = "toast-x"; x.setAttribute("aria-label", "Fechar o aviso"); x.textContent = "×";
  t.append(span, x); box.append(t);
  armToast(t);
};
function armToast(t) {
  const close = () => { t.classList.add("is-out"); setTimeout(() => t.remove(), 250); };
  const x = t.querySelector(".toast-x");
  if (x) x.addEventListener("click", close);
  let timer = setTimeout(close, 10000);
  t.addEventListener("mouseenter", () => clearTimeout(timer));
  t.addEventListener("mouseleave", () => { timer = setTimeout(close, 4000); });
}
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-toasts] .toast").forEach(armToast);
  const body = document.body;
  if (body.dataset.role !== "leitura") return;
  const ALLOWED = ["/tema", "/painel/disposicao", "/conta/palavra-passe", "/sair"];
  document.addEventListener("submit", (e) => {
    const f = e.target;
    if ((f.getAttribute("method") || "get").toLowerCase() !== "post") return;
    const path = new URL(f.action, location.href).pathname;
    if (ALLOWED.includes(path)) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const b = e.submitter || f.querySelector("button");
    const what = (b && b.textContent.trim()) || "esta ação";
    window.atalaiaToast(`O utilizador ${body.dataset.user} não tem permissões para «${what}»: a conta é de ${body.dataset.roleLabel || "só consulta"}. ` +
                        "Peça a um administrador para mudar o papel em Sistema → Utilizadores.");
  }, true);
});

// Utilizadores: ao escolher outro papel, o botão Guardar dessa linha fica destacado (ainda não foi guardado)
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form.us-role select[name=papel]").forEach((sel) => {
    const start = sel.value, btn = sel.form.querySelector("button");
    if (!btn || !start) return;
    sel.addEventListener("change", () => {
      const changed = sel.value !== start;
      btn.classList.toggle("primary", changed);
      btn.textContent = changed ? "Guardar o papel" : "Guardar";
    });
  });
});
