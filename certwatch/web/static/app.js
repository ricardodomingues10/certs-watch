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
  });
});
