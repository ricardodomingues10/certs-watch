// certwatch — melhorias opcionais (a aplicação funciona sem JavaScript).
document.addEventListener("DOMContentLoaded", () => {
  // "Selecionar todos" numa tabela com checkboxes name="cn"
  document.querySelectorAll("input[data-check-all]").forEach((all) => {
    const form = all.closest("form");
    const boxes = () => Array.from(form.querySelectorAll('input[type=checkbox][name="cn"]'));
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
});
