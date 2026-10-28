// receipt lines to look at through the glass
const lines = ["KEMI'S COFFEE", "<b>0.01 TAZ</b>", "Invoice 42: two coffees", "utest14te2vs…0zndfa", "<s>c7f1 9ae0 4b2d</s>", "RENT <i>−4.20</i>", "CLINIC <i>−1.35</i>", "<s>81f3 0e6a 5c92</s>", "block 4,500,997", "<b>PROVEN BY THE PAYER</b>", "SALARY +12.50", "<s>d4b7 2a08 e76a</s>"];
document.getElementById("print").innerHTML = Array.from({ length: 96 }, (_, i) => lines[(i * 7) % lines.length]).join("<br>");
const lens = document.getElementById("lens"), stage = document.getElementById("stage");
let drag = null;
lens.addEventListener("pointerdown", (e) => { drag = { x: e.clientX - lens.offsetLeft, y: e.clientY - lens.offsetTop }; lens.setPointerCapture(e.pointerId); });
lens.addEventListener("pointermove", (e) => {
  if (!drag) return;
  const r = stage.getBoundingClientRect();
  lens.style.left = Math.max(-100, Math.min(r.width + 100, e.clientX - drag.x)) + "px";
  lens.style.top = Math.max(-60, Math.min(r.height + 60, e.clientY - drag.y)) + "px";
});
lens.addEventListener("pointerup", () => { drag = null; });
