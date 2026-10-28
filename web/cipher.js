// Marks the page "proved" while a verified receipt is shown, so the background can respond.
(() => {
  const result = document.getElementById("result");
  if (!result) return;
  new MutationObserver(() => { document.body.dataset.phase = result.querySelector(".stamp.good") ? "proved" : "sealed"; })
    .observe(result, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
})();
