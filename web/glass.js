// Liquid glass: elements marked data-lens bend what is behind them at their rounded edges, like
// a thick lens, then blur and saturate it. The bend is an SVG displacement map made for each
// element's size. Chromium can apply an SVG filter to the backdrop; other browsers keep the
// plain blur from zceipt.css.
(() => {
  if (!window.chrome || !CSS.supports("backdrop-filter", "url(#a)")) return;
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("aria-hidden", "true");
  svg.style.cssText = "position:absolute;width:0;height:0;overflow:hidden";
  document.body.appendChild(svg);
  let n = 0;

  // Red and green carry the x and y push (128 = none). Inside the rim the push points inward
  // and grows toward the edge, so the backdrop looks pulled around the curve.
  function map(w, h, r, rim) {
    const k = 0.5, cw = Math.max(2, Math.round(w * k)), ch = Math.max(2, Math.round(h * k));
    const c = document.createElement("canvas"); c.width = cw; c.height = ch;
    const g = c.getContext("2d"), img = g.createImageData(cw, ch), d = img.data;
    for (let y = 0; y < ch; y++) for (let x = 0; x < cw; x++) {
      const px = x / k, py = y / k;
      // signed distance to the rounded rectangle's edge, and the inward direction
      const qx = Math.max(Math.abs(px - w / 2) - (w / 2 - r), 0), qy = Math.max(Math.abs(py - h / 2) - (h / 2 - r), 0);
      const inner = Math.min(w / 2 - Math.abs(px - w / 2), h / 2 - Math.abs(py - h / 2));
      const dist = qx > 0 || qy > 0 ? r - Math.hypot(qx, qy) : r + inner - r;
      let dx = 0, dy = 0;
      if (dist < rim) {
        const t = Math.pow(1 - Math.max(0, dist) / rim, 2);
        let nx = qx > 0 ? -Math.sign(px - w / 2) * qx : 0, ny = qy > 0 ? -Math.sign(py - h / 2) * qy : 0;
        if (!nx && !ny) { if (w / 2 - Math.abs(px - w / 2) < h / 2 - Math.abs(py - h / 2)) nx = -Math.sign(px - w / 2); else ny = -Math.sign(py - h / 2); }
        const l = Math.hypot(nx, ny) || 1;
        dx = (nx / l) * t; dy = (ny / l) * t;
      }
      const i = (y * cw + x) * 4;
      d[i] = 128 + dx * 127; d[i + 1] = 128 + dy * 127; d[i + 2] = 128; d[i + 3] = 255;
    }
    g.putImageData(img, 0, 0);
    return c.toDataURL();
  }

  function lens(el) {
    const id = el.dataset.lensId || (el.dataset.lensId = `zlens${n++}`);
    const { width: w, height: h } = el.getBoundingClientRect();
    if (w < 4 || h < 4) return;
    const r = Math.min(parseFloat(getComputedStyle(el).borderTopLeftRadius) || 0, h / 2, w / 2);
    const rim = Math.min(Number(el.dataset.lens) || 18, h / 2);
    let f = svg.querySelector(`#${id}`);
    if (!f) {
      f = document.createElementNS(NS, "filter");
      f.id = id; f.setAttribute("color-interpolation-filters", "sRGB");
      f.setAttribute("x", "0"); f.setAttribute("y", "0"); f.setAttribute("width", "100%"); f.setAttribute("height", "100%");
      f.innerHTML = `<feImage x="0" y="0" preserveAspectRatio="none" result="m"/><feDisplacementMap in="SourceGraphic" in2="m" xChannelSelector="R" yChannelSelector="G"/>`;
      svg.appendChild(f);
    }
    const im = f.querySelector("feImage");
    im.setAttribute("href", map(w, h, r, rim));
    im.setAttribute("width", w); im.setAttribute("height", h);
    f.querySelector("feDisplacementMap").setAttribute("scale", String(Math.round(rim * 1.6)));
    const blur = el.dataset.lensBlur || "12";
    el.style.backdropFilter = `url(#${id}) blur(${blur}px) saturate(1.8) brightness(1.04)`;
  }

  const ro = new ResizeObserver((es) => es.forEach((e) => lens(e.target)));
  const watch = () => document.querySelectorAll("[data-lens]").forEach((el) => { if (!el.dataset.lensId) ro.observe(el); });
  watch();
  new MutationObserver(watch).observe(document.body, { childList: true, subtree: true });
  document.documentElement.classList.add("lens");
})();
