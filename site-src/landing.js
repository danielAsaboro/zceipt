const nav = document.getElementById("nav");
const onScroll = () => {
  nav.classList.toggle("scrolled", scrollY > 8);
  document.body.classList.toggle("top-of-story", scrollY < innerHeight * 0.3);
};
addEventListener("scroll", onScroll, { passive: true }); onScroll();

const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.12 });
document.querySelectorAll(".reveal").forEach((el) => io.observe(el));

const story = document.getElementById("story");
document.querySelectorAll(".story-dots button").forEach((b) => b.addEventListener("click", () => {
  const top = story.getBoundingClientRect().top + scrollY;
  scrollTo({ top: top + (story.offsetHeight - innerHeight) * Number(b.dataset.go), behavior: "smooth" });
}));

document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.setAttribute("aria-selected", x === b));
  document.querySelectorAll(".code pre").forEach((p) => (p.hidden = p.dataset.p !== b.dataset.t));
}));

// disclosure builder: recipient and amount always shown, balance and history never
const paper = document.getElementById("paper"), meter = document.getElementById("meter"), meterText = document.getElementById("meterText");
const ALL = paper.querySelectorAll(".rv").length;
function paint() {
  document.querySelectorAll("#toggles input").forEach((i) => paper.querySelector(`[data-r="${i.dataset.f}"]`).classList.toggle("on", i.checked));
  const shown = paper.querySelectorAll(".rv.on").length;
  meter.innerHTML = Array.from({ length: ALL }, (_, i) => `<i class="${i < shown ? "on" : ""}"></i>`).join("");
  meterText.textContent = `${shown} of ${ALL} shown`;
}
document.querySelectorAll("#toggles input").forEach((i) => i.addEventListener("change", paint));
paint();
