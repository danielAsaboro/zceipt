const r = document.getElementById("r"), s = document.getElementById("status");
r.addEventListener("receipt-verified", (e) => { s.textContent = "Paid ✓ " + (e.detail.paidToExpected / 1e8) + " ZEC received"; s.style.color = "#1d6b45"; });
r.addEventListener("receipt-invalid", (e) => { s.textContent = "Not paid: " + e.detail.error; s.style.color = "#a3271f"; });
