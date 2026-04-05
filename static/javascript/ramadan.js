// ==================== RAMADAN SEASONAL TOGGLE ====================
// Set to false after Ramadan to hide all decorations instantly.
const isRamadan = true;

document.addEventListener("DOMContentLoaded", function () {
  const el = document.getElementById("ramadan-mode");
  if (!el) return;
  if (!isRamadan) {
    el.classList.add("hidden");
  }
});
