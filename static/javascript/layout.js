document.addEventListener("DOMContentLoaded", function () {
  const sidebar = document.getElementById("sidebar");
  const mainWrapper = document.getElementById("mainWrapper");
  const sidebarToggle = document.getElementById("sidebarToggle");

  if (!sidebar || !mainWrapper) return;

  const sidebarCollapsed = localStorage.getItem("sidebarCollapsed") === "true";

  if (sidebarCollapsed) {
    sidebar.classList.add("collapsed");
    mainWrapper.classList.add("sidebar-collapsed");
  }

  if (sidebarToggle) {
    sidebarToggle.addEventListener("click", function () {
      sidebar.classList.toggle("collapsed");
      mainWrapper.classList.toggle("sidebar-collapsed");

      const isCollapsed = sidebar.classList.contains("collapsed");
      localStorage.setItem("sidebarCollapsed", isCollapsed);
    });
  }

  function handleResize() {
    if (window.innerWidth <= 768) {
      sidebar.classList.add("collapsed");
      mainWrapper.classList.add("sidebar-collapsed");
    }
  }

  handleResize();
  window.addEventListener("resize", handleResize);

  const sidebarResetBtn = document.getElementById("sidebar-reset-btn");
  if (sidebarResetBtn) {
    sidebarResetBtn.addEventListener("click", function () {
      if (
        confirm(
          "Are you sure you want to reset all statistics? This action cannot be undone."
        )
      ) {
        fetch("/api/dashboard/reset", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
        })
          .then((response) => response.json())
          .then((data) => {
            if (data.status === "stats_reset") {
              alert("Statistics reset successfully!");
              location.reload();
            } else {
              alert("Reset failed");
            }
          })
          .catch((error) => {
            console.error("Reset error:", error);
            alert("Failed to reset statistics");
          });
      }
    });
  }
});