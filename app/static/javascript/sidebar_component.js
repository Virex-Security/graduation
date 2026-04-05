function setSidebarExpandedState(sidebar, expanded) {
  sidebar.classList.toggle("collapsed", !expanded);
  sidebar.setAttribute("aria-expanded", String(expanded));
  localStorage.setItem("sidebarCollapsed", String(!expanded));

  const toggles = document.querySelectorAll(
    `[data-sidebar-target="${sidebar.id}"]`,
  );
  toggles.forEach((toggle) => {
    toggle.setAttribute("aria-expanded", String(expanded));
  });
}

function initSidebarComponent(root = document) {
  const sidebars = root.querySelectorAll(".modern-sidebar");
  sidebars.forEach((sidebar) => {
    const collapsed = localStorage.getItem("sidebarCollapsed") === "true";
    setSidebarExpandedState(sidebar, !collapsed);
  });

  const toggles = root.querySelectorAll("[data-sidebar-toggle]");

  toggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
      const targetId = toggle.getAttribute("data-sidebar-target");
      const sidebar = document.getElementById(targetId);
      if (!sidebar) return;

      const expanded = sidebar.classList.contains("collapsed");
      setSidebarExpandedState(sidebar, expanded);
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initSidebarComponent();
});
