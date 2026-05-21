function setSidebarExpandedState(sidebar, expanded) {
  sidebar.classList.toggle("collapsed", !expanded);
  sidebar.setAttribute("aria-expanded", String(expanded));
  localStorage.setItem("sidebarCollapsed", String(!expanded));
  
  // Update body class for components that need to respond to sidebar state
  document.body.classList.toggle("is-sidebar-collapsed", !expanded);

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

function checkAPIConnection() {
  const statusElement = document.querySelector('.modern-sidebar__status-text');
  if (!statusElement) return;
  
  // Set initial state to "Checking..."
  statusElement.textContent = 'Checking...';
  statusElement.className = 'modern-sidebar__status-text status-waiting';
  
  // Create AbortController for timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);
  
  fetch('/api/health', { 
    signal: controller.signal,
    method: 'GET',
    headers: { 'Accept': 'application/json' }
  })
    .then(response => {
      clearTimeout(timeoutId);
      if (response.ok) {
        statusElement.textContent = 'Connected';
        statusElement.className = 'modern-sidebar__status-text status-connected';
      } else {
        statusElement.textContent = 'Disconnected';
        statusElement.className = 'modern-sidebar__status-text status-disconnected';
      }
    })
    .catch(error => {
      clearTimeout(timeoutId);
      statusElement.textContent = 'Disconnected';
      statusElement.className = 'modern-sidebar__status-text status-disconnected';
    });
}

document.addEventListener("DOMContentLoaded", () => {
  initSidebarComponent();
  
  // Check API connection on load
  checkAPIConnection();
  
  // Check API connection every 10 seconds
  setInterval(checkAPIConnection, 10000);
});
