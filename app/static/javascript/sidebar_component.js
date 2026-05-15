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

// Check API connection status
async function checkAPIConnection() {
  const statusElement = document.getElementById("sidebar-connection-status");
  if (!statusElement) return;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    
    const response = await fetch("/api/health", {
      method: "GET",
      headers: { "Accept": "application/json" },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);

    if (response.ok) {
      statusElement.classList.remove("status-disconnected", "status-waiting");
      statusElement.classList.add("status-connected");
      statusElement.innerHTML = '<span class="status-dot"></span> Connected';
    } else {
      throw new Error("API not responding");
    }
  } catch (error) {
    statusElement.classList.remove("status-connected", "status-waiting");
    statusElement.classList.add("status-disconnected");
    statusElement.innerHTML = '<span class="status-dot"></span> Disconnected';
  }
}

// Check connection every 10 seconds
function startConnectionMonitoring() {
  checkAPIConnection(); // Initial check
  setInterval(checkAPIConnection, 10000); // Check every 10 seconds
}

document.addEventListener("DOMContentLoaded", () => {
  initSidebarComponent();
  startConnectionMonitoring();
});
