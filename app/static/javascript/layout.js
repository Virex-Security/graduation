/**
 * Unified Layout JavaScript
 * Handles sidebar, navbar, and shared layout functionality
 */

const LayoutManager = {
  sidebar: null,
  mainWrapper: null,
  sidebarToggle: null,
  navbar: null,
  connectionPollId: null,

  init() {
    this.sidebar = document.getElementById("sidebar");

    this.mainWrapper = document.querySelector(".main-wrapper");
    this.sidebarToggle = document.getElementById("sidebarToggle");
    this.navbar = document.querySelector(".navbar");

    if (!this.sidebar) return;

    this.initSidebar();
    this.initNavbar();
    this.initActiveMenuItem();
    this.initResetButton();
    this.initConnectionMonitor();
    this.handleResize();

    window.addEventListener("resize", () => this.handleResize());
  },

  /**
   * Initialize Sidebar Functionality
   */
  initSidebar() {
    // Restore sidebar state from localStorage
    const sidebarCollapsed =
      localStorage.getItem("sidebarCollapsed") === "true";
    if (sidebarCollapsed) {
      this.sidebar.classList.add("collapsed");
    }

    // Sidebar toggle button
    if (this.sidebarToggle) {
      this.sidebarToggle.addEventListener("click", () => this.toggleSidebar());
    }

    // Close sidebar when clicking outside on mobile
    document.addEventListener("click", (e) => {
      if (window.innerWidth <= 768) {
        const isClickInsideSidebar = this.sidebar.contains(e.target);
        const isClickOnToggle =
          this.sidebarToggle && this.sidebarToggle.contains(e.target);

        if (
          !isClickInsideSidebar &&
          !isClickOnToggle &&
          !this.sidebar.classList.contains("collapsed")
        ) {
          this.closeSidebar();
        }
      }
    });
  },

  /**
   * Toggle Sidebar Open/Close
   */
  toggleSidebar() {
    this.sidebar.classList.toggle("collapsed");
    const isCollapsed = this.sidebar.classList.contains("collapsed");
    localStorage.setItem("sidebarCollapsed", isCollapsed);

    // Dispatch custom event for other components
    window.dispatchEvent(
      new CustomEvent("sidebarToggle", {
        detail: { collapsed: isCollapsed },
      }),
    );
  },

  /**
   * Close Sidebar
   */
  closeSidebar() {
    this.sidebar.classList.add("collapsed");
    localStorage.setItem("sidebarCollapsed", "true");
  },

  /**
   * Open Sidebar
   */
  openSidebar() {
    this.sidebar.classList.remove("collapsed");
    localStorage.setItem("sidebarCollapsed", "false");
  },

  /**
   * Initialize Navbar Functionality
   */
  initNavbar() {
    if (!this.navbar) return;

    // Initialize navbar buttons
    this.initProfileButton();
    this.initThemeToggle();
    this.initLogoutButton();
  },

  /**
   * Initialize Profile Button
   */
  initProfileButton() {
    const profileBtn =
      document.getElementById("profile-btn") ||
      document.querySelector(".profile-btn");
    if (profileBtn) {
      profileBtn.addEventListener("click", () => {
        window.location.href = "/profile";
      });
    }
  },

  /**
   * Initialize Theme Toggle
   */
  initThemeToggle() {
    const themeToggle = document.getElementById("theme-toggle");
    if (themeToggle && typeof ThemeManager !== "undefined") {
      // ThemeManager handles the actual toggle, we just ensure the button exists
      console.log("Theme toggle initialized");
    }
  },

  /**
   * Initialize Logout Button
   */
  initLogoutButton() {
    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", (e) => {
        e.preventDefault();
        if (typeof Auth !== "undefined" && Auth.logout) {
          Auth.logout();
        } else {
          // Fallback logout
          fetch("/logout", { method: "POST", credentials: "same-origin" })
            .then(() => (window.location.href = "/login"))
            .catch(() => (window.location.href = "/login"));
        }
      });
    }
  },

  /**
   * Initialize Active Menu Item based on current URL
   */
  initActiveMenuItem() {
    const currentPath = window.location.pathname;
    const menuItems = document.querySelectorAll(
      ".menu-item, .modern-sidebar__item[href]",
    );

    menuItems.forEach((item) => {
      const href = item.getAttribute("href");
      if (href) {
        // Remove active class from all items
        item.classList.remove("active");

        // Add active class to matching item
        if (
          currentPath === href ||
          (href !== "/" && currentPath.startsWith(href + "/"))
        ) {
          item.classList.add("active");
        }

        // Special case for dashboard
        if (currentPath === "/dashboard" && href === "/dashboard") {
          item.classList.add("active");
        }
      }
    });
  },

  /**
   * Initialize Reset Button
   */
  initResetButton() {
    const sidebarResetBtn = document.getElementById("sidebar-reset-btn");
    if (sidebarResetBtn) {
      sidebarResetBtn.addEventListener("click", () => this.handleReset());
    }
  },

  initConnectionMonitor() {
    if (typeof ConnectionService !== "undefined") {
      ConnectionService.subscribe((status, msg) => {
        this.updateConnectionStatus(status, msg);
        this.updateProfileConnectionStatus(status === "connected");
      });
    }
  },


  /**
   * Handle Reset Statistics
   */
  handleReset() {
    this.showResetConfirmModal().then((confirmed) => {
      if (!confirmed) return;

      fetch("/api/dashboard/reset", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
      })
        .then((response) => response.json())
        .then((data) => {
          if (data.status === "stats_reset") {
            this.showResetNoticeModal(
              "Reset Completed",
              "All dashboard statistics were reset successfully.",
            ).then(() => {
              location.reload();
            });
          } else {
            this.showResetNoticeModal(
              "Reset Failed",
              "Unable to reset dashboard statistics.",
            );
          }
        })
        .catch((error) => {
          console.error("Reset error:", error);
          this.showResetNoticeModal(
            "Reset Failed",
            "An error occurred while resetting dashboard statistics.",
          );
        });
    });
  },

  showResetConfirmModal() {
    return new Promise((resolve) => {
      const existing = document.getElementById("reset-confirm-overlay");
      if (existing) {
        existing.remove();
      }

      const overlay = document.createElement("div");
      overlay.id = "reset-confirm-overlay";
      overlay.className = "reset-confirm-overlay";
      overlay.innerHTML = `
        <div class="reset-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="reset-confirm-title">
          <div class="reset-confirm-header">
            <h3 id="reset-confirm-title">Confirm Reset</h3>
          </div>
          <div class="reset-confirm-body">
            Are you sure you want to reset all dashboard statistics? This action cannot be undone.
          </div>
          <div class="reset-confirm-actions">
            <button type="button" class="reset-confirm-btn reset-confirm-cancel">Cancel</button>
            <button type="button" class="reset-confirm-btn reset-confirm-danger">Reset</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      const cancelBtn = overlay.querySelector(".reset-confirm-cancel");
      const confirmBtn = overlay.querySelector(".reset-confirm-danger");
      const close = (result) => {
        overlay.remove();
        resolve(result);
      };

      cancelBtn.addEventListener("click", () => close(false));
      confirmBtn.addEventListener("click", () => close(true));
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) {
          close(false);
        }
      });

      const onEscape = (event) => {
        if (event.key === "Escape") {
          document.removeEventListener("keydown", onEscape);
          close(false);
        }
      };
      document.addEventListener("keydown", onEscape);
    });
  },

  showResetNoticeModal(title, message) {
    return new Promise((resolve) => {
      const existing = document.getElementById("reset-confirm-overlay");
      if (existing) {
        existing.remove();
      }

      const overlay = document.createElement("div");
      overlay.id = "reset-confirm-overlay";
      overlay.className = "reset-confirm-overlay";
      overlay.innerHTML = `
        <div class="reset-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="reset-notice-title">
          <div class="reset-confirm-header">
            <h3 id="reset-notice-title">${title}</h3>
          </div>
          <div class="reset-confirm-body">${message}</div>
          <div class="reset-confirm-actions">
            <button type="button" class="reset-confirm-btn reset-confirm-primary">OK</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      const okBtn = overlay.querySelector(".reset-confirm-primary");
      const close = () => {
        overlay.remove();
        resolve(true);
      };

      okBtn.addEventListener("click", close);
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) {
          close();
        }
      });

      const onEscape = (event) => {
        if (event.key === "Escape") {
          document.removeEventListener("keydown", onEscape);
          close();
        }
      };
      document.addEventListener("keydown", onEscape);
    });
  },

  /**
   * Handle Window Resize
   */
  handleResize() {
    if (window.innerWidth <= 768) {
      // Auto-collapse on mobile
      this.closeSidebar();
    }
  },

  /**
   * Update Connection Status in Sidebar
   */
  updateConnectionStatus(status, message) {
    const statusEl = document.getElementById("sidebar-connection-status");
    if (!statusEl) return;

    // Remove all status classes
    statusEl.classList.remove(
      "status-connected",
      "status-disconnected",
      "status-waiting",
    );

    // Add appropriate class
    if (status === "connected") {
      statusEl.classList.add("status-connected");
      statusEl.innerHTML = '<i class="fas fa-circle"></i> Connected';
    } else if (status === "disconnected") {
      statusEl.classList.add("status-disconnected");
      statusEl.innerHTML = '<i class="fas fa-circle"></i> Disconnected';
    } else if (status === "waiting") {
      statusEl.classList.add("status-waiting");
      statusEl.innerHTML =
        '<i class="fas fa-spinner fa-spin"></i> Wait for API';
    }
  },

  updateProfileConnectionStatus(isOnline) {
    const badge = document.getElementById("profile-api-badge");
    const text = document.getElementById("profile-api-badge-text");
    if (!badge || !text) return;

    badge.classList.toggle("offline", !isOnline);
    text.textContent = isOnline ? "ONLINE" : "OFFLINE";
  },

};


// Initialize on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  LayoutManager.init();
});

// Export for use in other scripts
if (typeof module !== "undefined" && module.exports) {
  module.exports = LayoutManager;
}
