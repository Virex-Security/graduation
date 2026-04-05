/**
 * Access Control & Permissions Manager
 * Handles user role-based visibility and data filtering
 */

const AccessControl = {
  ROLE_ADMIN: "admin",
  ROLE_USER: "user",
  currentUser: null,

  /**
   * Initialize Access Control
   */
  async init() {
    await this.loadUserRole();
    this.applyAccessRules();
    this.setupBackButton();
  },

  /**
   * Load current user role from API
   */
  async loadUserRole() {
    try {
      const response = await fetch("/api/user", {
        credentials: "include",
      });
      if (response.ok) {
        const data = await response.json();
        this.currentUser = data;
        document.body.setAttribute("data-user-role", data.role);
      }
    } catch (error) {
      console.log("Could not load user data");
    }
  },

  /**
   * Check if current user is admin
   */
  isAdmin() {
    return this.currentUser && this.currentUser.role === this.ROLE_ADMIN;
  },

  /**
   * Apply access rules to the page
   */
  applyAccessRules() {
    if (!this.isAdmin()) {
      this.hideAdminOnlyElements();
      this.hideActionButtons();
      this.simplifyIncidentDisplay();
      this.simplifyMLDisplay();
    }
  },

  /**
   * Hide all elements marked with data-admin-only
   */
  hideAdminOnlyElements() {
    const adminElements = document.querySelectorAll("[data-admin-only]");
    adminElements.forEach((el) => {
      el.style.display = "none";
    });
  },

  /**
   * Hide action buttons for non-admin users
   */
  hideActionButtons() {
    const actionButtons = document.querySelectorAll(
      ".btn-action, .action-panel, .action-btns",
    );
    actionButtons.forEach((btn) => {
      btn.style.display = "none";
    });
  },

  /**
   * Mask sensitive data (IP, Payload) for non-admin users
   */
  maskSensitiveData() {
    // Hide IP columns
    const ipCells = document.querySelectorAll("[data-column='ip']");
    ipCells.forEach((cell) => {
      cell.style.display = "none";
    });

    // Hide Payload/Snippet columns
    const payloadCells = document.querySelectorAll("[data-column='payload']");
    payloadCells.forEach((cell) => {
      cell.style.display = "none";
    });

    // Hide Confidence columns
    const confidenceCells = document.querySelectorAll(
      "[data-column='confidence']",
    );
    confidenceCells.forEach((cell) => {
      cell.style.display = "none";
    });

    // Hide Payload Analysis column
    const analysisHeaders = document.querySelectorAll("th:contains('Payload')");
    analysisHeaders.forEach((th) => {
      const index = Array.from(th.parentElement.children).indexOf(th);
      if (index > -1) {
        const rows = document.querySelectorAll("tbody tr");
        rows.forEach((row) => {
          if (row.children[index]) {
            row.children[index].style.display = "none";
          }
        });
      }
    });
  },

  /**
   * Simplify incident details display for users
   */
  simplifyIncidentDisplay() {
    // Hide detailed event logs
    const eventTable = document.querySelector(".details-grid");
    if (eventTable) {
      const eventLogsSection = eventTable.querySelector("table");
      if (eventLogsSection) {
        // Keep the table but mark as simplified
        eventLogsSection.setAttribute("data-simplified", "true");
      }
    }

    // Hide right column (action panel)
    const rightCol = document.querySelector(".right-col");
    if (rightCol) {
      rightCol.style.display = "none";
    }

    // Show simple message instead
    const mainContent = document.querySelector(".main-content");
    if (mainContent) {
      const incidentType =
        document.querySelector("#incident-meta-p")?.textContent;
      const timestamp = document.querySelector(".section-title")?.textContent;

      const simpleMsg = document.createElement("div");
      simpleMsg.style.cssText = `
        background: rgba(168, 85, 247, 0.1);
        border: 1px solid rgba(168, 85, 247, 0.3);
        border-radius: 10px;
        padding: 1.5rem;
        margin: 1.5rem 0;
        color: var(--text-primary);
      `;

      simpleMsg.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
          <i class="fas fa-shield-alt" style="color: var(--brand-primary); font-size: 1.5rem;"></i>
          <h3 style="margin: 0;">تنبيه أمان</h3>
        </div>
        <p style="margin: 0; color: var(--text-secondary);">
          تم اكتشاف مشكلة أمان في النظام. تم إرسال التفاصيل إلى فريق الأمان المتخصص لتحليل الموقف واتخاذ الإجراءات اللازمة.
        </p>
      `;

      const detailsSection = document.querySelector(".details-grid");
      if (detailsSection) {
        detailsSection.parentElement.insertBefore(simpleMsg, detailsSection);
      }
    }
  },

  /**
   * Simplify ML detections display for users
   */
  simplifyMLDisplay() {
    const mlTable = document.querySelector(".data-table");
    if (mlTable && mlTable.getAttribute("data-ml-table")) {
      // Hide technical columns
      const headers = mlTable.querySelectorAll("th");
      headers.forEach((th, index) => {
        const text = th.textContent.toLowerCase();
        if (
          text.includes("confidence") ||
          text.includes("payload") ||
          text.includes("ip")
        ) {
          const cells = mlTable.querySelectorAll(`td:nth-child(${index + 1})`);
          cells.forEach((cell) => {
            cell.style.display = "none";
          });
          th.style.display = "none";
        }
      });

      // Replace table with simple message
      const simpleView = document.createElement("div");
      simpleView.style.cssText = `
        background: rgba(168, 85, 247, 0.1);
        border: 1px solid rgba(168, 85, 247, 0.3);
        border-radius: 10px;
        padding: 2rem;
        margin: 1.5rem 0;
        text-align: center;
        color: var(--text-primary);
      `;
      simpleView.innerHTML = `
        <i class="fas fa-brain" style="font-size: 3rem; color: var(--brand-secondary); margin-bottom: 1rem; display: block;"></i>
        <h2 style="margin-bottom: 0.5rem;">الكشف الذكي عن الهجمات</h2>
        <p style="color: var(--text-secondary); margin: 0;">
          تم اكتشاف عدة محاولات هجوم غير عادية من خلال نظام الذكاء الاصطناعي.
        </p>
        <div style="margin-top: 1.5rem;">
          <span style="
            display: inline-block;
            background: var(--brand-primary);
            color: white;
            padding: 0.5rem 1.5rem;
            border-radius: 8px;
            font-weight: 600;
          ">تم الكشف عن هجوم</span>
        </div>
      `;

      if (mlTable.parentElement) {
        mlTable.parentElement.insertBefore(simpleView, mlTable);
        mlTable.style.display = "none";
      }
    }
  },

  /**
   * Setup smart back button that preserves user role
   */
  setupBackButton() {
    const backButtons = document.querySelectorAll(
      ".logout-btn[onclick*='location.href = \\'/'], button:contains('Back')",
    );

    backButtons.forEach((btn) => {
      if (
        btn.innerHTML.includes("Back") ||
        btn.innerHTML.includes("arrow-left")
      ) {
        btn.addEventListener("click", (e) => {
          e.preventDefault();
          this.goBack();
        });
      }
    });
  },

  /**
   * Navigate back with role preservation
   */
  goBack() {
    const referrer = document.referrer;
    const currentUrl = window.location.href;
    const userRole = this.currentUser?.role || "user";

    // Store current page for role-aware navigation
    sessionStorage.setItem("lastPage", currentUrl);
    sessionStorage.setItem("userRole", userRole);

    if (referrer && referrer.includes(window.location.host)) {
      window.history.back();
    } else {
      // Default navigation based on role
      if (userRole === this.ROLE_ADMIN) {
        window.location.href = "/";
      } else {
        window.location.href = "/";
      }
    }
  },

  /**
   * Check if user can access a specific element
   */
  canAccess(requiredRole) {
    if (!requiredRole) return true;
    if (requiredRole === this.ROLE_ADMIN) {
      return this.isAdmin();
    }
    return true;
  },

  /**
   * Filter data based on user role
   */
  filterDataByRole(data) {
    if (this.isAdmin()) {
      return data;
    }

    // For users, remove sensitive fields
    if (Array.isArray(data)) {
      return data.map((item) => this.filterSingleRecord(item));
    }
    return this.filterSingleRecord(data);
  },

  /**
   * Filter single record to remove sensitive fields for users
   */
  filterSingleRecord(record) {
    if (this.isAdmin()) {
      return record;
    }

    const filtered = { ...record };
    // Remove sensitive fields for non-admin users
    // delete filtered.ip;
    // delete filtered.payload;
    // delete filtered.confidence;
    // delete filtered.snippet;

    // Replace with simplified versions
    if (filtered.ip) {
      filtered.ip = "***.***.***.**";
    }
    if (filtered.payload || filtered.snippet) {
      filtered.payload = "تم إخفاء التفاصيل التقنية";
      filtered.snippet = "تم إخفاء التفاصيل التقنية";
    }

    return filtered;
  },

  /**
   * Show role-based notification
   */
  showNotification(message, type = "info") {
    const container = document.getElementById("notification-container");
    if (!container) return;

    const notification = document.createElement("div");
    notification.className = `toast toast-${type}`;

    // Unify styling with dashboard.css toasts if possible, otherwise keep fallback
    notification.innerHTML = `
      <span style="flex: 1">${message}</span>
      <button class="toast-close" style="background: none; border: none; color: inherit; opacity: 0.6; cursor: pointer; padding: 4px; display: flex; align-items: center; justify-content: center; transition: opacity 0.2s; margin-left: 10px;">
        <i class="fas fa-times"></i>
      </button>
    `;

    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: var(--brand-primary);
      color: white;
      padding: 1rem 1.5rem;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      z-index: 9999;
      display: flex;
      align-items: center;
      animation: slideInRight 0.3s ease;
    `;

    container.appendChild(notification);

    const closeBtn = notification.querySelector('.toast-close');
    closeBtn.addEventListener('mouseover', () => closeBtn.style.opacity = '1');
    closeBtn.addEventListener('mouseout', () => closeBtn.style.opacity = '0.6');
    closeBtn.addEventListener('click', () => {
      notification.style.animation = "slideUp 0.4s ease-in forwards";
      setTimeout(() => notification.remove(), 400);
    });

    setTimeout(() => {
      if (notification.parentElement) {
        notification.style.animation = "slideUp 0.4s ease-in forwards";
        setTimeout(() => notification.remove(), 400);
      }
    }, 5000);
  },
};

// Initialize on page load
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => AccessControl.init());
} else {
  AccessControl.init();
}
