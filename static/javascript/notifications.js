/**
 * Professional Notification System - Virex
 * Production-ready dropdown alert system for cybersecurity SaaS dashboard
 *
 * Features:
 * - Bell icon in navbar with red badge counter
 * - Dropdown panel anchored to bell
 * - Non-intrusive dropdown behavior
 * - Critical alert pulse animation
 * - Scroll support for multiple alerts
 * - Color-coded notification items
 * - Close on outside click / ESC / bell click
 */

const SecurityAlerts = {
  bellContainer: null,
  bellIcon: null,
  badge: null,
  dropdown: null,
  alertsList: null,
  activeAlerts: [],
  alertTimers: new Map(),
  unreadCount: 0,
  dropdownOpen: false,

  // Color mapping by attack type
  colorMap: {
    "SQL Injection": {
      indicator: "#F59E0B",
      bg: "#FEFCE8",
      text: "#78350F",
    },
    XSS: {
      indicator: "#F59E0B",
      bg: "#FEF3C7",
      text: "#78350F",
    },
    "ML Detection": {
      indicator: "#A855F7",
      bg: "#F3E8FF",
      text: "#581C87",
    },
    "Brute Force": {
      indicator: "#EF4444",
      bg: "#FEE2E2",
      text: "#7F1D1D",
    },
    "Rate Limit": {
      indicator: "#800000",
      bg: "#FEE2E2",
      text: "#5A0000",
    },
    "Access Violation": {
      indicator: "#3B82F6",
      bg: "#DBEAFE",
      text: "#0C2340",
    },
    Scanner: {
      indicator: "#6B7280",
      bg: "#F3F4F6",
      text: "#1F2937",
    },
    default: {
      indicator: "#9CA3AF",
      bg: "#F9FAFB",
      text: "#374151",
    },
  },

  /**
   * Initialize notification system
   */
  init() {
    // Use existing bell from navbar instead of creating new one
    this.bellIcon = document.getElementById("notification-bell");
    this.badge = document.getElementById("notification-count");

    if (this.bellIcon) {
      this.bellContainer = this.bellIcon.parentElement;
      this.createDropdown();
      this.attachEventListeners();
      this.connect();
      this.createNotificationSound();
    } else {
      // Fallback: create bell if not found
      this.createBellIcon();
      const waitForBell = () => {
        if (this.bellIcon) {
          this.createDropdown();
          this.attachEventListeners();
          this.connect();
          this.createNotificationSound();
        } else {
          setTimeout(waitForBell, 100);
        }
      };
      waitForBell();
    }
  },

  /**
   * Create notification sound
   */
  createNotificationSound() {
    // Create audio context for notification sound
    this.audioContext = new (
      window.AudioContext || window.webkitAudioContext
    )();
  },

  /**
   * Play notification sound
   */
  playNotificationSound() {
    if (!this.audioContext) return;

    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();

      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);

      // Bell-like sound: two tones
      oscillator.frequency.setValueAtTime(800, this.audioContext.currentTime);
      oscillator.frequency.setValueAtTime(
        600,
        this.audioContext.currentTime + 0.1,
      );

      gainNode.gain.setValueAtTime(0.3, this.audioContext.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(
        0.01,
        this.audioContext.currentTime + 0.3,
      );

      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + 0.3);
    } catch (e) {
      console.warn("[Alerts] Could not play notification sound:", e);
    }
  },

  /**
   * Create bell icon in navbar
   */
  createBellIcon() {
    // Wait for navbar to be ready
    const checkNavbar = () => {
      const navbar =
        document.querySelector(".navbar") ||
        document.querySelector("nav") ||
        document.querySelector("header");
      if (!navbar) {
        setTimeout(checkNavbar, 100);
        return;
      }

      // Create bell container
      this.bellContainer = document.createElement("div");
      this.bellContainer.id = "notification-bell-container";
      this.bellContainer.style.cssText = `
        position: relative;
        display: flex;
        align-items: center;
        margin-right: 8px;
      `;

      // Create bell button
      this.bellIcon = document.createElement("button");
      this.bellIcon.id = "notification-bell";
      this.bellIcon.style.cssText = `
        width: 40px;
        height: 40px;
        border-radius: 50%;
        border: none;
        background: transparent;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 20px;
        transition: all 0.2s ease;
        position: relative;
      `;
      this.bellIcon.innerHTML = "🔔";

      // Create badge
      this.badge = document.createElement("div");
      this.badge.id = "notification-badge";
      this.badge.style.cssText = `
        position: absolute;
        top: -8px;
        right: -8px;
        background: #EF4444;
        color: white;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        display: none;
        align-items: center;
        justify-content: center;
        font-size: 11px;
        font-weight: 700;
        border: 2px solid white;
      `;
      this.badge.textContent = "0";

      this.bellIcon.appendChild(this.badge);
      this.bellContainer.appendChild(this.bellIcon);

      // Insert before logout button inside nav-actions
      const navActions = navbar.querySelector(".nav-actions");
      if (navActions) {
        // Find logout button and insert before it
        const logoutBtn = navActions.querySelector(".logout-btn");
        if (logoutBtn) {
          navActions.insertBefore(this.bellContainer, logoutBtn);
        } else {
          navActions.appendChild(this.bellContainer);
        }
      } else {
        navbar.appendChild(this.bellContainer);
      }
    };

    checkNavbar();
  },

  /**
   * Create dropdown panel
   */
  createDropdown() {
    this.dropdown = document.createElement("div");
    this.dropdown.id = "notification-dropdown";
    this.dropdown.style.cssText = `
      position: absolute;
      top: 50px;
      right: 0;
      width: 380px;
      max-height: 500px;
      background: var(--bg-layout);
      border: 1px solid var(--border-dim);
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3), 0 0 20px rgba(168, 85, 247, 0.2);
      z-index: 10000;
      display: none;
      flex-direction: column;
      animation: dropdownSlideIn 0.2s ease-out;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      backdrop-filter: blur(12px);
    `;

    // Header
    const header = document.createElement("div");
    header.style.cssText = `
      padding: 14px 16px;
      border-bottom: 1px solid var(--border-dim);
      background: rgba(168, 85, 247, 0.08);
      border-radius: 8px 8px 0 0;
      display: flex;
      align-items: center;
      justify-content: space-between;
    `;

    const title = document.createElement("div");
    title.style.cssText = `
      font-size: 13px;
      font-weight: 700;
      color: var(--brand-primary);
    `;
    title.textContent = "Security Alerts";

    header.appendChild(title);

    // Close button for dropdown
    const closeBtn = document.createElement("button");
    closeBtn.className = "close-chat";
    closeBtn.innerHTML = "&times;";
    closeBtn.title = "Close Notifications";
    closeBtn.style.fontSize = "26px"; // Match chatbot
    closeBtn.addEventListener("click", () => this.closeDropdown());
    header.appendChild(closeBtn);
    // Alerts list (scrollable)
    this.alertsList = document.createElement("div");
    this.alertsList.id = "notification-alerts-list";
    this.alertsList.style.cssText = `
      flex: 1;
      overflow-y: auto;
      padding: 8px 0;
      display: flex;
      flex-direction: column;
      max-height: 436px;
    `;

    // Empty state
    const emptyState = document.createElement("div");
    emptyState.id = "empty-state";
    emptyState.style.cssText = `
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 200px;
      gap: 8px;
      color: var(--text-secondary);
      opacity: 0.6;
      font-size: 12px;
    `;
    emptyState.innerHTML = `
      <div style="font-size: 32px;"></div>
      <div>No recent alerts</div>
    `;
    this.alertsList.appendChild(emptyState);

    this.dropdown.appendChild(header);
    this.dropdown.appendChild(this.alertsList);

    // Position relative to bell container
    if (this.bellContainer) {
      this.bellContainer.appendChild(this.dropdown);
    } else {
      document.body.appendChild(this.dropdown);
    }
  },

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    if (!this.bellIcon) {
      setTimeout(() => this.attachEventListeners(), 100);
      return;
    }

    // Bell click
    this.bellIcon.addEventListener("click", (e) => {
      e.stopPropagation();
      this.toggleDropdown();
    });

    // Outside click
    document.addEventListener("click", (e) => {
      if (
        this.dropdown &&
        !this.dropdown.contains(e.target) &&
        !this.bellIcon.contains(e.target)
      ) {
        this.closeDropdown();
      }
    });

    // ESC key
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        this.closeDropdown();
      }
    });
  },

  /**
   * Toggle dropdown visibility
   */
  toggleDropdown() {
    if (this.dropdownOpen) {
      this.closeDropdown();
    } else {
      this.openDropdown();
    }
  },

  /**
   * Open dropdown
   */
  openDropdown() {
    if (!this.dropdown) return;
    this.dropdown.style.display = "flex";
    this.dropdownOpen = true;
  },

  /**
   * Close dropdown
   */
  closeDropdown() {
    if (!this.dropdown) return;
    this.dropdown.style.display = "none";
    this.dropdownOpen = false;
  },

  /**
   * Update badge count
   */
  updateBadge() {
    if (!this.badge) return;
    if (this.unreadCount > 0) {
      this.badge.style.display = "flex";
      this.badge.textContent = this.unreadCount > 9 ? "9+" : this.unreadCount;
    } else {
      this.badge.style.display = "none";
    }
  },

  /**
   * Pulse animation for critical alerts
   */
  pulseBell() {
    if (!this.bellIcon) return;
    // Add ringing class for animation
    this.bellIcon.classList.add("ringing");
    setTimeout(() => {
      this.bellIcon.classList.remove("ringing");
    }, 500);
  },

  /**
   * Connect to SSE stream for real-time blocked events
   */
  connect() {
    try {
      const eventSource = new EventSource("/api/blocked-events");

      eventSource.onmessage = (event) => {
        try {
          const blockedEvent = JSON.parse(event.data);
          if (this.shouldShowAlert(blockedEvent)) {
            this.showAlert(blockedEvent);
          }
        } catch (e) {
          console.error("[Alerts] Error parsing blocked event:", e);
        }
      };

      eventSource.onerror = () => {
        console.warn("[Alerts] SSE connection error, reconnecting...");
        eventSource.close();
        setTimeout(() => this.connect(), 5000);
      };
    } catch (e) {
      console.error("[Alerts] Failed to initialize SSE:", e);
      setTimeout(() => this.connect(), 5000);
    }
  },

  /**
   * Determine if alert should be shown based on trigger logic
   */
  shouldShowAlert(event) {
    // Don't show alerts for Clean/normal requests
    if (event.attack_type === "Clean" || event.type === "Clean") return false;

    // Show if request is blocked
    if (event.blocked) return true;

    // Show if high/critical severity
    if (event.severity === "High" || event.severity === "Critical") return true;

    // Show if high ML confidence (≥ 0.85)
    if (event.ml_detected && event.confidence && event.confidence >= 0.85) {
      return true;
    }

    return false;
  },

  /**
   * Create and display individual alert in dropdown
   */
  showAlert(event) {
    const alertId = `alert-${Date.now()}-${Math.random()}`;
    const colors = this.colorMap[event.attack_type] || this.colorMap.default;
    const severity = event.severity || "Medium";
    const isCritical = severity === "Critical";

    // Pulse bell for every alert
    this.pulseBell();

    // Only emit an audible tone for true critical alerts.  The
    // notifications dropdown is now made up of lightweight cards and
    // transitions between them are not meant to be disruptive, so we
    // avoid playing any sound unless the incident is marked critical.
    //
    // The old behaviour played a tone for every event which made the UI
    // feel noisy when merely switching cards.
    if (isCritical) {
      this.playNotificationSound();
    }

    // Remove empty state if exists
    const emptyState = document.getElementById("empty-state");
    if (emptyState) emptyState.remove();

    // Create alert item
    const alert = document.createElement("div");
    alert.id = alertId;
    alert.style.cssText = `
      padding: 12px 16px;
      display: flex;
      align-items: flex-start;
      gap: 10px;
      border-bottom: 1px solid var(--border-dim);
      transition: all 0.2s ease;
      cursor: pointer;
      background: var(--bg-main);
    `;

    alert.addEventListener("mouseover", () => {
      alert.style.background = "rgba(168, 85, 247, 0.05)";
    });

    alert.addEventListener("mouseout", () => {
      alert.style.background = "var(--bg-main)";
    });

    // Color indicator dot
    const indicator = document.createElement("div");
    indicator.style.cssText = `
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: ${colors.indicator};
      flex-shrink: 0;
      margin-top: 4px;
    `;

    // Content
    const content = document.createElement("div");
    content.style.cssText = `
      flex: 1;
      min-width: 0;
    `;

    // Title
    const title = document.createElement("div");
    title.style.cssText = `
      font-weight: 600;
      color: ${colors.text};
      font-size: 12px;
      line-height: 1.3;
    `;
    title.textContent = event.attack_type || "Security Alert";

    // Timestamp
    const timestamp = document.createElement("div");
    timestamp.style.cssText = `
      font-size: 10px;
      color: var(--text-secondary);
      margin-top: 2px;
    `;
    const now = new Date().toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
    });
    timestamp.textContent = now;

    // Description (optional)
    if (event.ip) {
      const desc = document.createElement("div");
      desc.style.cssText = `
        font-size: 11px;
        color: var(--text-secondary);
        margin-top: 3px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      `;
      desc.textContent = `From: ${event.ip}`;
      content.appendChild(title);
      content.appendChild(desc);
      content.appendChild(timestamp);
    } else {
      content.appendChild(title);
      content.appendChild(timestamp);
    }

    // Close button
    const closeBtn = document.createElement("button");
    closeBtn.className = "close-chat";
    closeBtn.innerHTML = "&times;";
    closeBtn.title = "Dismiss";
    closeBtn.style.fontSize = "22px"; // Slightly smaller for list items

    closeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      this.dismissAlert(alertId);
    });

    // Assemble
    alert.appendChild(indicator);
    alert.appendChild(content);
    alert.appendChild(closeBtn);

    // Click handler to navigate
    alert.addEventListener("click", () => {
      window.location.href = "/blocked";
    });

    // Add to list
    this.alertsList.insertBefore(alert, this.alertsList.firstChild);
    this.activeAlerts.push(alertId);

    // notify dashboard that a new security alert arrived (synchronize UI)
    try {
      const evt = new CustomEvent("newSecurityAlert", { detail: event });
      document.dispatchEvent(evt);
    } catch (e) {
      console.warn("[Alerts] failed to dispatch newSecurityAlert", e);
    }

    // Update unread count
    this.unreadCount++;
    this.updateBadge();
  },

  /**
   * Get emoji icon based on attack type
   */
  getIconForAttackType(type) {
    const icons = {
      "SQL Injection": "🔓",
      XSS: "🐍",
      "ML Detection": "🧠",
      "Brute Force": "⚔️",
      "Rate Limit": "🚫",
      "Access Violation": "🔒",
      Scanner: "🔍",
      default: "⚠️",
    };
    return icons[type] || icons.default;
  },

  /**
   * Set auto-dismiss timer for alert (60 seconds)
   */
  setAlertTimer(alertId, alertElement) {
    // Clear existing timer if any
    if (this.alertTimers.has(alertId)) {
      clearTimeout(this.alertTimers.get(alertId));
    }

    const timer = setTimeout(() => {
      this.dismissAlert(alertId);
    }, 60000); // 60 second auto-dismiss

    this.alertTimers.set(alertId, timer);
  },

  /**
   * Dismiss alert with fade-out animation
   */
  dismissAlert(alertId) {
    const alertElement = document.getElementById(alertId);
    if (!alertElement) return;

    // Play fade-out animation
    alertElement.style.animation = "slideOutRight 0.3s ease-out";

    setTimeout(() => {
      if (alertElement.parentElement) {
        alertElement.remove();
      }
      this.activeAlerts = this.activeAlerts.filter((id) => id !== alertId);

      // Update unread count
      if (this.unreadCount > 0) {
        this.unreadCount--;
      }
      this.updateBadge();

      // Show empty state if no alerts
      if (this.activeAlerts.length === 0) {
        const emptyState = document.createElement("div");
        emptyState.id = "empty-state";
        emptyState.style.cssText = `
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 200px;
          gap: 8px;
          color: #9CA3AF;
          font-size: 12px;
        `;
        emptyState.innerHTML = `
          <div style="font-size: 32px;"></div>
          <div>No recent alerts</div>
        `;
        this.alertsList.appendChild(emptyState);
      }

      // Clear timer
      if (this.alertTimers.has(alertId)) {
        clearTimeout(this.alertTimers.get(alertId));
        this.alertTimers.delete(alertId);
      }
    }, 300);
  },
};

// Inject professional CSS animations and styles
const alertStyles = document.createElement("style");
alertStyles.textContent = `
  /* Dropdown slide animation */
  @keyframes dropdownSlideIn {
    from {
      opacity: 0;
      transform: translateY(-8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  /* Bell pulse animation for critical alerts */
  @keyframes bellPulse {
    0%, 100% {
      transform: scale(1);
    }
    50% {
      transform: scale(1.15);
    }
  }

  /* Scrollbar styling for alerts list */
  #notification-alerts-list::-webkit-scrollbar {
    width: 6px;
  }

  #notification-alerts-list::-webkit-scrollbar-track {
    background: transparent;
  }

  #notification-alerts-list::-webkit-scrollbar-thumb {
    background: #D1D5DB;
    border-radius: 3px;
  }

  #notification-alerts-list::-webkit-scrollbar-thumb:hover {
    background: #9CA3AF;
  }

  /* Bell icon hover effect */
  #notification-bell:hover {
    background: #F3F4F6;
  }

  #notification-bell:active {
    background: #E5E7EB;
  }

  /* Responsive for mobile */
  @media (max-width: 640px) {
    #notification-dropdown {
      width: 100% !important;
      max-width: none !important;
      left: 0 !important;
      right: 0 !important;
      border-radius: 0 !important;
    }

    #notification-bell-container {
      margin-right: 8px !important;
    }
  }
`;
document.head.appendChild(alertStyles);

// Initialize on page load
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    SecurityAlerts.init();
  });
} else {
  SecurityAlerts.init();
}
