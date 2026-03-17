/**
 * Global Theme Manager for all pages
 * Handles dark/light mode toggling across the entire application
 */

const ThemeManager = {
  STORAGE_KEY: "theme",
  DEFAULT_THEME: "dark",

  /**
   * Initialize theme on page load
   */
  init() {
    const savedTheme =
      localStorage.getItem(this.STORAGE_KEY) || this.DEFAULT_THEME;
    this.setTheme(savedTheme);
    this.setupThemeToggle();
  },

  /**
   * Set theme for the entire application
   */
  setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(this.STORAGE_KEY, theme);
    this.updateThemeIcon(theme);
  },

  /**
   * Toggle between dark and light mode
   */
  toggleTheme() {
    const currentTheme =
      document.documentElement.getAttribute("data-theme") || this.DEFAULT_THEME;
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    this.setTheme(newTheme);

    // Trigger custom event for other scripts to listen
    window.dispatchEvent(
      new CustomEvent("themeChanged", { detail: { theme: newTheme } }),
    );
  },

  /**
   * Update the theme toggle icon and display icons
   */
  updateThemeIcon(theme) {
    // Update clickable theme toggle button (landing/login pages)
    const themeButtons = document.querySelectorAll("#theme-toggle");
    themeButtons.forEach((button) => {
      const icon = button.querySelector("i");
      if (icon) {
        icon.className = theme === "dark" ? "fas fa-sun" : "fas fa-moon";
      }
    });

    // Update theme icon displays (other pages)
    const themeIcons = document.querySelectorAll(".theme-icon i");
    themeIcons.forEach((icon) => {
      icon.className = theme === "dark" ? "fas fa-sun" : "fas fa-moon";
    });
  },
  /**
   * Setup click handler for theme toggle button
   */
  setupThemeToggle() {
    const themeButton = document.getElementById("theme-toggle");
    if (themeButton) {
      themeButton.addEventListener("click", () => this.toggleTheme());
    }
  },

  /**
   * Get current theme
   */
  getCurrentTheme() {
    return (
      document.documentElement.getAttribute("data-theme") || this.DEFAULT_THEME
    );
  },
};

// Initialize theme immediately to prevent flash
(function () {
  const savedTheme =
    localStorage.getItem(ThemeManager.STORAGE_KEY) ||
    ThemeManager.DEFAULT_THEME;
  document.documentElement.setAttribute("data-theme", savedTheme);
})();

// Initialize event listeners when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () =>
    ThemeManager.setupThemeToggle(),
  );
  document.addEventListener("DOMContentLoaded", () => {
    const currentTheme =
      localStorage.getItem(ThemeManager.STORAGE_KEY) ||
      ThemeManager.DEFAULT_THEME;
    ThemeManager.updateThemeIcon(currentTheme);
  });
} else {
  ThemeManager.setupThemeToggle();
  const currentTheme =
    localStorage.getItem(ThemeManager.STORAGE_KEY) ||
    ThemeManager.DEFAULT_THEME;
  ThemeManager.updateThemeIcon(currentTheme);
}
