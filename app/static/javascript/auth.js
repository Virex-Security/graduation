/**
 * Authentication management for the CyberShield Pro dashboard
 */

const Auth = {
  // Session keys
  SESSION_KEY: "cyber_shield_session",
  USER_KEY: "cyber_shield_user",

  /**
   * Initialize authentication state
   */
  init() {
    // Avoid automatic redirects from the login and signup pages
    // and the landing page to prevent redirect loops.
    if (
      !this.isAuthenticated() &&
      !window.location.pathname.includes("login") &&
      !window.location.pathname.includes("signup") &&
      !window.location.pathname.includes("forgot-password") &&
      window.location.pathname !== "/"
    ) {
      window.location.href = "/login";
    }
  },

  /**
   * Check if user is authenticated
   */
  isAuthenticated() {
    return localStorage.getItem(this.SESSION_KEY) !== null;
  },

  /**
   * Get current user data
   */
  getUser() {
    const userJson = localStorage.getItem(this.USER_KEY);
    return userJson ? JSON.parse(userJson) : null;
  },

  /**
   * Perform login
   */
  async login(username, password) {
    try {
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
      const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        const data = await response.json();
        const userData = {
          username: username,
          role: data.role,
          loginTime: new Date().toISOString(),
        };

        localStorage.setItem(this.SESSION_KEY, "active");
        localStorage.setItem(this.USER_KEY, JSON.stringify(userData));

        // Redirect to the protected dashboard route; server will verify the cookie
        window.location.href = "/dashboard";
        return true;
      }
      return false;
<<<<<<< HEAD
=======
=======
      const data = await API.post("/api/auth/login", { username, password });
      
      const userData = {
        username: username,
        role: data.role,
        loginTime: new Date().toISOString(),
      };

      localStorage.setItem(this.SESSION_KEY, "active");
      localStorage.setItem(this.USER_KEY, JSON.stringify(userData));

      // Redirect to the protected dashboard route; server will verify the cookie
      window.location.href = "/dashboard";
      return true;
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    } catch (error) {
      console.error("Login error:", error);
      return false;
    }
  },

  /**
   * Perform logout
   */
  async logout() {
    try {
<<<<<<< HEAD
      await fetch("/api/auth/logout");
=======
<<<<<<< HEAD
      await fetch("/api/auth/logout");
=======
      await API.get("/api/auth/logout");
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    } catch (e) {}
    localStorage.removeItem(this.SESSION_KEY);
    localStorage.removeItem(this.USER_KEY);
    window.location.href = "/";
  },
};

// Initialize on load
Auth.init();


