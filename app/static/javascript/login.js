/* ==================== LOGIN PAGE JAVASCRIPT ==================== */

/**
 * Display message in the message box with animation
 * @param {HTMLElement} element - The message box element
 * @param {string} message - The message to display
 * @param {string} type - Message type: 'success' or 'error'
 */
function showMessage(element, message, type) {
  const iconClass =
    type === "error" ? "fa-exclamation-circle" : "fa-check-circle";
  element.className = `${type}`;
  element.innerHTML = `<div class="message-content"><i class="fas ${iconClass}"></i> ${message}</div>`;
  element.classList.remove("hidden");

  // Auto-hide error messages after 5 seconds
  if (type === "error") {
    setTimeout(() => {
      element.classList.add("hidden");
    }, 5000);
  }
}

/**
 * Handle login form submission
 * @param {Event} event - Form submission event
 */
async function handleLogin(event) {
  event.preventDefault();

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const messageBox = document.getElementById("message-box");
  const submitButton = document.querySelector(".btn-submit");

  // Validation
  if (!username) {
    showMessage(messageBox, "Username is required", "error");
    return;
  }

  if (!password) {
    showMessage(messageBox, "Password is required", "error");
    return;
  }

  // Disable submit button and show loading state
  submitButton.disabled = true;
  submitButton.innerHTML =
    '<i class="fas fa-spinner fa-spin"></i> Signing In...';

  // Use Auth module to login
  const success = await Auth.login(username, password);

  if (!success) {
    showMessage(messageBox, "Incorrect username or password", "error");
    submitButton.disabled = false;
    submitButton.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign In';
  }
  // If success, Auth.login redirects automatically to /dashboard
}

/**
 * Initialize password visibility toggle
 */
function initializePasswordToggle() {
  const passwordInputs = document.querySelectorAll('input[type="password"]');

  passwordInputs.forEach((input) => {
    const formGroup = input.parentElement;

    // Create toggle button
    const toggleButton = document.createElement("button");
    toggleButton.type = "button";
    toggleButton.className = "password-toggle";
    toggleButton.innerHTML = '<i class="fas fa-eye"></i>';
    toggleButton.setAttribute("title", "Show/Hide Password");

    // Add styling via inline styles
    toggleButton.style.position = "absolute";
    toggleButton.style.right = "1rem";
    toggleButton.style.top = "2.5rem";
    toggleButton.style.background = "none";
    toggleButton.style.border = "none";
    toggleButton.style.color = "var(--color-text-muted)";
    toggleButton.style.cursor = "pointer";
    toggleButton.style.fontSize = "1rem";
    toggleButton.style.padding = "0.5rem";
    toggleButton.style.transition = "color 0.3s ease";

    // Make form group position relative for absolute positioning
    formGroup.style.position = "relative";

    // Add some right padding to input
    input.style.paddingRight = "3rem";

    formGroup.appendChild(toggleButton);

    toggleButton.addEventListener("click", (e) => {
      e.preventDefault();
      const isPassword = input.type === "password";
      input.type = isPassword ? "text" : "password";
      toggleButton.innerHTML = isPassword
        ? '<i class="fas fa-eye-slash"></i>'
        : '<i class="fas fa-eye"></i>';
      toggleButton.style.color = isPassword
        ? "var(--color-purple)"
        : "var(--color-text-muted)";
    });

    // Change color on hover
    toggleButton.addEventListener("mouseenter", () => {
      toggleButton.style.color = "var(--color-purple)";
    });

    toggleButton.addEventListener("mouseleave", () => {
      const isPassword = input.type === "password";
      toggleButton.style.color = isPassword
        ? "var(--color-text-muted)"
        : "var(--color-purple)";
    });
  });
}

/**
 * Initialize login form on DOMContentLoaded
 */
document.addEventListener("DOMContentLoaded", () => {
  // Attach form submission handler
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", handleLogin);
  }

  // Initialize password visibility toggle
  initializePasswordToggle();

  // Add real-time username input validation
  const usernameInput = document.getElementById("username");
  if (usernameInput) {
    usernameInput.addEventListener("input", (e) => {
      const value = e.target.value.trim();
      if (value) {
        e.target.classList.remove("invalid");
      }
    });
  }

  // Add password input validation
  const passwordInput = document.getElementById("password");
  if (passwordInput) {
    passwordInput.addEventListener("input", (e) => {
      if (e.target.value) {
        e.target.classList.remove("invalid");
      }
    });
  }
});


