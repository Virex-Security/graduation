/* ==================== LOGIN PAGE JAVASCRIPT ==================== */

/**
 * Toggle password visibility
 * @param {string} inputId - The ID of the password input
 */
function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  const button = input.parentElement.querySelector('.password-toggle');
  const icon = button.querySelector('i');
  
  if (input.type === 'password') {
    input.type = 'text';
    icon.className = 'fas fa-eye-slash';
  } else {
    input.type = 'password';
    icon.className = 'fas fa-eye';
  }
}

/**
 * Display message in the message box with animation
 * @param {HTMLElement} element - The message box element
 * @param {string} message - The message to display
 * @param {string} type - Message type: 'success' or 'error'
 */
function showMessage(element, message, type) {
  const iconClass = type === "error" ? "fa-exclamation-circle" : "fa-check-circle";
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
  const submitButton = document.querySelector(".btn-primary");

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
  submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing In...';

  // Use Auth module to login
  const success = await Auth.login(username, password);

  if (!success) {
    showMessage(messageBox, "Incorrect username or password", "error");
    submitButton.disabled = false;
    submitButton.innerHTML = '<span>Sign In</span><i class="fas fa-arrow-right"></i>';
  }
  // If success, Auth.login redirects automatically to /dashboard
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


