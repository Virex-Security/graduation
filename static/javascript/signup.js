/* ==================== SIGNUP PAGE JAVASCRIPT ==================== */

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
 * Validate signup form and submit to backend
 * @param {Event} event - Form submission event
 */
async function handleSignup(event) {
  event.preventDefault();

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirm-password").value;
  const messageBox = document.getElementById("message-box");
  const submitButton = document.querySelector(".btn-submit");

  // Validation
  if (!username) {
    showMessage(messageBox, "Username is required", "error");
    return;
  }

  if (username.length < 3) {
    showMessage(messageBox, "Username must be at least 3 characters", "error");
    return;
  }

  if (!password || password.length < 8) {
    showMessage(messageBox, "Password must be at least 8 characters", "error");
    return;
  }

  if (password !== confirmPassword) {
    showMessage(messageBox, "Passwords do not match", "error");
    return;
  }

  // Disable submit button and show loading state
  submitButton.disabled = true;
  submitButton.innerHTML =
    '<i class="fas fa-spinner fa-spin"></i> Creating Account...';

  try {
    const response = await fetch("/api/auth/signup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    });

    const data = await response.json();

    if (response.status === 201) {
      showMessage(
        messageBox,
        "✓ Account created successfully! Redirecting to login...",
        "success",
      );
      // Clear form
      document.getElementById("signup-form").reset();
      // Redirect to login after 2 seconds
      setTimeout(() => {
        window.location.href = "/login";
      }, 2000);
    } else if (response.status === 409) {
      showMessage(
        messageBox,
        data.message || "Username already exists",
        "error",
      );
      submitButton.disabled = false;
      submitButton.innerHTML =
        '<i class="fas fa-user-plus"></i> Create Account';
    } else {
      showMessage(messageBox, data.message || "Sign up failed", "error");
      submitButton.disabled = false;
      submitButton.innerHTML =
        '<i class="fas fa-user-plus"></i> Create Account';
    }
  } catch (error) {
    showMessage(messageBox, "Connection error. Please try again.", "error");
    console.error("Signup error:", error);
    submitButton.disabled = false;
    submitButton.innerHTML = '<i class="fas fa-user-plus"></i> Create Account';
  }
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

    // Add some basic styling via inline styles for the toggle
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
 * Initialize signup form on DOMContentLoaded
 */
document.addEventListener("DOMContentLoaded", () => {
  // Attach form submission handler
  const signupForm = document.getElementById("signup-form");
  if (signupForm) {
    signupForm.addEventListener("submit", handleSignup);
  }

  // Initialize password visibility toggle
  initializePasswordToggle();

  // Add real-time username validation
  const usernameInput = document.getElementById("username");
  if (usernameInput) {
    usernameInput.addEventListener("input", (e) => {
      const value = e.target.value.trim();
      if (value.length < 3 && value.length > 0) {
        e.target.classList.add("invalid");
      } else {
        e.target.classList.remove("invalid");
      }
    });
  }

  // Add real-time password validation
  const passwordInput = document.getElementById("password");
  if (passwordInput) {
    passwordInput.addEventListener("input", (e) => {
      const value = e.target.value;
      if (value.length < 8 && value.length > 0) {
        e.target.classList.add("invalid");
      } else {
        e.target.classList.remove("invalid");
      }
    });
  }

  // Add password match validation
  const confirmPasswordInput = document.getElementById("confirm-password");
  if (confirmPasswordInput && passwordInput) {
    confirmPasswordInput.addEventListener("input", (e) => {
      if (e.target.value !== passwordInput.value && e.target.value) {
        e.target.classList.add("invalid");
      } else {
        e.target.classList.remove("invalid");
      }
    });
  }
});
