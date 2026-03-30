/* ==================== LOGIN PAGE JAVASCRIPT ==================== */

/**
 * Returns true only when debug logging is explicitly enabled by the server.
 * Keep this false in production by not defining window.__APP_DEBUG__.
 */
function isClientDebugEnabled() {
  return (
    typeof window !== "undefined" &&
    window.__APP_DEBUG__ === true
  );
}

/**
 * Redact potentially sensitive fields before logging.
 * Never allow OTP/password/token/user identifiers to be printed raw.
 * @param {unknown} value
 * @returns {unknown}
 */
function sanitizeDebugValue(value) {
  if (value == null) return value;

  if (typeof value === "string") {
    return value.length <= 4 ? "***" : `${value.slice(0, 2)}***${value.slice(-2)}`;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeDebugValue(item));
  }

  if (typeof value === "object") {
    const masked = {};
    for (const [key, rawVal] of Object.entries(value)) {
      const normalized = key.toLowerCase();
      if (
        /otp|password|token|secret|user.?id|identifier|email|username/.test(
          normalized,
        )
      ) {
        masked[key] = "[REDACTED]";
      } else {
        masked[key] = sanitizeDebugValue(rawVal);
      }
    }
    return masked;
  }

  return "[REDACTED]";
}

/**
 * Safe debug logger that is disabled by default and redacts sensitive fields.
 * @param {string} eventName
 * @param {Record<string, unknown>} [metadata]
 */
function safeDebugLog(eventName, metadata = {}) {
  if (!isClientDebugEnabled()) return;
  const cleanMetadata = sanitizeDebugValue(metadata);
  if (Object.keys(cleanMetadata).length) {
    console.debug(`[LoginDebug] ${eventName}`, cleanMetadata);
  } else {
    console.debug(`[LoginDebug] ${eventName}`);
  }
}

/**
 * Toggle password visibility
 * @param {string} inputId - The ID of the password input
 */
function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  const button = input.parentElement.querySelector(".password-toggle");
  const icon = button.querySelector("i");

  if (input.type === "password") {
    input.type = "text";
    icon.className = "fas fa-eye-slash";
  } else {
    input.type = "password";
    icon.className = "fas fa-eye";
  }
}

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
  submitButton.innerHTML =
    '<i class="fas fa-spinner fa-spin"></i> Signing In...';

  // Use Auth module to login
  const success = await Auth.login(username, password);

  if (!success) {
    showMessage(messageBox, "Incorrect username or password", "error");
    submitButton.disabled = false;
    submitButton.innerHTML =
      '<span>Sign In</span><i class="fas fa-arrow-right"></i>';
  }
  // If success, Auth.login redirects automatically to /dashboard
}

/**
 * Initialize login form on DOMContentLoaded
 */
document.addEventListener("DOMContentLoaded", () => {
  // Scoped variable to store user_id for password reset
  let otpResetUserId = null;

  // Make forgot password functions available globally for all pages
  window.submitForgotPassword = async function () {
    const identifier = document
      .getElementById("forgot-identifier")
      .value.trim();
    const msgBox = document.getElementById("forgot-message");
    if (!identifier) {
      showMessage(msgBox, "Username or email is required", "error");
      return;
    }
    msgBox.className = "";
    msgBox.innerHTML =
      '<i class="fas fa-spinner fa-spin"></i> Generating OTP...';
    try {
      const res = await fetch("/api/request-reset-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ identifier }),
      });
      const data = await res.json();
      if (res.ok) {
        otpResetUserId = data.user_id;
        safeDebugLog("reset_otp_requested_successfully", {
          hasResetUserId: Boolean(otpResetUserId),
          hasExpiry: Boolean(data.expiry),
        });
        if (typeof window.showOtpResetModal === "function") {
          window.showOtpResetModal(data.expiry);
        } else if (document.getElementById("otp-reset-form")) {
          // Fallback for forgot_password.html
          document.getElementById("forgot-password-form").style.display =
            "none";
          document.getElementById("otp-reset-form").style.display = "block";
          const msgBox2 = document.getElementById("otp-reset-message");
          msgBox2.className = "success";
          msgBox2.replaceChildren();
          {
            const icon = document.createElement("i");
            icon.className = "fas fa-check-circle";
            msgBox2.appendChild(icon);
            msgBox2.append(" An OTP has been sent to your email address.");
            msgBox2.appendChild(document.createElement("br"));

            const span = document.createElement("span");
            span.style.fontSize = "0.9em";
            span.textContent = `(expires at ${String(data.expiry ?? "")})`;
            msgBox2.appendChild(span);
          }
          msgBox2.classList.remove("hidden");
        }
      } else {
        showMessage(msgBox, data.error || "Failed to generate OTP", "error");
      }
    } catch (e) {
      showMessage(msgBox, "Network error. Please try again.", "error");
    }
  };

  window.submitOtpReset = async function () {
    const otp = document.getElementById("otp-code").value.trim();
    const newPassword = document.getElementById("otp-new-password").value;
    const msgBox = document.getElementById("otp-reset-message");
    if (!otp || !newPassword) {
      showMessage(msgBox, "OTP and new password are required", "error");
      return;
    }
    msgBox.className = "";
    msgBox.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';
    safeDebugLog("submitting_reset_otp_verification", {
      hasResetUserId: Boolean(otpResetUserId),
      otpLength: otp.length,
    });
    try {
      const res = await fetch("/api/verify-reset-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id: otpResetUserId,
          otp,
          new_password: newPassword,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        showMessage(
          msgBox,
          data.message || "Password reset successful!",
          "success",
        );
        setTimeout(() => {
          if (document.getElementById("otp-reset-form")) {
            document.getElementById("otp-reset-form").style.display = "none";
          }
          if (typeof window.closeOtpResetModal === "function") {
            window.closeOtpResetModal();
          }
        }, 2000);
      } else {
        showMessage(msgBox, data.error || "Failed to reset password", "error");
      }
    } catch (e) {
      showMessage(msgBox, "Network error. Please try again.", "error");
    }
  };

  window.showOtpResetModal = function (expiry) {
    if (document.getElementById("otp-reset-modal")) {
      document.getElementById("otp-reset-modal").style.display = "block";
      document.getElementById("otp-reset-message").className = "hidden";
      document.getElementById("otp-reset-message").innerHTML = "";
      document.getElementById("otp-code").value = "";
      document.getElementById("otp-new-password").value = "";
      showMessage(
        document.getElementById("otp-reset-message"),
        `An OTP has been sent to your email address.`,
        "success",
      );
    } else if (document.getElementById("otp-reset-form")) {
      document.getElementById("forgot-password-form").style.display = "none";
      document.getElementById("otp-reset-form").style.display = "block";
      const msgBox2 = document.getElementById("otp-reset-message");
      msgBox2.className = "success";
      msgBox2.innerHTML = `<i class='fas fa-check-circle'></i> An OTP has been sent to your email address.`;
      msgBox2.classList.remove("hidden");
    }
  };

  // Ensure togglePassword is always available
  window.togglePassword = togglePassword;
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
