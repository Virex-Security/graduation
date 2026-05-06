/* ==================== LOGIN PAGE JAVASCRIPT ==================== */

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
  if (!element) return;
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
  const rememberMe = document.getElementById("remember-me")?.checked || false;
  const messageBox = document.getElementById("message-box");
  const submitButton = document.querySelector(".btn-primary");

  const isValid = FormValidator.validate("login-form", {
    username: { required: true },
    password: { required: true },
  });

  if (!isValid) return;

  if (rememberMe) {
    Auth.rememberUsername(username);
  } else {
    Auth.clearRememberedUsername();
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
}

/**
 * Initialize login form on DOMContentLoaded
 */
// Global variable to store user_id for password reset
let otpResetUserId = null;
let otpVerifiedForReset = false;
let otpValidationInProgress = false;
let verifiedOtpCode = "";

function getOtpDigits() {
  return Array.from(document.querySelectorAll(".otp-digit-input"));
}

function getOtpCodeFromInputs() {
  return getOtpDigits()
    .map((input) => (input.value || "").trim())
    .join("");
}

function setOtpCodeHiddenValue() {
  const otpCodeInput = document.getElementById("otp-code");
  if (otpCodeInput) {
    otpCodeInput.value = getOtpCodeFromInputs();
  }
}

function setOtpInputsDisabled(disabled) {
  getOtpDigits().forEach((input) => {
    input.disabled = disabled;
  });
}

function resetOtpStage() {
  otpVerifiedForReset = false;
  otpValidationInProgress = false;
  verifiedOtpCode = "";
  const otpForm = document.getElementById("otp-reset-form");
  const resetForm = document.getElementById("reset-password-form");
  if (otpForm) {
    otpForm.style.display = "block";
  }
  if (resetForm) {
    resetForm.style.display = "none";
  }
  setOtpInputsDisabled(false);
}

async function validateOtpBeforePasswordEntry() {
  if (otpVerifiedForReset || otpValidationInProgress) return;

  const otp = getOtpCodeFromInputs();
  if (otp.length !== 6) return;

  const msgBox = document.getElementById("otp-reset-message");
  if (!otpResetUserId) {
    showMessage(msgBox, "Invalid OTP", "error");
    return;
  }

  otpValidationInProgress = true;
  showMessage(msgBox, "Verifying OTP...", "success");

  try {
    const res = await fetch("/api/verify-reset-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: otpResetUserId, otp }),
    });
    let data = {};
    try {
      data = await res.json();
    } catch (parseError) {
      data = { error: "Server returned an invalid response." };
    }

    if (res.ok) {
      otpVerifiedForReset = true;
      verifiedOtpCode = otp;
      setOtpCodeHiddenValue();
      setOtpInputsDisabled(true);
      const otpForm = document.getElementById("otp-reset-form");
      const resetForm = document.getElementById("reset-password-form");
      if (otpForm) {
        otpForm.style.display = "none";
      }
      if (resetForm) {
        resetForm.style.display = "block";
      }
      const resetMsgBox = document.getElementById("reset-password-message");
      showMessage(
        resetMsgBox,
        "OTP verified. Set your new password.",
        "success",
      );
      const newPasswordInput = document.getElementById("otp-new-password");
      if (newPasswordInput) {
        newPasswordInput.focus();
      }
    } else {
      resetOtpStage();
      getOtpDigits().forEach((input) => {
        input.value = "";
      });
      setOtpCodeHiddenValue();
      const firstOtp = document.getElementById("otp-digit-1");
      if (firstOtp) firstOtp.focus();
      showMessage(msgBox, data.error || "Invalid OTP", "error");
    }
  } catch (e) {
    resetOtpStage();
    showMessage(msgBox, "Network error. Please try again.", "error");
  } finally {
    otpValidationInProgress = false;
  }
}

function initializeOtpDigitInputs() {
  const otpInputs = getOtpDigits();
  if (!otpInputs.length) return;

  otpInputs.forEach((input, index) => {
    input.addEventListener("input", async (event) => {
      const cleanValue = (event.target.value || "").replace(/\D/g, "");
      event.target.value = cleanValue.slice(-1);

      if (event.target.value && index < otpInputs.length - 1) {
        otpInputs[index + 1].focus();
      }

      setOtpCodeHiddenValue();
      await validateOtpBeforePasswordEntry();
    });

    input.addEventListener("keydown", (event) => {
      if (event.key === "Backspace" && !input.value && index > 0) {
        otpInputs[index - 1].focus();
      }
    });

    input.addEventListener("focus", () => {
      input.select();
    });
  });

  const otpRow = document.getElementById("otp-digit-row");
  if (otpRow) {
    otpRow.addEventListener("paste", async (event) => {
      const pasted = (event.clipboardData || window.clipboardData)
        .getData("text")
        .replace(/\D/g, "")
        .slice(0, 6);
      if (!pasted) return;

      event.preventDefault();
      otpInputs.forEach((input, idx) => {
        input.value = pasted[idx] || "";
      });
      setOtpCodeHiddenValue();
      if (pasted.length < 6) {
        otpInputs[pasted.length].focus();
      }
      await validateOtpBeforePasswordEntry();
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initializeOtpDigitInputs();

  const rememberCheckbox = document.getElementById("remember-me");
  const usernameInput = document.getElementById("username");
  if (rememberCheckbox && usernameInput) {
    const remembered = Auth.getRememberedUsername();
    if (remembered) {
      usernameInput.value = remembered;
      rememberCheckbox.checked = true;
    }
  }

  // Ensure forgot-password starts in a clean state: identifier form only.
  const forgotForm = document.getElementById("forgot-password-form");
  const otpForm = document.getElementById("otp-reset-form");
  const resetForm = document.getElementById("reset-password-form");
  if (forgotForm && otpForm) {
    forgotForm.style.display = "flex";
    otpForm.style.display = "none";
    if (resetForm) {
      resetForm.style.display = "none";
    }
  }

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
        otpResetUserId = data.user_id || null;
        resetOtpStage();
        console.log("OTP Reset User ID set to:", otpResetUserId);
        const genericOtpMsg =
          "If the account exists, an OTP has been sent to the registered email.";
        showMessage(msgBox, genericOtpMsg, "success");
        if (typeof window.showOtpResetModal === "function") {
          window.showOtpResetModal(data.otp, data.expiry);
        } else if (document.getElementById("otp-reset-form")) {
          // Fallback for forgot_password.html
          document.getElementById("forgot-password-form").style.display =
            "none";
          document.getElementById("otp-reset-form").style.display = "block";
          const msgBox2 = document.getElementById("otp-reset-message");
          msgBox2.className = "success";
          msgBox2.innerHTML = `<i class='fas fa-check-circle'></i> If the account exists, an OTP has been sent to the registered email.`;
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
    const otp = getOtpCodeFromInputs();
    const msgBox = document.getElementById("otp-reset-message");
    if (otp.length !== 6) {
      showMessage(msgBox, "Please enter all 6 OTP digits", "error");
      return;
    }
    await validateOtpBeforePasswordEntry();
  };

  window.submitPasswordReset = async function () {
    const otp = verifiedOtpCode || getOtpCodeFromInputs();
    const newPassword = document.getElementById("otp-new-password").value;
    const confirmPassword = document.getElementById(
      "otp-confirm-password",
    ).value;
    const msgBox = document.getElementById("reset-password-message");
    if (!otpVerifiedForReset) {
      showMessage(msgBox, "Please verify OTP first.", "error");
      return;
    }
    if (!newPassword || !confirmPassword) {
      showMessage(
        msgBox,
        "New password and confirmation are required",
        "error",
      );
      return;
    }
    if (newPassword !== confirmPassword) {
      showMessage(msgBox, "Passwords do not match", "error");
      return;
    }
    msgBox.className = "";
    msgBox.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying...';
    console.log(
      "Submitting OTP reset with user_id:",
      otpResetUserId,
      "otp:",
      otp,
    );
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
          if (document.getElementById("reset-password-form")) {
            document.getElementById("reset-password-form").style.display =
              "none";
          }
          if (typeof window.closeOtpResetModal === "function") {
            window.closeOtpResetModal();
          }
        }, 2000);
      } else {
        if ((data.error || "").toLowerCase().includes("otp")) {
          resetOtpStage();
          getOtpDigits().forEach((input) => {
            input.value = "";
          });
          setOtpCodeHiddenValue();
          const otpMsg = document.getElementById("otp-reset-message");
          showMessage(
            otpMsg,
            "OTP is invalid or expired. Enter OTP again.",
            "error",
          );
        }
        showMessage(msgBox, data.error || "Failed to reset password", "error");
      }
    } catch (e) {
      showMessage(msgBox, "Network error. Please try again.", "error");
    }
  };

  window.showOtpResetModal = function (otp, expiry) {
    if (document.getElementById("otp-reset-modal")) {
      document.getElementById("otp-reset-modal").style.display = "block";
      document.getElementById("otp-reset-message").className = "hidden";
      document.getElementById("otp-reset-message").innerHTML = "";
      const resetMsg = document.getElementById("reset-password-message");
      if (resetMsg) {
        resetMsg.className = "hidden";
        resetMsg.innerHTML = "";
      }
      getOtpDigits().forEach((input) => {
        input.value = "";
      });
      setOtpCodeHiddenValue();
      resetOtpStage();
      document.getElementById("otp-new-password").value = "";
      if (document.getElementById("otp-confirm-password")) {
        document.getElementById("otp-confirm-password").value = "";
      }
      showMessage(
        document.getElementById("otp-reset-message"),
        `If the account exists, an OTP has been sent to the registered email.`,
        "success",
      );
    } else if (document.getElementById("otp-reset-form")) {
      document.getElementById("forgot-password-form").style.display = "none";
      document.getElementById("otp-reset-form").style.display = "block";
      const resetForm = document.getElementById("reset-password-form");
      if (resetForm) {
        resetForm.style.display = "none";
      }
      getOtpDigits().forEach((input) => {
        input.value = "";
      });
      setOtpCodeHiddenValue();
      resetOtpStage();
      const msgBox2 = document.getElementById("otp-reset-message");
      msgBox2.className = "success";
      msgBox2.innerHTML = `<i class='fas fa-check-circle'></i> If the account exists, an OTP has been sent to the registered email.`;
      msgBox2.classList.remove("hidden");
      const firstOtp = document.getElementById("otp-digit-1");
      if (firstOtp) firstOtp.focus();
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
