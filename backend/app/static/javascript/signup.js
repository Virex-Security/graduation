/* ==================== SIGNUP PAGE JAVASCRIPT ==================== */

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
 * Validate signup form and submit to backend
 * @param {Event} event - Form submission event
 */
async function handleSignup(event) {
  event.preventDefault();

  const fullName = document.getElementById("fullName").value.trim();
  const username = document.getElementById("username").value.trim();
  const email = document.getElementById("email").value.trim();
  const phone = document.getElementById("phone").value.trim();
  const department = document.getElementById("department").value;
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;
  const messageBox = document.getElementById("message-box");
  const submitButton = document.querySelector(".btn-primary");

  const isValid = FormValidator.validate("signupForm", {
    fullName: { required: true, minLength: 2 },
    username: { required: true, minLength: 3 },
    email: { required: true, email: true },
    phone: { required: true },
    department: { required: true },
    password: { required: true, strong: true },
    confirmPassword: { required: true, match: "password" }
  });

  if (!isValid) return;

  // Check terms and conditions
  const termsCheckbox = document.getElementById("terms");
  if (!termsCheckbox.checked) {
    showMessage(messageBox, "Please accept the Terms of Service and Privacy Policy", "error");
    return;
  }

  // Disable submit button and show loading state
  submitButton.disabled = true;
  submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Account...';

  try {
    const data = await API.post("/api/auth/signup", {
        fullName: fullName,
        username: username,
        email: email,
        phone: phone,
        department: department,
        password: password,
    });

    showMessage(
      messageBox,
      "✓ Account created successfully! Redirecting to login...",
      "success",
    );
    // Clear form
    document.getElementById("signupForm").reset();
    // Redirect to login after 2 seconds
    setTimeout(() => {
      window.location.href = "/login";
    }, 2000);

  } catch (error) {
    if (error.message.includes("exists") || error.message.includes("409")) {
      showMessage(messageBox, error.message || "Username or email already exists", "error");
    } else {
      showMessage(messageBox, error.message || "Sign up failed", "error");
      console.error("Signup error:", error);
    }
    submitButton.disabled = false;
    submitButton.innerHTML = '<span>Create Account</span><i class="fas fa-arrow-right"></i>';
  }
}

/**
 * Initialize signup form on DOMContentLoaded
 */
document.addEventListener("DOMContentLoaded", () => {
  // Attach form submission handler
  const signupForm = document.getElementById("signupForm");
  if (signupForm) {
    signupForm.addEventListener("submit", handleSignup);
  }

  // Add real-time validation
  const fullNameInput = document.getElementById("fullName");
  if (fullNameInput) {
    fullNameInput.addEventListener("input", (e) => {
      const value = e.target.value.trim();
      if (value.length < 2 && value.length > 0) {
        e.target.classList.add("invalid");
      } else {
        e.target.classList.remove("invalid");
      }
    });
  }

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

  const emailInput = document.getElementById("email");
  if (emailInput) {
    emailInput.addEventListener("input", (e) => {
      const value = e.target.value.trim();
      if (value && !validateEmail(value)) {
        e.target.classList.add("invalid");
      } else {
        e.target.classList.remove("invalid");
      }
    });
  }

  const phoneInput = document.getElementById("phone");
  if (phoneInput) {
    phoneInput.addEventListener("input", (e) => {
      const value = e.target.value.trim();
      if (value && !validatePhone(value)) {
        e.target.classList.add("invalid");
      } else {
        e.target.classList.remove("invalid");
      }
    });
  }

  const passwordInput = document.getElementById("password");
  if (passwordInput) {
    passwordInput.addEventListener("input", (e) => {
      const value = e.target.value;
      const validation = validatePassword(value);
      if (value && !validation.isValid) {
        e.target.classList.add("invalid");
      } else {
        e.target.classList.remove("invalid");
      }
    });
  }

  const confirmPasswordInput = document.getElementById("confirmPassword");
  if (confirmPasswordInput && passwordInput) {
    confirmPasswordInput.addEventListener("input", (e) => {
      if (e.target.value !== passwordInput.value && e.target.value) {
        e.target.classList.add("password-mismatch");
        e.target.classList.remove("password-match");
      } else if (e.target.value === passwordInput.value && e.target.value) {
        e.target.classList.add("password-match");
        e.target.classList.remove("password-mismatch");
      } else {
        e.target.classList.remove("password-match", "password-mismatch");
      }
    });
  }
});


