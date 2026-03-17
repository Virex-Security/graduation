/**
 * Landing Page JavaScript - Interactions and Navigation
 */

document.addEventListener("DOMContentLoaded", function () {
  // Smooth scroll for navigation
  setupSmoothScroll();

  // Navbar scroll effect
  setupNavbarScroll();

  // Add animation classes on scroll
  setupScrollAnimations();
});

/**
 * Check if user is authenticated and redirect to dashboard
 */
// Note: automatic redirect removed to avoid navigation races with the login
// flow. If you want automatic redirect, call this explicitly after verifying
// a server-side session or a validated token.

/**
 * Setup smooth scrolling for navigation links
 */
function setupSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault();
      const targetId = this.getAttribute("href");
      const target = document.querySelector(targetId);
      
      console.log(`Navigating to: ${targetId}`);
      
      if (target) {
        console.log(`Target found: ${target.tagName}#${target.id}`);
        
        // Calculate offset for fixed navbar (approximately 80px)
        const navbarHeight = 80;
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navbarHeight;
        
        window.scrollTo({
          top: targetPosition,
          behavior: "smooth"
        });
      } else {
        console.error(`Target not found for: ${targetId}`);
      }
    });
  });
}

/**
 * Handle navbar transparency on scroll - DISABLED
 * Navbar now maintains theme colors consistently
 */
function setupNavbarScroll() {
  // Navbar scroll effects disabled to maintain theme consistency
  // The navbar will use CSS variables and maintain theme colors
}

/**
 * Setup scroll animations for elements
 */
function setupScrollAnimations() {
  // This is a simple animation setup
  // In production, you might use Intersection Observer API
  const observerOptions = {
    threshold: 0.1,
    rootMargin: "0px 0px -50px 0px",
  };

  const observer = new IntersectionObserver(function (entries) {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = "1";
        entry.target.style.transform = "translateY(0)";
      }
    });
  }, observerOptions);

  // Observe feature cards and step cards
  document.querySelectorAll(".feature-card, .step-card").forEach((el) => {
    el.style.opacity = "0";
    el.style.transform = "translateY(20px)";
    el.style.transition = "all 0.6s ease-out";
    observer.observe(el);
  });
}

/**
 * Add ripple effect to buttons - DISABLED
 * This was causing visual sizing issues with hero buttons
 */
// function setupButtonRipple() {
//   const buttons = document.querySelectorAll("button");
//   buttons.forEach((button) => {
//     button.addEventListener("click", function (e) {
//       const ripple = document.createElement("span");
//       const rect = this.getBoundingClientRect();
//       const size = Math.max(rect.width, rect.height);
//       const x = e.clientX - rect.left - size / 2;
//       const y = e.clientY - rect.top - size / 2;
//       ripple.style.width = ripple.style.height = size + "px";
//       ripple.style.left = x + "px";
//       ripple.style.top = y + "px";
//       ripple.classList.add("ripple");
//       const existingRipple = this.querySelector(".ripple");
//       if (existingRipple) existingRipple.remove();
//       this.appendChild(ripple);
//     });
//   });
// }

/**
 * Mobile menu toggle (if needed in future)
 */
function toggleMobileMenu() {
  const navButtons = document.querySelector(".nav-buttons");
  navButtons.classList.toggle("active");
}

// Add scroll animation on page load
window.addEventListener("load", function () {
  console.log("Landing page loaded successfully");
});
