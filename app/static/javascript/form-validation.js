/**
 * Form Validation Module for Login & Registration
 * Leverages HTML5 validation and custom rules natively.
 */

const FormValidator = {
  /**
   * Main entry method to validate a given form object against rules
   */
  validate(formId, rules) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    let isValid = true;
    
    // Clear all previous errors
    form.querySelectorAll('.is-invalid').forEach(el => el.classList.remove('is-invalid'));
    form.querySelectorAll('.field-error-text').forEach(el => el.style.display = 'none');
    
    // Validate each rule
    for (const [fieldName, fieldRules] of Object.entries(rules)) {
      const input = form.querySelector(`[name="${fieldName}"]`);
      if (!input) continue;
      
      const val = input.value.trim();
      let error = null;
      
      // Rule: required
      if (fieldRules.required && !val) {
        error = `${fieldName} is required`;
      }
      
      // Rule: minLength
      else if (fieldRules.minLength && val.length < fieldRules.minLength) {
        error = `${fieldName} must be at least ${fieldRules.minLength} characters`;
      }
      
      // Rule: email
      else if (fieldRules.email && val && !/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(val)) {
        error = `Please enter a valid email address`;
      }
      
      // Rule: match
      else if (fieldRules.match) {
        const matchInput = form.querySelector(`[name="${fieldRules.match}"]`);
        if (matchInput && val !== matchInput.value.trim()) {
          error = `${fieldName}s do not match`;
        }
      }
      
      // Rule: strong password
      else if (fieldRules.strong && val) {
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/.test(val)) {
          error = `Password must contain uppercase, lowercase, and a number`;
        }
      }
      
      if (error) {
        this.showError(input, error);
        isValid = false;
      }
    }
    
    return isValid;
  },
  
  showError(inputElement, message) {
    inputElement.classList.add('is-invalid');
    inputElement.setAttribute('aria-invalid', 'true');
    
    // Setup ARIA Error element
    let errorEl = inputElement.parentElement.querySelector('.field-error-text');
    if (!errorEl) {
      errorEl = document.createElement('div');
      errorEl.className = 'field-error-text';
      errorEl.setAttribute('role', 'alert');
      
      // Generate ID for aria-describedby
      const errorId = `${inputElement.name}-error`;
      errorEl.id = errorId;
      inputElement.setAttribute('aria-describedby', errorId);
      
      inputElement.parentElement.appendChild(errorEl);
    }
    
    errorEl.textContent = message;
    errorEl.style.display = 'block';
  }
};

window.FormValidator = FormValidator;
