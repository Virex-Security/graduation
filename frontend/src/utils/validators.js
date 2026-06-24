/**
 * Form validation rules for Virex Dashboard.
 */

export function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email) return 'Email is required';
  if (!re.test(email)) return 'Please enter a valid email address';
  return null;
}

export function validatePassword(password) {
  if (!password) return 'Password is required';
  if (password.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Z]/.test(password)) return 'Password must contain an uppercase letter';
  if (!/[0-9]/.test(password)) return 'Password must contain a number';
  if (!/[^A-Za-z0-9]/.test(password)) return 'Password must contain a special character';
  return null;
}

export function validateRequired(value, fieldName = 'This field') {
  if (!value || (typeof value === 'string' && !value.trim())) {
    return `${fieldName} is required`;
  }
  return null;
}

export function validateIP(ip) {
  if (!ip) return 'IP address is required';
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!v4.test(ip.trim())) return 'Please enter a valid IPv4 address';
  const parts = ip.split('.').map(Number);
  if (parts.some((p) => p > 255)) return 'Each IP octet must be 0–255';
  return null;
}

export function validateMinLength(value, min, fieldName = 'This field') {
  if (!value || value.length < min) return `${fieldName} must be at least ${min} characters`;
  return null;
}

/**
 * Run an object of validators against an object of values.
 * Returns { errors: {field: message}, isValid: boolean }
 */
export function runValidations(rules) {
  const errors = {};
  for (const [field, result] of Object.entries(rules)) {
    if (result) errors[field] = result;
  }
  return { errors, isValid: Object.keys(errors).length === 0 };
}
