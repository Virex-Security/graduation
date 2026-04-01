import React, { useState, memo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { FormField, TextInput } from '../components/Forms';
import { PrimaryButton } from '../components/Buttons';
import { useAuth } from '../utils/useAuth';
import { useToast } from '../utils/useToast';
import { validateRequired, runValidations } from '../utils/validators';

export default memo(function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const { addToast } = useToast();

  const [form, setForm] = useState({ username: '', password: '' });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [showPw, setShowPw] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const { errors: errs, isValid } = runValidations({
      username: validateRequired(form.username, 'Username'),
      password: validateRequired(form.password, 'Password'),
    });
    setErrors(errs);
    if (!isValid) return;

    setLoading(true);
    try {
      await login(form);
      navigate('/dashboard');
    } catch (err) {
      addToast(err.message || 'Login failed. Check your credentials.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg-main flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-4">
            <svg width="48" height="48" viewBox="0 0 100 100" aria-hidden="true">
              <defs>
                <linearGradient id="login-v-left" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#9a277d" /><stop offset="100%" stopColor="#792b9d" />
                </linearGradient>
                <linearGradient id="login-v-right" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#e046ba" /><stop offset="100%" stopColor="#b347e6" />
                </linearGradient>
              </defs>
              <path d="M25,25 L50,80" stroke="url(#login-v-left)" strokeWidth="18" strokeLinecap="round" fill="none" />
              <path d="M50,80 L75,25" stroke="url(#login-v-right)" strokeWidth="18" strokeLinecap="round" fill="none" />
            </svg>
            <span className="brand-text text-3xl">VIREX</span>
          </div>
          <p className="text-text-muted text-sm">Security Intelligence Platform</p>
        </div>

        {/* Card */}
        <div className="card">
          <h1 className="text-xl font-bold text-text-primary normal-case tracking-normal mb-6">Sign In</h1>

          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            <FormField id="login-username" label="Username" required error={errors.username}>
              <TextInput
                id="login-username"
                type="text"
                placeholder="Enter your username"
                autoComplete="username"
                value={form.username}
                error={errors.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
              />
            </FormField>

            <FormField id="login-password" label="Password" required error={errors.password}>
              <div className="relative">
                <TextInput
                  id="login-password"
                  type={showPw ? 'text' : 'password'}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  value={form.password}
                  error={errors.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:opacity-100 opacity-60"
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeSlashIcon className="w-4 h-4" /> : <EyeIcon className="w-4 h-4" />}
                </button>
              </div>
            </FormField>

            <div className="flex justify-end">
              <Link to="/forgot-password" size="sm" className="text-xs text-brand-primary hover:underline">Forgot password?</Link>
            </div>

            <PrimaryButton type="submit" className="w-full mt-2" loading={loading}>
              Sign In
            </PrimaryButton>
          </form>

          <p className="text-center text-sm text-text-muted mt-6">
            Don&apos;t have an account?{' '}
            <Link to="/signup" className="text-brand-primary hover:underline font-medium">Sign Up</Link>
          </p>
        </div>

        <p className="text-center text-xs text-text-muted mt-8 opacity-50">
          Protected by Virex Security Platform
        </p>
      </div>
    </div>
  );
});
