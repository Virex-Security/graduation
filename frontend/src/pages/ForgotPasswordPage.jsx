import React, { useState, memo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { 
  KeyIcon, 
  UserIcon, 
  ArrowLeftIcon,
  ShieldCheckIcon,
  EyeIcon,
  EyeSlashIcon,
  ArrowPathIcon
} from '@heroicons/react/24/outline';
import { FormField, TextInput } from '../components/Forms';
import { PrimaryButton, SecondaryButton } from '../components/Buttons';
import { requestResetOtp, verifyResetOtp } from '../api/endpoints';
import { useToast } from '../utils/useToast';
import { validateRequired, runValidations } from '../utils/validators';

export default memo(function ForgotPasswordPage() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  
  const [step, setStep] = useState(1); // 1: request OTP, 2: verify & reset
  const [loading, setLoading] = useState(false);
  const [showPw, setShowPw] = useState(false);
  
  const [identifier, setIdentifier] = useState('');
  const [userId, setUserId] = useState(null);
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [errors, setErrors] = useState({});

  const handleRequestOtp = async (e) => {
    e.preventDefault();
    if (!identifier.trim()) {
      setErrors({ identifier: 'Username or email is required' });
      return;
    }
    
    setLoading(true);
    setErrors({});
    try {
      const data = await requestResetOtp(identifier);
      setUserId(data.user_id);
      setStep(2);
      addToast('OTP has been sent to your registered email', 'success');
    } catch (err) {
      addToast(err.message || 'Failed to request password reset', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    const { errors: errs, isValid } = runValidations({
      otp: validateRequired(otp, 'OTP'),
      newPassword: validateRequired(newPassword, 'New Password'),
    });
    setErrors(errs);
    if (!isValid) return;

    if (!userId) {
      addToast('Session expired. Please request a new OTP.', 'error');
      setStep(1);
      return;
    }

    setLoading(true);
    try {
      await verifyResetOtp({ 
        user_id: userId, 
        otp, 
        new_password: newPassword 
      });
      addToast('Password reset successful!', 'success');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      addToast(err.message || 'Failed to reset password. Check your OTP.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-bg-main flex items-center justify-center p-4 relative overflow-hidden">
      {/* Abstract Background patterns */}
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] bg-brand-primary/5 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] bg-brand-secondary/5 rounded-full blur-[120px] pointer-events-none" />

      <div className="w-full max-w-sm relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-6">
            <svg width="60" height="60" viewBox="0 0 100 100" className="drop-shadow-[0_0_15px_rgba(224,70,186,0.3)]">
              <defs>
                <linearGradient id="fp-v-left" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#9a277d" /><stop offset="100%" stopColor="#792b9d" />
                </linearGradient>
                <linearGradient id="fp-v-right" x1="0%" y1="0%" x2="0%" y2="100%">
                  <stop offset="0%" stopColor="#e046ba" /><stop offset="100%" stopColor="#b347e6" />
                </linearGradient>
              </defs>
              <path d="M25,25 L50,80" stroke="url(#fp-v-left)" strokeWidth="18" strokeLinecap="round" fill="none" />
              <path d="M50,80 L75,25" stroke="url(#fp-v-right)" strokeWidth="18" strokeLinecap="round" fill="none" />
            </svg>
          </div>
          <h1 className="text-3xl font-black text-text-primary tracking-tight mb-2 uppercase">Forgot Password</h1>
          <p className="text-text-muted text-sm">Reset your VIREX Security account password</p>
        </div>

        {/* Form Card */}
        <div className="card shadow-2xl border border-white/5">
          {step === 1 ? (
            <form onSubmit={handleRequestOtp} className="space-y-6">
              <FormField id="identifier" label="Username or Email" error={errors.identifier}>
                <div className="relative">
                  <TextInput
                    id="identifier"
                    placeholder="Enter your username or email"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    className="pl-10"
                    error={errors.identifier}
                  />
                  <UserIcon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                </div>
              </FormField>

              <PrimaryButton type="submit" className="w-full h-11" loading={loading}>
                Get OTP
              </PrimaryButton>
            </form>
          ) : (
            <form onSubmit={handleResetPassword} className="space-y-6">
              <FormField id="otp" label="OTP" error={errors.otp}>
                <div className="relative">
                  <TextInput
                    id="otp"
                    placeholder="6-digit code"
                    maxLength={6}
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                    className="pl-10 font-mono tracking-widest text-center"
                    error={errors.otp}
                  />
                  <KeyIcon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                </div>
              </FormField>

              <FormField id="new-password" label="New Password" error={errors.newPassword}>
                <div className="relative">
                  <TextInput
                    id="new-password"
                    type={showPw ? 'text' : 'password'}
                    placeholder="••••••••••••"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="pl-10 pr-10"
                    error={errors.newPassword}
                  />
                  <ShieldCheckIcon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                  <button
                    type="button"
                    onClick={() => setShowPw(!showPw)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary transition-colors"
                  >
                    {showPw ? <EyeSlashIcon className="w-4 h-4" /> : <EyeIcon className="w-4 h-4" />}
                  </button>
                </div>
              </FormField>

              <div className="space-y-3">
                <PrimaryButton type="submit" className="w-full h-11" loading={loading}>
                  Reset Password
                </PrimaryButton>
                <SecondaryButton 
                  type="button" 
                  className="w-full h-11" 
                  onClick={() => setStep(1)}
                  disabled={loading}
                >
                  <ArrowPathIcon className="w-4 h-4 mr-2" />
                  Change Identifier
                </SecondaryButton>
              </div>
            </form>
          )}

          <div className="mt-8 pt-6 border-t border-white/5 text-center">
            <Link to="/login" className="inline-flex items-center gap-2 text-sm font-medium text-brand-primary hover:text-brand-secondary transition-colors">
              <ArrowLeftIcon className="w-4 h-4" />
              Back to Sign In
            </Link>
          </div>
        </div>

        <p className="text-center text-ds-micro text-text-muted/40 mt-ds-8 uppercase tracking-ds-widest">
          Protected by VIREX AI/ML Engine
        </p>
      </div>
    </div>
  );
});
