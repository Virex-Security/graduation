import { useState, useCallback, memo } from 'react';
import { UserCircleIcon, ShieldCheckIcon, BellIcon, CpuChipIcon } from '@heroicons/react/24/outline';
import { Cog6ToothIcon } from '@heroicons/react/24/outline';
import { InfoCard } from '../components/Cards';
import { FormField, TextInput, SelectInput } from '../components/Forms';
import { PrimaryButton, SecondaryButton } from '../components/Buttons';
import Modal from '../components/Modal';
import { updateSettings } from '../api/endpoints';
import { useToast } from '../utils/useToast';

function ToggleSwitch({ _id, label, description, checked, onChange }) {
  return (
    <div className="flex items-center justify-between py-4 border-b border-border-dim/50 last:border-0">
      <div>
        <div className="font-medium text-text-primary text-sm">{label}</div>
        <div className="text-xs text-text-muted mt-0.5">{description}</div>
      </div>
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-primary ${
          checked ? 'bg-brand-primary' : 'bg-bg-secondary border border-border-light'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-md transition-transform duration-200 ${
            checked ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
    </div>
  );
}

function SettingRow({ label, description, children }) {
  return (
    <div className="flex items-center justify-between py-4 border-b border-border-dim/50 last:border-0 flex-wrap gap-4">
      <div className="flex-1 min-w-0">
        <div className="font-medium text-text-primary text-sm">{label}</div>
        <div className="text-xs text-text-muted mt-0.5">{description}</div>
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

function SectionHeader({ icon: Icon, title, subtitle, iconColor = 'text-brand-primary' }) {
  return (
    <div className="flex items-center gap-4 mb-6">
      <div className={`w-10 h-10 rounded-xl bg-bg-secondary flex items-center justify-center ${iconColor}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <h2 className="text-base font-bold text-text-primary normal-case tracking-normal">{title}</h2>
        <p className="text-xs text-text-muted">{subtitle}</p>
      </div>
    </div>
  );
}

export default memo(function SettingsPage() {
  const { addToast } = useToast();
  const [saving, setSaving] = useState(false);
  const [profileModalOpen, setProfileModalOpen] = useState(false);

  const [general, setGeneral] = useState({ siteName: 'VIREX', timezone: 'UTC', dateFormat: 'YYYY-MM-DD' });
  const [security, setSecurity] = useState({ sessionTimeout: 30, maxLoginAttempts: 5, passwordExpiry: 90, require2fa: false });
  const [notifications, setNotifications] = useState({ emailAlerts: true, slackIntegration: false, alertThreshold: 'medium' });
  const [ml, setMl] = useState({ autoRetrain: true, confidenceThreshold: 0.85, modelVersion: '2.1.0' });
  const [api] = useState({ rateLimit: 1000, apiKeyExpiry: 365, corsEnabled: false });

  const [profileForm, setProfileForm] = useState({ fullName: '', email: '', department: '', password: '' });

  const handleSave = useCallback(async () => {
    setSaving(true);
    try {
      await updateSettings({ general, security, notifications, ml, api });
      addToast('Settings saved successfully', 'success');
    } catch (e) {
      addToast(e.message || 'Failed to save settings', 'error');
    } finally {
      setSaving(false);
    }
  }, [general, security, notifications, ml, api, addToast]);

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Settings</h1>
          <p className="text-text-muted text-sm mt-1">Configure system preferences and security options</p>
        </div>
      </div>

      {/* Profile Section */}
      <InfoCard>
        <SectionHeader icon={UserCircleIcon} title="Profile Information" subtitle="Your account details and preferences" />
        <div className="flex items-center gap-6 flex-wrap">
          <div className="w-16 h-16 rounded-2xl bg-brand-primary/20 flex items-center justify-center text-brand-primary font-black text-xl">US</div>
          <div className="flex-1">
            <div className="font-bold text-text-primary">User</div>
            <div className="text-text-muted text-sm">Administrator</div>
          </div>
          <SecondaryButton onClick={() => setProfileModalOpen(true)}>Edit Profile</SecondaryButton>
        </div>
      </InfoCard>

      {/* General Settings */}
      <InfoCard>
        <SectionHeader icon={Cog6ToothIcon} title="General" subtitle="Basic system configuration" />
        <SettingRow label="Site Name" description="Display name for the application">
          <TextInput id="site-name" value={general.siteName} onChange={(e) => setGeneral({ ...general, siteName: e.target.value })} className="w-44" />
        </SettingRow>
        <SettingRow label="Timezone" description="Default timezone for timestamps">
          <SelectInput id="timezone" value={general.timezone} onChange={(e) => setGeneral({ ...general, timezone: e.target.value })} className="w-44">
            <option value="UTC">UTC</option>
            <option value="America/New_York">Eastern Time</option>
            <option value="America/Los_Angeles">Pacific Time</option>
            <option value="Europe/London">London</option>
            <option value="Asia/Dubai">Dubai</option>
          </SelectInput>
        </SettingRow>
        <SettingRow label="Date Format" description="How dates are displayed">
          <SelectInput id="date-format" value={general.dateFormat} onChange={(e) => setGeneral({ ...general, dateFormat: e.target.value })} className="w-44">
            <option value="YYYY-MM-DD">YYYY-MM-DD</option>
            <option value="DD/MM/YYYY">DD/MM/YYYY</option>
            <option value="MM/DD/YYYY">MM/DD/YYYY</option>
          </SelectInput>
        </SettingRow>
      </InfoCard>

      {/* Security Settings */}
      <InfoCard>
        <SectionHeader icon={ShieldCheckIcon} title="Security" subtitle="Authentication and access control" iconColor="text-danger" />
        <SettingRow label="Session Timeout (min)" description="Minutes before auto-logout">
          <TextInput id="session-timeout" type="number" min={5} max={120} value={security.sessionTimeout}
            onChange={(e) => setSecurity({ ...security, sessionTimeout: Number(e.target.value) })} className="w-28" />
        </SettingRow>
        <SettingRow label="Max Login Attempts" description="Failed attempts before lockout">
          <TextInput id="max-login-attempts" type="number" min={3} max={10} value={security.maxLoginAttempts}
            onChange={(e) => setSecurity({ ...security, maxLoginAttempts: Number(e.target.value) })} className="w-28" />
        </SettingRow>
        <ToggleSwitch id="require-2fa" label="Require 2FA" description="Force two-factor authentication for all users"
          checked={security.require2fa} onChange={(v) => setSecurity({ ...security, require2fa: v })} />
      </InfoCard>

      {/* Notifications */}
      <InfoCard>
        <SectionHeader icon={BellIcon} title="Notifications" subtitle="Alert and notification preferences" iconColor="text-info" />
        <ToggleSwitch id="email-alerts" label="Email Alerts" description="Send security alerts via email"
          checked={notifications.emailAlerts} onChange={(v) => setNotifications({ ...notifications, emailAlerts: v })} />
        <ToggleSwitch id="slack-integration" label="Slack Integration" description="Post alerts to Slack channel"
          checked={notifications.slackIntegration} onChange={(v) => setNotifications({ ...notifications, slackIntegration: v })} />
        <SettingRow label="Alert Threshold" description="Minimum severity for notifications">
          <SelectInput id="alert-threshold" value={notifications.alertThreshold}
            onChange={(e) => setNotifications({ ...notifications, alertThreshold: e.target.value })} className="w-36">
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </SelectInput>
        </SettingRow>
      </InfoCard>

      {/* ML Model */}
      <InfoCard>
        <SectionHeader icon={CpuChipIcon} title="ML Model" subtitle="Machine learning configuration" iconColor="text-brand-primary" />
        <ToggleSwitch id="auto-retrain" label="Auto Retrain" description="Automatically retrain model with new data"
          checked={ml.autoRetrain} onChange={(v) => setMl({ ...ml, autoRetrain: v })} />
        <SettingRow label="Confidence Threshold" description="Minimum confidence for ML detection">
          <TextInput id="confidence-threshold" type="number" min={0.5} max={1} step={0.05} value={ml.confidenceThreshold}
            onChange={(e) => setMl({ ...ml, confidenceThreshold: Number(e.target.value) })} className="w-28" />
        </SettingRow>
        <SettingRow label="Model Version" description="Current ML model version">
          <TextInput id="model-version" value={ml.modelVersion} readOnly className="w-24 opacity-60 cursor-not-allowed" />
        </SettingRow>
      </InfoCard>

      {/* Save Actions */}
      <div className="flex items-center justify-end gap-4 pb-6">
        <SecondaryButton onClick={() => window.location.reload()}>Reset</SecondaryButton>
        <PrimaryButton onClick={handleSave} loading={saving}>Save Changes</PrimaryButton>
      </div>

      {/* Edit Profile Modal */}
      <Modal
        isOpen={profileModalOpen}
        onClose={() => setProfileModalOpen(false)}
        title="Edit Profile"
        footer={
          <>
            <SecondaryButton onClick={() => setProfileModalOpen(false)}>Cancel</SecondaryButton>
            <PrimaryButton onClick={() => { addToast('Profile saved', 'success'); setProfileModalOpen(false); }}>Save Changes</PrimaryButton>
          </>
        }
      >
        <div className="space-y-4">
          <FormField id="edit-fullname" label="Full Name">
            <TextInput id="edit-fullname" placeholder="Enter full name"
              value={profileForm.fullName} onChange={(e) => setProfileForm({ ...profileForm, fullName: e.target.value })} />
          </FormField>
          <FormField id="edit-email" label="Email">
            <TextInput id="edit-email" type="email" placeholder="Enter email"
              value={profileForm.email} onChange={(e) => setProfileForm({ ...profileForm, email: e.target.value })} />
          </FormField>
          <FormField id="edit-department" label="Department">
            <SelectInput id="edit-department" value={profileForm.department}
              onChange={(e) => setProfileForm({ ...profileForm, department: e.target.value })}>
              <option value="">Select department</option>
              <option>Security Analyst</option>
              <option>Security Engineer</option>
              <option>DevOps Engineer</option>
              <option>System Administrator</option>
              <option>IT Manager</option>
              <option>CISO</option>
              <option>CTO</option>
            </SelectInput>
          </FormField>
          <FormField id="edit-password" label="Change Password" hint="Leave empty to keep current password">
            <TextInput id="edit-password" type="password" placeholder="New password (optional)"
              value={profileForm.password} onChange={(e) => setProfileForm({ ...profileForm, password: e.target.value })} />
          </FormField>
        </div>
      </Modal>
    </div>
  );
});
