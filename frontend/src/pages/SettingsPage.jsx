import { useState, useCallback, memo, useId } from 'react';
import {
  UserCircleIcon,
  ShieldCheckIcon,
  BellIcon,
  CpuChipIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline';
import { FormField, TextInput, SelectInput } from '../components/Forms';
import { PrimaryButton, SecondaryButton } from '../components/Buttons';
import Modal from '../components/Modal';
import ToggleSwitch, { InfoTooltip } from '../components/ToggleSwitch';
import { updateSettings } from '../api/endpoints';
import { useToast } from '../utils/useToast';

function SettingRow({ id, label, description, tooltip, children }) {
  const autoRowId = useId();
  const rowId = id ?? autoRowId;
  return (
    <div className="flex flex-col gap-ds-3 py-ds-5 sm:flex-row sm:items-center sm:justify-between sm:gap-ds-8">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-ds-2">
          <span className="text-ds-body-sm font-medium text-text-primary" id={`${rowId}-label`}>
            {label}
          </span>
          <InfoTooltip text={tooltip} />
        </div>
        {description ? (
          <p className="mt-ds-1 text-ds-caption text-text-muted">{description}</p>
        ) : null}
      </div>
      <div className="flex shrink-0 items-center sm:justify-end">{children}</div>
    </div>
  );
}

function SectionHeader({ icon: Icon, title, subtitle, iconColor = 'text-brand-primary' }) {
  return (
    <div className="flex items-start gap-ds-4">
      <div
        className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-ds-lg border border-border-dim/60 bg-bg-main/50 ${iconColor}`}
      >
        <Icon className="h-5 w-5" aria-hidden />
      </div>
      <div className="min-w-0 pt-0.5">
        <h2 className="text-ds-heading font-bold normal-case tracking-normal text-text-primary">
          {title}
        </h2>
        <p className="mt-ds-1 text-ds-caption text-text-muted">{subtitle}</p>
      </div>
    </div>
  );
}

/** Card shell: glassy panel + subtle shadow, matches Virex design tokens */
function SettingsSectionCard({ children, className = '' }) {
  return (
    <section
      className={`overflow-hidden rounded-ds-xl border border-border-dim/70 bg-bg-secondary/35 shadow-ds-card backdrop-blur-md ${className}`}
    >
      {children}
    </section>
  );
}

export default memo(function SettingsPage() {
  const { addToast } = useToast();
  const [saving, setSaving] = useState(false);
  const [profileModalOpen, setProfileModalOpen] = useState(false);

  const [general, setGeneral] = useState({ siteName: 'VIREX', timezone: 'UTC', dateFormat: 'YYYY-MM-DD' });
  const [security, setSecurity] = useState({
    sessionTimeout: 30,
    maxLoginAttempts: 5,
    passwordExpiry: 90,
    require2fa: false,
  });
  const [notifications, setNotifications] = useState({
    emailAlerts: true,
    slackIntegration: false,
    alertThreshold: 'medium',
  });
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
    <div className="mx-auto max-w-4xl space-y-ds-8 pb-ds-10">
      <header className="space-y-ds-2">
        <h1 className="text-ds-title font-bold text-text-primary">Settings</h1>
        <p className="max-w-2xl text-ds-body-sm text-text-muted">
          Configure system preferences, security, notifications, and ML behavior. Changes apply after you save.
        </p>
      </header>

      {/* Profile */}
      <SettingsSectionCard>
        <div className="border-b border-border-dim/50 bg-brand-primary/[0.06] px-ds-6 py-ds-5">
          <SectionHeader
            icon={UserCircleIcon}
            title="Profile"
            subtitle="Account details and quick edits"
          />
        </div>
        <div className="px-ds-6 py-ds-6">
          <div className="flex flex-col gap-ds-6 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-ds-5">
              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-ds-xl bg-brand-primary/20 text-xl font-black text-brand-primary">
                US
              </div>
              <div>
                <div className="font-bold text-text-primary">User</div>
                <div className="text-ds-caption text-text-muted">Administrator</div>
              </div>
            </div>
            <SecondaryButton onClick={() => setProfileModalOpen(true)}>Edit profile</SecondaryButton>
          </div>
        </div>
      </SettingsSectionCard>

      {/* General */}
      <SettingsSectionCard>
        <div className="border-b border-border-dim/50 bg-brand-primary/[0.06] px-ds-6 py-ds-5">
          <SectionHeader
            icon={Cog6ToothIcon}
            title="General"
            subtitle="Basic system configuration"
          />
        </div>
        <div className="divide-y divide-border-dim/40 px-ds-6">
          <SettingRow
            id="site-name-row"
            label="Site name"
            description="Shown in the UI and notification footers."
            tooltip="Used as the display name across the dashboard header and exported reports."
          >
            <TextInput
              id="site-name"
              value={general.siteName}
              onChange={(e) => setGeneral({ ...general, siteName: e.target.value })}
              className="w-full min-w-[12rem] sm:w-52"
              aria-labelledby="site-name-row-label"
            />
          </SettingRow>
          <SettingRow
            id="timezone-row"
            label="Timezone"
            description="Default zone for timestamps and schedules."
            tooltip="Applies to incident timelines, logs, and scheduled reports."
          >
            <SelectInput
              id="timezone"
              value={general.timezone}
              onChange={(e) => setGeneral({ ...general, timezone: e.target.value })}
              className="w-full min-w-[12rem] sm:w-52"
            >
              <option value="UTC">UTC</option>
              <option value="America/New_York">Eastern Time</option>
              <option value="America/Los_Angeles">Pacific Time</option>
              <option value="Europe/London">London</option>
              <option value="Asia/Dubai">Dubai</option>
            </SelectInput>
          </SettingRow>
          <SettingRow
            id="date-format-row"
            label="Date format"
            description="How dates appear in tables and exports."
            tooltip="Does not change stored data—only display and CSV/ PDF exports."
          >
            <SelectInput
              id="date-format"
              value={general.dateFormat}
              onChange={(e) => setGeneral({ ...general, dateFormat: e.target.value })}
              className="w-full min-w-[12rem] sm:w-52"
            >
              <option value="YYYY-MM-DD">YYYY-MM-DD</option>
              <option value="DD/MM/YYYY">DD/MM/YYYY</option>
              <option value="MM/DD/YYYY">MM/DD/YYYY</option>
            </SelectInput>
          </SettingRow>
        </div>
      </SettingsSectionCard>

      {/* Security */}
      <SettingsSectionCard>
        <div className="border-b border-border-dim/50 bg-brand-primary/[0.06] px-ds-6 py-ds-5">
          <SectionHeader
            icon={ShieldCheckIcon}
            title="Security"
            subtitle="Authentication and session policy"
            iconColor="text-danger"
          />
        </div>
        <div className="divide-y divide-border-dim/40 px-ds-6">
          <SettingRow
            label="Session timeout (minutes)"
            description="Idle time before users are signed out."
            tooltip="Lower values reduce risk on shared workstations; higher values improve convenience."
          >
            <TextInput
              id="session-timeout"
              type="number"
              min={5}
              max={120}
              value={security.sessionTimeout}
              onChange={(e) => setSecurity({ ...security, sessionTimeout: Number(e.target.value) })}
              className="w-full min-w-[6rem] sm:w-32"
            />
          </SettingRow>
          <SettingRow
            label="Max login attempts"
            description="Failed attempts before the account is temporarily locked."
            tooltip="Helps mitigate brute-force attacks against the login endpoint."
          >
            <TextInput
              id="max-login-attempts"
              type="number"
              min={3}
              max={10}
              value={security.maxLoginAttempts}
              onChange={(e) => setSecurity({ ...security, maxLoginAttempts: Number(e.target.value) })}
              className="w-full min-w-[6rem] sm:w-32"
            />
          </SettingRow>
          <ToggleSwitch
            id="require-2fa"
            label="Require 2FA"
            description="Require a second factor for every user account."
            tooltip="When enabled, users must enroll TOTP or hardware keys before accessing the console."
            checked={security.require2fa}
            onChange={(v) => setSecurity({ ...security, require2fa: v })}
          />
        </div>
      </SettingsSectionCard>

      {/* Notifications */}
      <SettingsSectionCard>
        <div className="border-b border-border-dim/50 bg-brand-primary/[0.06] px-ds-6 py-ds-5">
          <SectionHeader
            icon={BellIcon}
            title="Notifications"
            subtitle="Alerts and external channels"
            iconColor="text-info"
          />
        </div>
        <div className="divide-y divide-border-dim/40 px-ds-6">
          <ToggleSwitch
            id="email-alerts"
            label="Email alerts"
            description="Send security notifications to configured inboxes."
            tooltip="Critical and high-severity events are emailed immediately when this is on."
            checked={notifications.emailAlerts}
            onChange={(v) => setNotifications({ ...notifications, emailAlerts: v })}
          />
          <ToggleSwitch
            id="slack-integration"
            label="Slack integration"
            description="Mirror alerts to a Slack workspace webhook."
            tooltip="Requires a valid webhook URL in your environment configuration."
            checked={notifications.slackIntegration}
            onChange={(v) => setNotifications({ ...notifications, slackIntegration: v })}
          />
          <SettingRow
            label="Alert threshold"
            description="Minimum severity that generates a notification."
            tooltip="Events below this level are logged only and do not trigger email or Slack."
          >
            <SelectInput
              id="alert-threshold"
              value={notifications.alertThreshold}
              onChange={(e) => setNotifications({ ...notifications, alertThreshold: e.target.value })}
              className="w-full min-w-[10rem] sm:w-40"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </SelectInput>
          </SettingRow>
        </div>
      </SettingsSectionCard>

      {/* ML */}
      <SettingsSectionCard>
        <div className="border-b border-border-dim/50 bg-brand-primary/[0.06] px-ds-6 py-ds-5">
          <SectionHeader
            icon={CpuChipIcon}
            title="ML model"
            subtitle="Detection engine parameters"
            iconColor="text-brand-primary"
          />
        </div>
        <div className="divide-y divide-border-dim/40 px-ds-6">
          <ToggleSwitch
            id="auto-retrain"
            label="Auto retrain"
            description="Periodically retrain models when enough new labeled data exists."
            tooltip="Increases accuracy over time but uses additional compute during the retrain window."
            checked={ml.autoRetrain}
            onChange={(v) => setMl({ ...ml, autoRetrain: v })}
          />
          <SettingRow
            label="Confidence threshold"
            description="Minimum model score to flag traffic as suspicious."
            tooltip="Higher values reduce false positives but may miss subtle attacks."
          >
            <TextInput
              id="confidence-threshold"
              type="number"
              min={0.5}
              max={1}
              step={0.05}
              value={ml.confidenceThreshold}
              onChange={(e) => setMl({ ...ml, confidenceThreshold: Number(e.target.value) })}
              className="w-full min-w-[6rem] sm:w-32"
            />
          </SettingRow>
          <SettingRow
            label="Model version"
            description="Currently deployed classifier version (read-only)."
            tooltip="Updates when operations deploy a new model package."
          >
            <TextInput
              id="model-version"
              value={ml.modelVersion}
              readOnly
              className="w-full min-w-[6rem] cursor-not-allowed opacity-70 sm:w-32"
            />
          </SettingRow>
        </div>
      </SettingsSectionCard>

      <div className="flex flex-col-reverse gap-ds-3 sm:flex-row sm:items-center sm:justify-end sm:gap-ds-4">
        <SecondaryButton onClick={() => window.location.reload()}>Reset</SecondaryButton>
        <PrimaryButton onClick={handleSave} loading={saving}>
          Save changes
        </PrimaryButton>
      </div>

      <Modal
        isOpen={profileModalOpen}
        onClose={() => setProfileModalOpen(false)}
        title="Edit Profile"
        footer={
          <>
            <SecondaryButton onClick={() => setProfileModalOpen(false)}>Cancel</SecondaryButton>
            <PrimaryButton
              onClick={() => {
                addToast('Profile saved', 'success');
                setProfileModalOpen(false);
              }}
            >
              Save changes
            </PrimaryButton>
          </>
        }
      >
        <div className="space-y-ds-4">
          <FormField id="edit-fullname" label="Full Name">
            <TextInput
              id="edit-fullname"
              placeholder="Enter full name"
              value={profileForm.fullName}
              onChange={(e) => setProfileForm({ ...profileForm, fullName: e.target.value })}
            />
          </FormField>
          <FormField id="edit-email" label="Email">
            <TextInput
              id="edit-email"
              type="email"
              placeholder="Enter email"
              value={profileForm.email}
              onChange={(e) => setProfileForm({ ...profileForm, email: e.target.value })}
            />
          </FormField>
          <FormField id="edit-department" label="Department">
            <SelectInput
              id="edit-department"
              value={profileForm.department}
              onChange={(e) => setProfileForm({ ...profileForm, department: e.target.value })}
            >
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
            <TextInput
              id="edit-password"
              type="password"
              placeholder="New password (optional)"
              value={profileForm.password}
              onChange={(e) => setProfileForm({ ...profileForm, password: e.target.value })}
            />
          </FormField>
        </div>
      </Modal>
    </div>
  );
});
