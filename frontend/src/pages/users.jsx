import { useEffect, useState, useMemo, memo, useCallback } from 'react';
import {
  UsersIcon,
  UserGroupIcon,
  ShieldCheckIcon,
  ClockIcon,
  UserPlusIcon,
  PencilSquareIcon,
  TrashIcon,
  EyeIcon,
} from '@heroicons/react/24/outline';
import { StatCard } from '../components/Cards';
import DataTable from '../components/DataTable';
import RoleBadge from '../components/RoleBadge';
import StatusBadge from '../components/StatusBadge';
import { PrimaryButton, SecondaryButton, IconButton } from '../components/Buttons';
import Modal, { ConfirmModal } from '../components/Modal';
import { FormField, TextInput, SelectInput } from '../components/Forms';
import { getUsers, updateUser, deleteUser } from '../api/endpoints';
import { formatDate } from '../utils/formatters';
import { useToast } from '../utils/useToast';

function UsersTableCard({ children }) {
  return (
    <section className="overflow-hidden rounded-ds-xl border border-border-dim/70 bg-bg-secondary/35 shadow-ds-card backdrop-blur-md transition-shadow duration-300 hover:shadow-glow-purple/30">
      <div className="border-b border-border-dim/50 bg-brand-primary/[0.06] px-ds-5 py-ds-4 sm:px-ds-6 sm:py-ds-5">
        <h2 className="text-ds-heading font-bold normal-case tracking-normal text-text-primary">
          User directory
        </h2>
        <p className="mt-ds-1 text-ds-caption text-text-muted">
          Roles, status, and last activity. Use actions to view or remove accounts.
        </p>
      </div>
      <div className="p-ds-4 sm:p-ds-6">{children}</div>
    </section>
  );
}

export default memo(function UsersPage() {
  const { addToast } = useToast();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [detailsModalOpen, setDetailsModalOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(null);

  const [form, setForm] = useState({ username: '', email: '', role: 'viewer', password: '' });
  const [submitting, setSubmitting] = useState(false);

  const fetchUsers = useCallback(() => {
    setLoading(true);
    getUsers()
      .then((r) => setData(Array.isArray(r) ? r : r?.users ?? []))
      .catch((e) => addToast(e.message || 'Failed to load users', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const stats = useMemo(() => {
    const counts = { total: data.length, active: 0, admin: 0, online: 0 };
    data.forEach((u) => {
      if (u.status === 'active') counts.active++;
      if (u.role === 'admin') counts.admin++;
      if (u.online) counts.online++;
    });
    return counts;
  }, [data]);

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!form.username || !form.email) return addToast('Required fields missing', 'warning');

    setSubmitting(true);
    try {
      await updateUser('new', form);
      addToast('User created successfully', 'success');
      setModalOpen(false);
      setForm({ username: '', email: '', role: 'viewer', password: '' });
      fetchUsers();
    } catch (e) {
      addToast(e.message || 'Failed to create user', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    setSubmitting(true);
    try {
      await deleteUser(confirmDelete.id);
      addToast('User deleted successfully', 'success');
      setConfirmDelete(null);
      fetchUsers();
    } catch (e) {
      addToast(e.message || 'Failed to delete user', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const columns = [
    {
      key: 'username',
      label: 'User',
      render: (v, row) => (
        <div className="flex items-center gap-ds-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-ds-lg bg-brand-primary/15 text-xs font-bold text-brand-primary shadow-sm ring-1 ring-brand-primary/20 transition-transform duration-200 hover:scale-105">
            {v?.substring(0, 2).toUpperCase()}
          </div>
          <div className="min-w-0 flex flex-col">
            <span className="truncate font-semibold text-ds-body-sm text-text-primary">{v}</span>
            <span className="truncate text-ds-micro text-text-muted">
              {row.full_name || 'No full name'}
            </span>
          </div>
        </div>
      ),
    },
    {
      key: 'email',
      label: 'Email',
      render: (v) => (
        <span className="text-ds-caption text-text-secondary sm:text-ds-body-sm">{v}</span>
      ),
    },
    {
      key: 'role',
      label: 'Role',
      render: (v) => <RoleBadge role={v} />,
    },
    {
      key: 'status',
      label: 'Status',
      render: (v) => <StatusBadge status={v} />,
    },
    {
      key: 'last_login',
      label: 'Last login',
      render: (v) => (
        <span className="whitespace-nowrap font-mono text-ds-caption text-text-muted sm:text-ds-body-sm">
          {v ? formatDate(v) : 'Never'}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      render: (_, row) => (
        <div className="flex flex-wrap items-center gap-ds-1">
          <IconButton
            label="View Details"
            onClick={() => {
              setSelectedUser(row);
              setDetailsModalOpen(true);
            }}
            className="rounded-ds-md transition-colors hover:bg-brand-primary/10 hover:text-brand-primary"
          >
            <EyeIcon className="h-4 w-4" />
          </IconButton>
          <IconButton
            label="Edit"
            onClick={() => addToast('Editing not implemented in demo', 'info')}
            className="rounded-ds-md transition-colors hover:bg-bg-secondary"
          >
            <PencilSquareIcon className="h-4 w-4" />
          </IconButton>
          <IconButton
            label="Delete"
            onClick={() => setConfirmDelete(row)}
            className="rounded-ds-md text-danger transition-colors hover:bg-danger/10"
          >
            <TrashIcon className="h-4 w-4" />
          </IconButton>
        </div>
      ),
    },
  ];

  return (
    <div className="mx-auto max-w-7xl space-y-ds-8 pb-ds-8">
      <header className="flex flex-col gap-ds-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-ds-2">
          <h1 className="text-ds-title font-bold text-text-primary">User management</h1>
          <p className="max-w-xl text-ds-body-sm text-text-muted">
            Manage platform users, roles, and access control.
          </p>
        </div>
        <PrimaryButton
          onClick={() => setModalOpen(true)}
          className="shrink-0 shadow-ds-btn-primary transition hover:shadow-ds-btn-primary-hover"
        >
          <UserPlusIcon className="mr-ds-2 h-4 w-4" />
          Add user
        </PrimaryButton>
      </header>

      <div className="grid grid-cols-1 gap-ds-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-ds-xl p-px transition duration-300 hover:bg-gradient-to-br hover:from-brand-primary/20 hover:to-transparent">
          <StatCard icon={UsersIcon} label="Total users" value={stats.total} accentColor="#9a277d" />
        </div>
        <div className="rounded-ds-xl p-px transition duration-300 hover:bg-gradient-to-br hover:from-success/20 hover:to-transparent">
          <StatCard icon={UserGroupIcon} label="Active users" value={stats.active} accentColor="#10b981" />
        </div>
        <div className="rounded-ds-xl p-px transition duration-300 hover:bg-gradient-to-br hover:from-info/20 hover:to-transparent">
          <StatCard icon={ShieldCheckIcon} label="Administrators" value={stats.admin} accentColor="#3b82f6" />
        </div>
        <div className="rounded-ds-xl p-px transition duration-300 hover:bg-gradient-to-br hover:from-warning/20 hover:to-transparent">
          <StatCard icon={ClockIcon} label="Online now" value={stats.online} accentColor="#f59e0b" />
        </div>
      </div>

      <UsersTableCard>
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={10}
          pageSizeOptions={[10, 15, 25, 50]}
          emptyMessage="No users found."
          caption="User management table"
        />
      </UsersTableCard>

      <Modal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Create new user"
        footer={
          <>
            <SecondaryButton onClick={() => setModalOpen(false)} disabled={submitting}>
              Cancel
            </SecondaryButton>
            <PrimaryButton onClick={handleAdd} loading={submitting}>
              Create user
            </PrimaryButton>
          </>
        }
      >
        <form className="space-y-ds-4">
          <FormField label="Username" id="new-username" required>
            <TextInput
              id="new-username"
              placeholder="jdoe"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
            />
          </FormField>
          <FormField label="Email" id="new-email" required>
            <TextInput
              id="new-email"
              type="email"
              placeholder="john@example.com"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
            />
          </FormField>
          <FormField label="Password" id="new-password" required>
            <TextInput
              id="new-password"
              type="password"
              placeholder="••••••••"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
            />
          </FormField>
          <FormField label="Role" id="new-role">
            <SelectInput
              id="new-role"
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
            >
              <option value="viewer">User</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </SelectInput>
          </FormField>
        </form>
      </Modal>

      <Modal
        isOpen={detailsModalOpen}
        onClose={() => setDetailsModalOpen(false)}
        title={selectedUser ? `${selectedUser.username}'s details` : 'User details'}
        size="lg"
      >
        {selectedUser && (
          <div className="grid grid-cols-1 gap-ds-8 md:grid-cols-2">
            <div className="space-y-ds-4">
              <h4 className="ds-section-label">Account</h4>
              <div className="space-y-ds-3 rounded-ds-lg border border-border-dim/60 bg-bg-main/30 p-ds-4 shadow-inner">
                <div className="flex items-center justify-between gap-ds-4 text-ds-body-sm">
                  <span className="text-text-muted">Username</span>
                  <span className="font-semibold text-text-primary">{selectedUser.username}</span>
                </div>
                <div className="flex items-center justify-between gap-ds-4 text-ds-body-sm">
                  <span className="text-text-muted">Email</span>
                  <span className="truncate text-text-primary">{selectedUser.email}</span>
                </div>
                <div className="flex items-center justify-between gap-ds-4 text-ds-body-sm">
                  <span className="text-text-muted">Role</span>
                  <RoleBadge role={selectedUser.role} />
                </div>
                <div className="flex items-center justify-between gap-ds-4 text-ds-body-sm">
                  <span className="text-text-muted">Status</span>
                  <StatusBadge status={selectedUser.status} />
                </div>
                <div className="flex items-center justify-between gap-ds-4 text-ds-body-sm">
                  <span className="text-text-muted">Created</span>
                  <span className="font-mono text-ds-caption text-text-primary">
                    {formatDate(selectedUser.created_at)}
                  </span>
                </div>
              </div>
            </div>
            <div className="space-y-ds-4">
              <h4 className="ds-section-label">Recent activity</h4>
              <div className="custom-scrollbar max-h-52 space-y-ds-2 overflow-y-auto pr-ds-2">
                {selectedUser.recent_actions?.length > 0 ? (
                  selectedUser.recent_actions.map((act, i) => (
                    <div
                      key={i}
                      className="rounded-ds-md border border-border-dim/40 bg-bg-secondary/50 p-ds-3 text-ds-micro shadow-sm transition hover:border-brand-primary/25 hover:shadow-md"
                    >
                      <div className="mb-ds-1 flex justify-between gap-ds-2">
                        <span className="font-bold uppercase text-brand-primary">{act.action}</span>
                        <span className="shrink-0 text-text-muted">{formatDate(act.timestamp)}</span>
                      </div>
                      <p className="truncate text-text-secondary">{act.details || 'No details provided'}</p>
                    </div>
                  ))
                ) : (
                  <p className="py-ds-8 text-center text-ds-caption text-text-muted">
                    No recent activity detected.
                  </p>
                )}
              </div>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmModal
        isOpen={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={handleDelete}
        title="Delete user"
        message={`Are you sure you want to delete user ${confirmDelete?.username}? This action cannot be undone.`}
        confirmLabel="Delete user"
        danger
        loading={submitting}
      />
    </div>
  );
});
