import { useEffect, useState, useMemo, memo, useCallback } from 'react';
import { 
  UsersIcon, 
  UserGroupIcon, 
  ShieldCheckIcon, 
  ClockIcon,
  UserPlusIcon,
  PencilSquareIcon,
  TrashIcon,
  EyeIcon
} from '@heroicons/react/24/outline';
import { InfoCard, StatCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { PrimaryButton, SecondaryButton, IconButton } from '../components/Buttons';
import Modal, { ConfirmModal } from '../components/Modal';
import { FormField, TextInput, SelectInput } from '../components/Forms';
import { getUsers, updateUser, deleteUser } from '../api/endpoints';
import { formatDate } from '../utils/formatters';
import { useToast } from '../utils/useToast';

export default memo(function UserManagerPage() {
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
    data.forEach(u => {
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
      // In a real app, this would be a create call
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
    { key: 'username', label: 'User', render: (v, row) => (
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-brand-primary/10 flex items-center justify-center text-brand-primary font-bold text-xs">
          {v?.substring(0, 2).toUpperCase()}
        </div>
        <div className="flex flex-col">
          <span className="font-semibold text-text-primary text-xs">{v}</span>
          <span className="text-[10px] text-text-muted">{row.full_name || 'No full name'}</span>
        </div>
      </div>
    )},
    { key: 'email', label: 'Email', render: (v) => <span className="text-xs">{v}</span> },
    { key: 'role', label: 'Role', render: (v) => (
      <Badge 
        label={v} 
        className={v === 'admin' ? 'text-brand-primary bg-brand-primary/10 border-brand-primary/30' : 'text-info bg-info/10 border-info/30'} 
      />
    )},
    { key: 'status', label: 'Status', render: (v) => (
      <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${v === 'active' ? 'text-success' : 'text-text-muted'}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${v === 'active' ? 'bg-success animate-pulse' : 'bg-text-muted'}`} />
        {v === 'active' ? 'Active' : 'Inactive'}
      </span>
    )},
    { key: 'last_login', label: 'Last Login', render: (v) => <span className="text-xs text-text-muted">{v ? formatDate(v) : 'Never'}</span> },
    { key: 'actions', label: 'Actions', sortable: false, render: (_, row) => (
      <div className="flex items-center gap-1">
        <IconButton label="View Details" onClick={() => { setSelectedUser(row); setDetailsModalOpen(true); }}>
          <EyeIcon className="w-4 h-4" />
        </IconButton>
        <IconButton label="Edit" onClick={() => addToast('Editing not implemented in demo', 'info')}>
          <PencilSquareIcon className="w-4 h-4" />
        </IconButton>
        <IconButton label="Delete" onClick={() => setConfirmDelete(row)} className="text-danger hover:bg-danger/10">
          <TrashIcon className="w-4 h-4" />
        </IconButton>
      </div>
    )},
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">User Management</h1>
          <p className="text-text-muted text-sm mt-1">Manage platform users, roles, and access control</p>
        </div>
        <PrimaryButton onClick={() => setModalOpen(true)}>
          <UserPlusIcon className="w-4 h-4 mr-2" />
          Add New User
        </PrimaryButton>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={UsersIcon} label="Total Users" value={stats.total} accentColor="#9a277d" />
        <StatCard icon={UserGroupIcon} label="Active Users" value={stats.active} accentColor="#10b981" />
        <StatCard icon={ShieldCheckIcon} label="Administrators" value={stats.admin} accentColor="#3b82f6" />
        <StatCard icon={ClockIcon} label="Online Now" value={stats.online} accentColor="#f59e0b" />
      </div>

      <InfoCard>
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={10}
          emptyMessage="No users found."
          caption="User management table"
        />
      </InfoCard>

      {/* Add User Modal */}
      <Modal 
        isOpen={modalOpen} 
        onClose={() => setModalOpen(false)} 
        title="Create New User"
        footer={
          <>
            <SecondaryButton onClick={() => setModalOpen(false)} disabled={submitting}>Cancel</SecondaryButton>
            <PrimaryButton onClick={handleAdd} loading={submitting}>Create User</PrimaryButton>
          </>
        }
      >
        <form className="space-y-4">
          <FormField label="Username" id="new-username" required>
            <TextInput id="new-username" placeholder="jdoe" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </FormField>
          <FormField label="Email" id="new-email" required>
            <TextInput id="new-email" type="email" placeholder="john@example.com" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          </FormField>
          <FormField label="Password" id="new-password" required>
            <TextInput id="new-password" type="password" placeholder="••••••••" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          </FormField>
          <FormField label="Role" id="new-role">
            <SelectInput id="new-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <option value="viewer">Viewer</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </SelectInput>
          </FormField>
        </form>
      </Modal>

      {/* User Details Modal */}
      <Modal
        isOpen={detailsModalOpen}
        onClose={() => setDetailsModalOpen(false)}
        title={selectedUser ? `${selectedUser.username}'s Details` : 'User Details'}
        size="lg"
      >
        {selectedUser && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <h4 className="text-xs font-bold text-text-muted uppercase tracking-widest border-b border-border-dim/50 pb-2">Account Info</h4>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-text-muted">Username:</span>
                  <span className="text-text-primary font-semibold">{selectedUser.username}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-text-muted">Email:</span>
                  <span className="text-text-primary">{selectedUser.email}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-text-muted">Role:</span>
                  <Badge label={selectedUser.role} className="text-info bg-info/10 border-info/30" />
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-text-muted">Created:</span>
                  <span className="text-text-primary text-xs">{formatDate(selectedUser.created_at)}</span>
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <h4 className="text-xs font-bold text-text-muted uppercase tracking-widest border-b border-border-dim/50 pb-2">Recent Activity</h4>
              <div className="max-h-48 overflow-y-auto space-y-2 custom-scrollbar pr-2">
                {selectedUser.recent_actions?.length > 0 ? (
                  selectedUser.recent_actions.map((act, i) => (
                    <div key={i} className="text-[10px] p-2 rounded bg-bg-secondary/50 border border-border-dim/30">
                      <div className="flex justify-between mb-1">
                        <span className="text-brand-primary font-bold uppercase">{act.action}</span>
                        <span className="text-text-muted">{formatDate(act.timestamp)}</span>
                      </div>
                      <p className="text-text-secondary truncate">{act.details || 'No details provided'}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-center text-text-muted text-xs py-8">No recent activity detected.</p>
                )}
              </div>
            </div>
          </div>
        )}
      </Modal>

      {/* Delete Confirmation */}
      <ConfirmModal
        isOpen={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={handleDelete}
        title="Delete User"
        message={`Are you sure you want to delete user ${confirmDelete?.username}? This action cannot be undone.`}
        confirmLabel="Delete User"
        danger
        loading={submitting}
      />
    </div>
  );
});
