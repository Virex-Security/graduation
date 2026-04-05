import { useEffect, useState, useMemo, memo, useCallback } from 'react';
import { 
  NoSymbolIcon, 
  MapIcon, 
  GlobeAltIcon, 
  ComputerDesktopIcon,
  PlusIcon,
  PencilSquareIcon,
  TrashIcon
} from '@heroicons/react/24/outline';
import { InfoCard, StatCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { PrimaryButton, SecondaryButton, IconButton } from '../components/Buttons';
import Modal, { ConfirmModal } from '../components/Modal';
import { FormField, TextInput, SelectInput, TextareaInput } from '../components/Forms';
import { getBlacklist, addBlacklist, removeBlacklist } from '../api/endpoints';
import { formatDate } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const typeIcons = {
  ip: MapIcon,
  domain: GlobeAltIcon,
  user_agent: ComputerDesktopIcon,
};

export default memo(function BlacklistPage() {
  const { addToast } = useToast();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);
  
  const [form, setForm] = useState({ type: 'ip', value: '', reason: '', active: true });
  const [submitting, setSubmitting] = useState(false);

  const fetchBlacklist = useCallback(() => {
    setLoading(true);
    getBlacklist()
      .then((r) => setData(Array.isArray(r) ? r : r?.blacklist ?? []))
      .catch((e) => addToast(e.message || 'Failed to load blacklist', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  useEffect(() => {
    fetchBlacklist();
  }, [fetchBlacklist]);

  const stats = useMemo(() => {
    const counts = { total: data.length, ip: 0, domain: 0, user_agent: 0 };
    data.forEach(item => { if (counts[item.type] !== undefined) counts[item.type]++; });
    return counts;
  }, [data]);

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!form.value.trim()) return addToast('Value is required', 'warning');
    
    setSubmitting(true);
    try {
      await addBlacklist(form);
      addToast('Added to blacklist successfully', 'success');
      setModalOpen(false);
      setForm({ type: 'ip', value: '', reason: '', active: true });
      fetchBlacklist();
    } catch (e) {
      addToast(e.message || 'Failed to add entry', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    setSubmitting(true);
    try {
      await removeBlacklist(confirmDelete.value);
      addToast('Removed from blacklist', 'success');
      setConfirmDelete(null);
      fetchBlacklist();
    } catch (e) {
      addToast(e.message || 'Failed to remove entry', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const columns = [
    { key: 'type', label: 'Type', render: (v) => {
      const Icon = typeIcons[v] || NoSymbolIcon;
      return (
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-brand-primary" />
          <span className="capitalize text-xs font-semibold">{v?.replace('_', ' ')}</span>
        </div>
      );
    }},
    { key: 'value', label: 'Value', render: (v) => <span className="font-mono text-xs font-bold text-text-primary">{v}</span> },
    { key: 'reason', label: 'Reason', render: (v) => <span className="text-xs truncate max-w-[150px] block" title={v}>{v || '—'}</span> },
    { key: 'added_by', label: 'Added By', render: (v) => <span className="text-xs">{v || 'System'}</span> },
    { key: 'timestamp', label: 'Date Added', render: (v) => <span className="text-xs">{formatDate(v)}</span> },
    { key: 'active', label: 'Status', render: (v) => (
      <Badge label={v ? 'Active' : 'Inactive'} className={v ? 'text-danger bg-danger/10 border-danger/30' : 'text-text-muted bg-bg-secondary border-border-dim'} />
    )},
    { key: 'actions', label: 'Actions', sortable: false, render: (_, row) => (
      <div className="flex items-center gap-1">
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
          <h1 className="text-2xl font-bold text-text-primary">Blacklist Management</h1>
          <p className="text-text-muted text-sm mt-1">Manage blocked IPs, domains, and user agents</p>
        </div>
        <PrimaryButton onClick={() => setModalOpen(true)}>
          <PlusIcon className="w-4 h-4 mr-2" />
          Add to Blacklist
        </PrimaryButton>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={NoSymbolIcon} label="Total Blacklisted" value={stats.total} accentColor="#ef4444" />
        <StatCard icon={MapIcon} label="Blocked IPs" value={stats.ip} accentColor="#f59e0b" />
        <StatCard icon={GlobeAltIcon} label="Blocked Domains" value={stats.domain} accentColor="#9a277d" />
        <StatCard icon={ComputerDesktopIcon} label="Blocked Agents" value={stats.user_agent} accentColor="#3b82f6" />
      </div>

      <InfoCard>
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={15}
          emptyMessage="Blacklist is empty."
          caption="Blacklist management table"
        />
      </InfoCard>

      {/* Add Modal */}
      <Modal 
        isOpen={modalOpen} 
        onClose={() => setModalOpen(false)} 
        title="Add to Blacklist"
        footer={
          <>
            <SecondaryButton onClick={() => setModalOpen(false)} disabled={submitting}>Cancel</SecondaryButton>
            <PrimaryButton onClick={handleAdd} loading={submitting}>Add Entry</PrimaryButton>
          </>
        }
      >
        <form className="space-y-4">
          <FormField label="Type" id="type">
            <SelectInput 
              id="type" 
              value={form.type} 
              onChange={(e) => setForm({ ...form, type: e.target.value })}
            >
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="user_agent">User Agent</option>
            </SelectInput>
          </FormField>
          
          <FormField label="Value" id="value" required>
            <TextInput 
              id="value" 
              placeholder={form.type === 'ip' ? 'e.g. 192.168.1.1' : form.type === 'domain' ? 'e.g. malicious.com' : 'e.g. BadBot/1.0'}
              value={form.value}
              onChange={(e) => setForm({ ...form, value: e.target.value })}
            />
          </FormField>

          <FormField label="Reason" id="reason">
            <TextareaInput 
              id="reason" 
              placeholder="Why is this being blacklisted?"
              value={form.reason}
              onChange={(e) => setForm({ ...form, reason: e.target.value })}
              rows={3}
            />
          </FormField>

          <div className="flex items-center gap-3 py-2">
            <input 
              type="checkbox" 
              id="active" 
              checked={form.active} 
              onChange={(e) => setForm({ ...form, active: e.target.checked })}
              className="w-4 h-4 rounded border-border-dim bg-bg-secondary text-brand-primary focus:ring-brand-primary"
            />
            <label htmlFor="active" className="text-sm text-text-primary">Active (block immediately)</label>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation */}
      <ConfirmModal
        isOpen={!!confirmDelete}
        onClose={() => setConfirmDelete(null)}
        onConfirm={handleDelete}
        title="Remove from Blacklist"
        message={`Are you sure you want to remove ${confirmDelete?.value} from the blacklist? This will restore access immediately.`}
        confirmLabel="Remove"
        danger
        loading={submitting}
      />
    </div>
  );
});
