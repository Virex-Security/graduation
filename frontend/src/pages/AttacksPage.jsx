import { useEffect, useState, memo } from 'react';
import { InfoCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { getAttackHistory } from '../api/endpoints';
import { formatDate, formatIP, severityClass } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const columns = [
  { key: 'timestamp', label: 'Timestamp', render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span> },
  { key: 'attack_type', label: 'Attack Type', render: (v) => <span className="text-brand-primary font-semibold">{v ?? '—'}</span> },
  { key: 'source_ip', label: 'Source IP', render: (v) => <span className="font-mono text-xs">{formatIP(v)}</span> },
  { key: 'target_path', label: 'Target Path', render: (v) => (
    <span className="font-mono text-xs text-text-muted truncate max-w-[180px] block" title={v}>{v ?? '—'}</span>
  )},
  { key: 'severity', label: 'Severity', render: (v) => <Badge label={v ?? 'Unknown'} className={severityClass(v)} /> },
  { key: 'status', label: 'Status', render: (v) => (
    <span className={`text-xs font-bold capitalize ${v === 'blocked' ? 'text-success' : 'text-warning'}`}>{v ?? '—'}</span>
  )},
  { key: 'ml_score', label: 'ML Score', render: (v) => (
    <span className="font-mono text-xs">{v !== null && v !== undefined ? `${(v * 100).toFixed(1)}%` : '—'}</span>
  )},
];

export default memo(function AttacksPage() {
  const { addToast } = useToast();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAttackHistory()
      .then((r) => setData(Array.isArray(r) ? r : r?.attacks ?? []))
      .catch((e) => addToast(e.message || 'Failed to load attack history', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Attack History</h1>
        <p className="text-text-muted text-sm mt-1">All detected attack events with ML scoring</p>
      </div>

      <InfoCard>
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={15}
          emptyMessage="No attacks detected"
          caption="Attack history table"
        />
      </InfoCard>
    </div>
  );
});
