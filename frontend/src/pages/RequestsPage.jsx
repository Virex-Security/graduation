import { useEffect, useState, memo } from 'react';
import { InfoCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { getAllRequests } from '../api/endpoints';
import { formatDate, formatIP, truncate } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const methodColor = {
  GET: 'text-info',
  POST: 'text-success',
  PUT: 'text-warning',
  DELETE: 'text-danger',
  PATCH: 'text-brand-primary',
};

const columns = [
  { key: 'timestamp', label: 'Time', render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span> },
  { key: 'method', label: 'Method', render: (v) => (
    <span className={`font-bold font-mono text-xs ${methodColor[v] || 'text-text-muted'}`}>{v ?? '—'}</span>
  )},
  { key: 'path', label: 'Path', render: (v) => (
    <span className="font-mono text-xs text-text-muted" title={v}>{truncate(v, 60)}</span>
  )},
  { key: 'source_ip', label: 'Source IP', render: (v) => <span className="font-mono text-xs">{formatIP(v)}</span> },
  { key: 'status_code', label: 'Status', render: (v) => {
    const n = Number(v);
    const color = n < 300 ? 'text-success' : n < 400 ? 'text-info' : n < 500 ? 'text-warning' : 'text-danger';
    return <span className={`font-mono font-bold text-xs ${color}`}>{v ?? '—'}</span>;
  }},
  { key: 'is_threat', label: 'Threat', render: (v) => (
    v ? <Badge label="Threat" className="text-danger bg-danger/10 border-danger/30" />
      : <Badge label="Clean" className="text-success bg-success/10 border-success/30" />
  )},
];

export default memo(function RequestsPage() {
  const { addToast } = useToast();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAllRequests()
      .then((r) => setData(Array.isArray(r) ? r : r?.requests ?? []))
      .catch((e) => addToast(e.message || 'Failed to load requests', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">All Requests</h1>
        <p className="text-text-muted text-sm mt-1">Complete HTTP request log with threat classification</p>
      </div>

      <InfoCard>
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={20}
          emptyMessage="No requests found"
          caption="HTTP request log"
        />
      </InfoCard>
    </div>
  );
});
