import { useEffect, useState, memo } from 'react';
import { Link } from 'react-router-dom';
import { InfoCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { getIncidents } from '../api/endpoints';
import { formatDate, severityClass, statusClass } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const columns = [
  { key: 'id', label: 'ID', sortable: true, render: (v) => (
    <Link to={`/incidents/${v}`} className="text-brand-primary hover:underline font-mono text-xs">#{v}</Link>
  )},
  { key: 'created_at', label: 'Created', render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span> },
  { key: 'title', label: 'Title', render: (v) => <span className="font-semibold text-text-primary">{v ?? '—'}</span> },
  { key: 'severity', label: 'Severity', render: (v) => <Badge label={v ?? 'Unknown'} className={severityClass(v)} /> },
  { key: 'status', label: 'Status', render: (v) => <Badge label={v ?? 'Unknown'} className={statusClass(v)} /> },
  { key: 'assigned_to', label: 'Assigned To', render: (v) => <span className="text-text-muted text-sm">{v ?? 'Unassigned'}</span> },
];

export default memo(function IncidentsPage() {
  const { addToast } = useToast();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getIncidents()
      .then((r) => setData(Array.isArray(r) ? r : r?.incidents ?? []))
      .catch((e) => addToast(e.message || 'Failed to load incidents', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Incidents</h1>
          <p className="text-text-muted text-sm mt-1">Track and manage security incidents</p>
        </div>
      </div>

      <InfoCard>
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={15}
          emptyMessage="No incidents found"
          caption="Security incidents table"
        />
      </InfoCard>
    </div>
  );
});
