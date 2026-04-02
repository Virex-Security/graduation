import { useEffect, useState, useMemo, memo } from 'react';
import { Link } from 'react-router-dom';
import { InfoCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { getIncidents } from '../api/endpoints';
import { formatDate, severityClass, statusClass } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const TYPE_KEYS = ['incident_type', 'attack_type', 'type', 'category'];

const columns = [
  {
    key: 'id',
    label: 'ID',
    sortable: true,
    render: (v) => (
      <Link to={`/incidents/${v}`} className="text-brand-primary hover:underline font-mono text-xs">
        #{v}
      </Link>
    ),
  },
  {
    key: 'created_at',
    label: 'Created',
    sortable: true,
    render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span>,
  },
  {
    key: 'title',
    label: 'Title',
    sortable: true,
    render: (v) => <span className="font-semibold text-text-primary">{v ?? '—'}</span>,
  },
  {
    key: 'severity',
    label: 'Severity',
    sortable: true,
    render: (v) => <Badge label={v ?? 'Unknown'} className={severityClass(v)} />,
  },
  {
    key: 'status',
    label: 'Status',
    sortable: true,
    render: (v) => <Badge label={v ?? 'Unknown'} className={statusClass(v)} />,
  },
  {
    key: 'assigned_to',
    label: 'Assigned To',
    sortable: true,
    render: (v) => <span className="text-text-muted text-sm">{v ?? 'Unassigned'}</span>,
  },
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

  const incidentTypeField = useMemo(() => {
    for (const k of TYPE_KEYS) {
      if (data.some((r) => r[k] != null && r[k] !== '')) return k;
    }
    return null;
  }, [data]);

  const filterConfig = useMemo(() => {
    const severities = [...new Set(data.map((r) => r.severity).filter(Boolean))].sort();
    const statuses = [...new Set(data.map((r) => r.status).filter(Boolean))].sort();

    const filters = [
      {
        id: 'severity',
        label: 'Severity',
        field: 'severity',
        options: [
          { label: 'All', value: '' },
          ...severities.map((s) => ({ label: s, value: s })),
        ],
      },
      {
        id: 'status',
        label: 'Status',
        field: 'status',
        options: [
          { label: 'All', value: '' },
          ...statuses.map((s) => ({ label: s, value: s })),
        ],
      },
    ];

    if (incidentTypeField) {
      const types = [...new Set(data.map((r) => r[incidentTypeField]).filter(Boolean))].sort();
      filters.push({
        id: 'incident_type',
        label: 'Type',
        field: incidentTypeField,
        options: [
          { label: 'All', value: '' },
          ...types.map((t) => ({ label: String(t), value: String(t) })),
        ],
      });
    }

    return filters;
  }, [data, incidentTypeField]);

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
          pageSizeOptions={[10, 15, 20, 50]}
          filterConfig={filterConfig}
          emptyMessage="No incidents found"
          caption="Security incidents table"
        />
      </InfoCard>
    </div>
  );
});
