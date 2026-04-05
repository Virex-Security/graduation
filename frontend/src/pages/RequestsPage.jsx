import { useEffect, useState, useMemo, memo } from 'react';
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
  {
    key: 'timestamp',
    label: 'Time',
    sortable: true,
    render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span>,
  },
  {
    key: 'method',
    label: 'Method',
    sortable: true,
    render: (v) => (
      <span className={`font-bold font-mono text-xs ${methodColor[v] || 'text-text-muted'}`}>
        {v ?? '—'}
      </span>
    ),
  },
  {
    key: 'path',
    label: 'Path',
    sortable: false,
    render: (v, row) => (
      <span className="font-mono text-xs text-text-muted" title={row.path}>
        {truncate(v, 60)}
      </span>
    ),
  },
  {
    key: 'source_ip',
    label: 'Source IP',
    sortable: false,
    render: (v) => <span className="font-mono text-xs">{formatIP(v)}</span>,
  },
  {
    key: 'status_code',
    label: 'Status',
    sortable: true,
    render: (v) => {
      const n = Number(v);
      const color =
        n < 300 ? 'text-success' : n < 400 ? 'text-info' : n < 500 ? 'text-warning' : 'text-danger';
      return (
        <span className={`font-mono font-bold text-xs ${color}`}>{v ?? '—'}</span>
      );
    },
  },
  {
    key: 'is_threat',
    label: 'Threat',
    sortable: true,
    getSortValue: (row) => (row.is_threat ? 1 : 0),
    render: (v) =>
      v ? (
        <Badge label="Threat" className="text-danger bg-danger/10 border-danger/30" />
      ) : (
        <Badge label="Clean" className="text-success bg-success/10 border-success/30" />
      ),
  },
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

  const filterConfig = useMemo(() => {
    const methods = [...new Set(data.map((r) => r.method).filter(Boolean))].sort();
    const codes = [...new Set(data.map((r) => r.status_code).filter((c) => c != null && c !== ''))].sort(
      (a, b) => Number(a) - Number(b)
    );

    return [
      {
        id: 'is_threat',
        label: 'Threat',
        field: 'is_threat',
        options: [
          { label: 'All', value: '' },
          { label: 'Threat', value: 'threat' },
          { label: 'Clean', value: 'clean' },
        ],
        match: (row, sel) => {
          if (!sel) return true;
          if (sel === 'threat') return Boolean(row.is_threat);
          if (sel === 'clean') return !row.is_threat;
          return true;
        },
      },
      {
        id: 'method',
        label: 'Method',
        field: 'method',
        options: [{ label: 'All', value: '' }, ...methods.map((m) => ({ label: m, value: m }))],
      },
      {
        id: 'status_code',
        label: 'HTTP status',
        field: 'status_code',
        options: [
          { label: 'All', value: '' },
          ...codes.map((c) => ({ label: String(c), value: String(c) })),
        ],
        match: (row, sel) => {
          if (!sel) return true;
          return String(row.status_code ?? '') === String(sel);
        },
      },
    ];
  }, [data]);

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
          pageSizeOptions={[10, 15, 20, 50]}
          filterConfig={filterConfig}
          emptyMessage="No requests found"
          caption="HTTP request log"
        />
      </InfoCard>
    </div>
  );
});
