import { useEffect, useState, useMemo, memo } from 'react';
import { StatCard, InfoCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { getAllRequests, getSecurityStats } from '../api/endpoints';
import { formatDate, formatIP, truncate } from '../utils/formatters';
import { useToast } from '../utils/useToast';
import { ChevronLeftIcon, ChevronRightIcon, GlobeAltIcon, ExclamationTriangleIcon, ShieldCheckIcon, CheckCircleIcon } from '@heroicons/react/24/outline';

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
    key: 'attack_type',
    label: 'Type',
    sortable: true,
    render: (v, row) => {
      const type = v || row.type || 'Clean';
      const isClean = String(type).toLowerCase() === 'clean';
      return (
        <Badge
          label={type}
          className={
            isClean
              ? 'text-success bg-success/10 border-success/30'
              : 'text-warning bg-warning/10 border-warning/30'
          }
        />
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
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [stats, setStats] = useState(null);
  const [activeFilter, setActiveFilter] = useState('all');

  useEffect(() => {
    getSecurityStats()
      .then(setStats)
      .catch(() => {});
  }, [currentPage, activeFilter]);

  useEffect(() => {
    setLoading(true);
    getAllRequests(currentPage, pageSize, activeFilter)
      .then((r) => {
        setData(r?.requests ?? []);
        setTotalCount(r?.totalCount ?? 0);
        setTotalPages(r?.totalPages ?? 1);
      })
      .catch((e) => addToast(e.message || 'Failed to load requests', 'error'))
      .finally(() => setLoading(false));
  }, [currentPage, pageSize, activeFilter, addToast]);

  const filters = [
    { id: 'all', label: 'All' },
    { id: 'clean', label: 'Clean' },
    { id: 'sqli', label: 'SQLi' },
    { id: 'xss', label: 'XSS' },
    { id: 'brute', label: 'Brute Force' },
    { id: 'scanner', label: 'Scanner' },
    { id: 'rate', label: 'Rate Limit' },
    { id: 'csrf', label: 'CSRF' },
    { id: 'ssrf', label: 'SSRF' },
    { id: 'path', label: 'Path Traversal' },
    { id: 'blocked', label: 'Blocked' },
  ];

  const kpiCards = [
    {
      icon: GlobeAltIcon,
      label: 'Total Requests',
      value: stats?.total_requests != null ? Number(stats.total_requests).toLocaleString() : '0',
      accentColor: '#3b82f6',
    },
    {
      icon: CheckCircleIcon,
      label: 'Clean',
      value: stats?.normal_request_count != null ? Number(stats.normal_request_count).toLocaleString() : '0',
      accentColor: '#10b981',
    },
    {
      icon: ExclamationTriangleIcon,
      label: 'Attacks Detected',
      value: stats ? (Number(stats.total_requests) - Number(stats.normal_request_count || 0)).toLocaleString() : '0',
      accentColor: '#f59e0b',
    },
    {
      icon: ShieldCheckIcon,
      label: 'Blocked',
      value: stats?.blocked_requests != null ? Number(stats.blocked_requests).toLocaleString() : '0',
      accentColor: '#ef4444',
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">All Requests</h1>
        <p className="text-text-muted text-sm mt-1">Complete HTTP request log with threat classification</p>
      </div>

      {/* Top Cards Layer */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {kpiCards.map((card) => (
          <StatCard key={card.label} {...card} />
        ))}
      </div>

      <InfoCard>
        {/* Bottom Navigation Tabs Layer (Filter Buttons) */}
        <div className="flex flex-wrap gap-2 mb-6 pb-4 border-b border-border-dim/40">
          {filters.map((f) => (
            <button
              key={f.id}
              onClick={() => {
                setActiveFilter(f.id);
                setCurrentPage(1);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all duration-200 ${
                activeFilter === f.id
                  ? 'bg-brand-primary text-white shadow-lg shadow-brand-primary/20'
                  : 'bg-bg-secondary/60 hover:bg-bg-secondary text-text-muted hover:text-text-primary border border-border-dim/40'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={pageSize}
          pageSizeOptions={[10, 25, 50]}
          filterConfig={[]}
          emptyMessage="No requests found"
          caption="HTTP request log"
          showPagination={false}
        />
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mt-6 pt-4 border-t border-border-dim text-sm text-text-muted">
          <span className="text-sm font-medium text-text-secondary">
            Page {currentPage} of {totalPages}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={loading || currentPage <= 1}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded hover:bg-bg-secondary text-text-secondary disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium text-xs"
              aria-label="Previous page"
            >
              <ChevronLeftIcon className="w-4 h-4" />
              <span>Previous</span>
            </button>
            
            <div className="flex items-center gap-1">
              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter((p) => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
                .reduce((acc, p, i, arr) => {
                  if (i > 0 && p - arr[i - 1] > 1) acc.push('…');
                  acc.push(p);
                  return acc;
                }, [])
                .map((p, i) =>
                  p === '…' ? (
                    <span key={`ellipsis-${i}`} className="px-2 text-text-muted select-none">
                      …
                    </span>
                  ) : (
                    <button
                      key={p}
                      type="button"
                      onClick={() => setCurrentPage(p)}
                      disabled={loading}
                      className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                        p === currentPage
                          ? 'bg-brand-primary text-white'
                          : 'hover:bg-bg-secondary text-text-secondary'
                      }`}
                    >
                      {p}
                    </button>
                  )
                )}
            </div>

            <button
              type="button"
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={loading || currentPage >= totalPages}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded hover:bg-bg-secondary text-text-secondary disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium text-xs"
              aria-label="Next page"
            >
              <span>Next</span>
              <ChevronRightIcon className="w-4 h-4" />
            </button>
          </div>
        </div>
      </InfoCard>
    </div>
  );
});
