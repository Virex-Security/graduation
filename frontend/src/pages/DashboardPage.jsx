import { useEffect, useState, memo } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheckIcon, ExclamationTriangleIcon, EyeIcon,
  GlobeAltIcon,
} from '@heroicons/react/24/outline';
import { StatCard, InfoCard } from '../components/Cards';
import DataTable from '../components/DataTable';
import { Badge } from '../components/DataTable';
import { getSecurityStats, getAttackHistory } from '../api/endpoints';
import { formatDate, formatNumber, severityClass } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const STAT_SKELETONS = 4;

function SecurityScore({ score = 0 }) {
  const pct = Math.min(Math.max(score, 0), 100);
  const color = pct >= 80 ? '#10b981' : pct >= 50 ? '#f59e0b' : '#ef4444';
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-28 h-28">
        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
          <circle cx="18" cy="18" r="15.9" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
          <circle
            cx="18" cy="18" r="15.9" fill="none"
            stroke={color} strokeWidth="3" strokeLinecap="round"
            strokeDasharray={`${pct} 100`}
            className="transition-all duration-1000"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-black text-text-primary">{pct}</span>
          <span className="text-xs text-text-muted">/ 100</span>
        </div>
      </div>
      <span className="text-sm font-semibold" style={{ color }}>
        {pct >= 80 ? 'Excellent' : pct >= 50 ? 'Moderate' : 'At Risk'}
      </span>
    </div>
  );
}

const attackColumns = [
  { key: 'timestamp', label: 'Time', render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span> },
  { key: 'attack_type', label: 'Type', render: (v) => <span className="font-mono text-xs text-brand-primary">{v ?? '—'}</span> },
  { key: 'source_ip', label: 'Source IP', render: (v) => <span className="font-mono text-xs">{v ?? '—'}</span> },
  { key: 'severity', label: 'Severity', sortable: true, render: (v) => (
    <Badge label={v ?? 'Unknown'} className={severityClass(v)} />
  )},
  { key: 'status', label: 'Status', render: (v) => (
    <span className={`text-xs font-semibold capitalize ${v === 'blocked' ? 'text-success' : 'text-warning'}`}>{v ?? '—'}</span>
  )},
];

export default memo(function DashboardPage() {
  const { addToast } = useToast();
  const [stats, setStats] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([getSecurityStats(), getAttackHistory()])
      .then(([s, a]) => {
        setStats(s);
        setAttacks(Array.isArray(a) ? a : a?.attacks ?? []);
      })
      .catch((err) => addToast(err.message || 'Failed to load dashboard data', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  const statCards = [
    {
      icon: ShieldCheckIcon,
      label: 'Threats Blocked',
      value: formatNumber(stats?.threats_blocked),
      accentColor: '#10b981',
    },
    {
      icon: ExclamationTriangleIcon,
      label: 'Active Incidents',
      value: formatNumber(stats?.active_incidents),
      accentColor: '#f59e0b',
    },
    {
      icon: EyeIcon,
      label: 'ML Detections',
      value: formatNumber(stats?.ml_detections),
      accentColor: '#9a277d',
    },
    {
      icon: GlobeAltIcon,
      label: 'Total Requests',
      value: formatNumber(stats?.total_requests),
      accentColor: '#3b82f6',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Security Overview</h1>
        <p className="text-text-muted text-sm mt-1">Real-time threat detection and system status</p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {loading
          ? Array.from({ length: STAT_SKELETONS }).map((_, i) => <StatCard key={i} skeleton />)
          : statCards.map((card) => <StatCard key={card.label} {...card} />)
        }
      </div>

      {/* Security Score + Recent Attacks */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <InfoCard title="Security Score" className="col-span-1 flex flex-col items-center justify-center py-6">
          {loading
            ? <div className="w-28 h-28 rounded-full bg-bg-secondary animate-pulse" />
            : <SecurityScore score={stats?.security_score ?? 0} />
          }
          <div className="mt-4 w-full space-y-2">
            {[
              { label: 'Detection Rate', value: `${stats?.detection_rate ?? 0}%` },
              { label: 'False Positives', value: `${stats?.false_positives ?? 0}%` },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between text-sm">
                <span className="text-text-muted">{label}</span>
                <span className="font-semibold text-text-primary">{loading ? '—' : value}</span>
              </div>
            ))}
          </div>
        </InfoCard>

        <div className="col-span-1 lg:col-span-2">
          <InfoCard
            title="Recent Attacks"
            action={<Link to="/attack-history" className="text-xs text-brand-primary hover:underline">View all →</Link>}
          >
            <DataTable
              columns={attackColumns}
              data={attacks.slice(0, 5)}
              loading={loading}
              searchable={false}
              pageSize={5}
              emptyMessage="No attacks detected"
              caption="Recent attack events"
            />
          </InfoCard>
        </div>
      </div>
    </div>
  );
});
