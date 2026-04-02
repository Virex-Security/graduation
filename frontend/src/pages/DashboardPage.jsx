import { useEffect, useState, memo } from 'react';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  EyeIcon,
} from '@heroicons/react/24/outline';
import { StatCard } from '../components/Cards';
import {
  DashboardHeader,
  KpiGrid,
  SecurityScoreCard,
  QuickLinks,
} from '../components/dashboard';
import { getSecurityStats } from '../api/endpoints';
import { formatNumber } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const KPI_LINKS = [
  { to: '/attack-history', label: 'Attack history' },
  { to: '/incidents', label: 'Incidents' },
  { to: '/ml-detections', label: 'ML detections' },
];

export default memo(function DashboardPage() {
  const { addToast } = useToast();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getSecurityStats()
      .then(setStats)
      .catch((err) => addToast(err.message || 'Failed to load dashboard', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  const kpiCards = [
    {
      icon: ShieldCheckIcon,
      label: 'Threats blocked',
      value: formatNumber(stats?.threats_blocked),
      accentColor: '#10b981',
    },
    {
      icon: ExclamationTriangleIcon,
      label: 'Active incidents',
      value: formatNumber(stats?.active_incidents),
      accentColor: '#f59e0b',
    },
    {
      icon: EyeIcon,
      label: 'ML detections',
      value: formatNumber(stats?.ml_detections),
      accentColor: '#9a277d',
    },
  ];

  return (
    <div className="space-y-ds-8 max-w-7xl">
      <DashboardHeader
        title="Security overview"
        description="Key posture metrics at a glance. Use the links below to drill into traffic, incidents, and model output."
      />

      <KpiGrid>
        <SecurityScoreCard
          loading={loading}
          score={stats?.security_score ?? 0}
          detectionRate={stats?.detection_rate}
          falsePositives={stats?.false_positives}
        />
        {loading
          ? kpiCards.map((c) => <StatCard key={c.label} skeleton />)
          : kpiCards.map((card) => <StatCard key={card.label} {...card} />)}
      </KpiGrid>

      <QuickLinks links={KPI_LINKS} />
    </div>
  );
});
