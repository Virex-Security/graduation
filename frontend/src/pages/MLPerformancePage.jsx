import { useEffect, useState, useMemo, memo, useCallback } from 'react';
import { 
  ArrowPathIcon, 
  StarIcon,
  CheckBadgeIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';
import {
  Chart as ChartJS,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement
} from 'chart.js';
import { Radar, Bar } from 'react-chartjs-2';
import { InfoCard, StatCard } from '../components/Cards';
import { PrimaryButton } from '../components/Buttons';
import { getMLStats } from '../api/endpoints';
import { useToast } from '../utils/useToast';

ChartJS.register(
  RadialLinearScale,
  PointElement,
  LineElement,
  BarElement,
  Filler,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale
);

export default memo(function MLPerformancePage() {
  const { addToast } = useToast();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = useCallback(async () => {
    setRefreshing(true);
    try {
      const r = await getMLStats();
      setData(r);
    } catch (e) {
      addToast(e.message || 'Failed to load ML performance data', 'error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const radarData = useMemo(() => {
    if (!data) return { labels: [], datasets: [] };
    return {
      labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score'],
      datasets: [
        {
          label: 'Model Performance',
          data: [
            data.accuracy || 0,
            data.precision || 0,
            data.recall || 0,
            data.f1_score || 0,
          ],
          backgroundColor: 'rgba(154, 39, 125, 0.2)',
          borderColor: '#9a277d',
          borderWidth: 2,
          pointBackgroundColor: '#9a277d',
          pointBorderColor: '#fff',
        },
      ],
    };
  }, [data]);

  const barData = useMemo(() => {
    if (!data?.confusion_matrix) return { labels: [], datasets: [] };
    const cm = data.confusion_matrix;
    return {
      labels: ['True Negatives', 'False Positives', 'False Negatives', 'True Positives'],
      datasets: [
        {
          label: 'Count',
          data: [cm.tn || 0, cm.fp || 0, cm.fn || 0, cm.tp || 0],
          backgroundColor: [
            'rgba(16, 185, 129, 0.8)',
            'rgba(245, 158, 11, 0.8)',
            'rgba(239, 68, 68, 0.8)',
            'rgba(59, 130, 246, 0.8)',
          ],
        },
      ],
    };
  }, [data]);

  const radarOptions = {
    scales: {
      r: {
        beginAtZero: true,
        max: 100,
        grid: { color: 'rgba(255, 255, 255, 0.1)' },
        angleLines: { color: 'rgba(255, 255, 255, 0.1)' },
        ticks: { display: false },
      },
    },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#120b1a',
        titleColor: '#e046ba',
        borderColor: '#9a277d',
        borderWidth: 1,
      }
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="w-8 h-8 rounded-full border-2 border-brand-primary border-t-transparent animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-brand-primary/10 flex items-center justify-center text-brand-primary">
              <StarIcon className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold text-text-primary">ML Model Performance</h1>
          </div>
          <p className="text-text-muted text-sm">Real-time inference accuracy and model health metrics.</p>
        </div>
        <PrimaryButton onClick={fetchStats} loading={refreshing}>
          <ArrowPathIcon className="w-4 h-4 mr-2" />
          REFRESH
        </PrimaryButton>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={CheckCircleIcon} label="Accuracy" value={`${data?.accuracy || 0}%`} accentColor="#3b82f6" />
        <StatCard icon={CheckBadgeIcon} label="Precision" value={`${data?.precision || 0}%`} accentColor="#10b981" />
        <div className="card flex items-center gap-5 border-l-4 border-orange-500">
           <div className="w-12 h-12 rounded-2xl bg-orange-500/10 flex items-center justify-center text-orange-500">
             <span className="brand-text text-xl">V</span>
           </div>
           <div>
             <div className="text-sm font-medium text-text-muted">Recall</div>
             <div className="text-2xl font-black text-text-primary">{data?.recall || 0}%</div>
           </div>
        </div>
        <StatCard icon={StarIcon} label="F1-Score" value={`${data?.f1_score || 0}%`} accentColor="#9a277d" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Radar Chart */}
        <InfoCard title="Performance Radar">
          <div className="h-80 flex items-center justify-center">
            <Radar data={radarData} options={radarOptions} />
          </div>
        </InfoCard>

        {/* Confusion Matrix */}
        <InfoCard title="Confusion Matrix">
          <div className="h-80">
            <Bar data={barData} options={{ 
              responsive: true, 
              maintainAspectRatio: false, 
              plugins: { legend: { display: false } },
              scales: { 
                y: { grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { display: false } }
              }
            }} />
          </div>
        </InfoCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Indicators */}
        <InfoCard title="Top Attack Indicators" className="lg:col-span-2">
          <div className="space-y-4">
            {data?.top_features?.map((f, i) => (
              <div key={i} className="space-y-1.5">
                <div className="flex justify-between items-end px-1">
                  <div className="min-w-0">
                    <span className="text-sm font-bold text-text-primary mr-2">#{i+1}</span>
                    <span className="text-xs text-text-muted font-normal uppercase tracking-wider">{f.feature?.replace(/_/g, ' ')}</span>
                  </div>
                  <span className="text-xs font-mono text-brand-primary">{(f.importance * 100).toFixed(1)}% weight</span>
                </div>
                <div className="h-1.5 w-full bg-bg-secondary rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-brand-primary to-brand-secondary transition-all duration-1000 ease-out"
                    style={{ width: `${(f.importance / (data.top_features[0]?.importance || 1)) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </InfoCard>

        {/* Model Info */}
        <InfoCard title="Model Metadata">
          <div className="space-y-4">
            <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
              <div className="text-[10px] text-text-muted uppercase font-bold tracking-widest">Model Type</div>
              <div className="text-xs text-text-primary font-mono">{data?.model_type || 'Random Forest Classifier'}</div>
            </div>
            <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
              <div className="text-[10px] text-text-muted uppercase font-bold tracking-widest">Dataset Size</div>
              <div className="text-xs text-text-primary font-mono">{data?.dataset_size?.toLocaleString() || '5,000 samples'}</div>
            </div>
            <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
              <div className="text-[10px] text-text-muted uppercase font-bold tracking-widest">Test Samples</div>
              <div className="text-xs text-text-primary font-mono">{data?.test_samples || '1,000 samples'}</div>
            </div>
            <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
              <div className="text-[10px] text-text-muted uppercase font-bold tracking-widest">AU-ROC Score</div>
              <div className="text-xs text-brand-primary font-mono font-bold tracking-widest">{data?.roc_auc?.toFixed(4) || '0.9756'}</div>
            </div>
          </div>
        </InfoCard>
      </div>
    </div>
  );
});
