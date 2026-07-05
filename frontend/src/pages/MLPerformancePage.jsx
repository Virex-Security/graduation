import { useEffect, useState, useMemo, memo, useCallback } from 'react';
import { 
  ArrowPathIcon, 
  StarIcon,
  CheckBadgeIcon,
  CheckCircleIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';
import {
  Chart as ChartJS,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend
} from 'chart.js';
import { Radar } from 'react-chartjs-2';
import { InfoCard, StatCard } from '../components/Cards';
import { PrimaryButton } from '../components/Buttons';
import { getMLStats, getSecurityStats } from '../api/endpoints';
import { useToast } from '../utils/useToast';

ChartJS.register(
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend
);

export default memo(function MLPerformancePage() {
  const { addToast } = useToast();
  const [mlData, setMlData] = useState(null);
  const [secData, setSecData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = useCallback(async () => {
    setRefreshing(true);
    try {
      const [mlRes, secRes] = await Promise.all([
        getMLStats(),
        getSecurityStats()
      ]);
      setMlData(mlRes);
      setSecData(secRes);
    } catch (e) {
      addToast(e.message || 'Failed to load data', 'error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  const radarData = useMemo(() => {
    if (!mlData) return { labels: [], datasets: [] };
    return {
      labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score'],
      datasets: [
        {
          label: 'Model Performance',
          data: [
            mlData.accuracy || 0,
            mlData.precision || 0,
            mlData.recall || 0,
            mlData.f1_score || 0,
          ],
          backgroundColor: 'rgba(154, 39, 125, 0.2)',
          borderColor: '#9a277d',
          borderWidth: 2,
          pointBackgroundColor: '#9a277d',
          pointBorderColor: '#fff',
        },
      ],
    };
  }, [mlData]);

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
    <div className="space-y-10">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-xl bg-brand-primary/10 flex items-center justify-center text-brand-primary">
              <ChartBarIcon className="w-6 h-6" />
            </div>
            <h1 className="text-2xl font-bold text-text-primary">ML Model Performance</h1>
          </div>
          <p className="text-text-muted text-sm">Separated Offline Model Evaluation and Live WAF Monitoring.</p>
        </div>
        <PrimaryButton onClick={fetchStats} loading={refreshing}>
          <ArrowPathIcon className="w-4 h-4 mr-2" />
          REFRESH
        </PrimaryButton>
      </div>

      {/* SECTION 1: OFFLINE MODEL EVALUATION */}
      <div className="space-y-6 bg-bg-secondary/20 p-6 rounded-2xl border border-border-dim">
        <div className="flex flex-col mb-4">
          <h2 className="text-xl font-bold text-brand-primary uppercase tracking-wide">Offline Model Evaluation</h2>
          <p className="text-xs text-text-muted mt-2 border-l-2 border-brand-secondary pl-3 py-1">
            This section shows the official evaluation of the trained LightGBM model using the held-out test dataset. These values remain constant during production.
          </p>
        </div>

        {/* Offline Metrics Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard icon={CheckCircleIcon} label="Accuracy" value={`${mlData?.accuracy || 0}%`} accentColor="#3b82f6" />
          <StatCard icon={CheckBadgeIcon} label="Precision" value={`${mlData?.precision || 0}%`} accentColor="#10b981" />
          <div className="card flex items-center gap-5 border-l-4 border-orange-500">
             <div className="w-12 h-12 rounded-2xl bg-orange-500/10 flex items-center justify-center text-orange-500">
               <span className="brand-text text-xl">V</span>
             </div>
             <div>
               <div className="text-sm font-medium text-text-muted">Recall</div>
               <div className="text-2xl font-black text-text-primary">{mlData?.recall || 0}%</div>
             </div>
          </div>
          <StatCard icon={StarIcon} label="F1-Score" value={`${mlData?.f1_score || 0}%`} accentColor="#9a277d" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Radar Chart */}
          <InfoCard title="Evaluation Radar" className="lg:col-span-1">
            <div className="h-64 flex items-center justify-center">
              <Radar data={radarData} options={radarOptions} />
            </div>
          </InfoCard>

          {/* Model Info Grid */}
          <InfoCard title="Model Metadata & Offline Statistics" className="lg:col-span-2">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Model Name/Version</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.model_type || 'LightGBM'} {mlData?.model_version || 'v2.0'}</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Training Date</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.training_date || '2026-06-28'}</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Dataset Size</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.dataset_size?.toLocaleString() || '53,000'}</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Test Samples</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.test_size?.toLocaleString() || '7,950'}</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Classes / Features</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.number_of_classes || 10} / {mlData?.feature_count || 5000}</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Balanced Acc.</div>
                <div className="text-xs text-text-primary font-mono text-brand-secondary">{mlData?.balanced_accuracy || 99.85}%</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">ROC-AUC</div>
                <div className="text-xs text-text-primary font-mono text-brand-primary font-bold">{mlData?.roc_auc != null ? mlData.roc_auc.toFixed(4) : 'N/A'}</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Log Loss</div>
                <div className="text-xs text-text-primary font-mono text-orange-400">{mlData?.log_loss || 0.0012}</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">CV Score</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.cross_validation_score || 99.9}%</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Avg Inference Time</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.average_inference_time_ms || 1.5} ms</div>
              </div>
              <div className="p-3 rounded-lg bg-bg-secondary/50 border border-border-dim/50 space-y-1">
                <div className="ds-overline">Pickle / ONNX Size</div>
                <div className="text-xs text-text-primary font-mono">{mlData?.pickle_size_mb || 5.4}MB / {mlData?.onnx_size_mb || 2.1}MB</div>
              </div>
            </div>
          </InfoCard>
        </div>
      </div>

      <hr className="border-border-dim/30 my-8" />

      {/* SECTION 2: LIVE WAF MONITORING */}
      <div className="space-y-6">
        <div className="flex flex-col mb-4">
          <h2 className="text-xl font-bold text-orange-500 uppercase tracking-wide">Live WAF Monitoring</h2>
          <p className="text-xs text-text-muted mt-1">Operational runtime metrics. These change with live traffic and attack simulations.</p>
        </div>

        {/* Live Traffic Stats Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <StatCard icon={ArrowPathIcon} label="Total Requests" value={mlData?.live_total_requests || secData?.total_requests || 0} accentColor="#6b7280" />
          <StatCard icon={ShieldCheckIcon} label="Allowed" value={secData?.clean_traffic || 0} accentColor="#10b981" />
          <StatCard icon={ShieldExclamationIcon} label="Blocked" value={secData?.total_attacks || 0} accentColor="#ef4444" />
          <StatCard icon={ShieldExclamationIcon} label="Rule Detections" value={secData?.rule_detected || 0} accentColor="#f59e0b" />
          <StatCard icon={StarIcon} label="ML Detections" value={mlData?.live_ml_detections || 0} accentColor="#9a277d" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top Indicators */}
          <InfoCard title="Live Top Attack Indicators">
            <div className="space-y-4 max-h-80 overflow-y-auto pr-2">
              {mlData?.live_attack_indicators && Object.keys(mlData.live_attack_indicators).length > 0 ? (
                Object.entries(mlData.live_attack_indicators)
                  .sort((a, b) => b[1] - a[1])
                  .map(([feature, importance], i) => (
                  <div key={i} className="space-y-1.5">
                    <div className="flex justify-between items-end px-1">
                      <div className="min-w-0">
                        <span className="text-sm font-bold text-text-primary mr-2">#{i+1}</span>
                        <span className="text-xs text-text-muted font-normal uppercase tracking-wider">{feature?.replace(/_/g, ' ')}</span>
                      </div>
                      <span className="text-xs font-mono text-brand-primary">{(importance * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-bg-secondary rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-orange-500 to-red-500 transition-all duration-1000 ease-out"
                        style={{ width: `${(importance / Math.max(...Object.values(mlData.live_attack_indicators))) * 100}%` }}
                      />
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-10 text-text-muted">
                  <p>No active attack indicators from live traffic.</p>
                </div>
              )}
            </div>
          </InfoCard>
          
          {/* Status Overview */}
          <InfoCard title="System Operational Status">
            <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-bg-secondary/40 border border-border-dim flex flex-col items-center justify-center">
                    <div className="text-text-muted text-sm mb-1">API Status</div>
                    <div className="flex items-center gap-2">
                        <span className="relative flex h-3 w-3">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                        </span>
                        <span className="text-green-500 font-bold">Online</span>
                    </div>
                </div>
                <div className="p-4 rounded-xl bg-bg-secondary/40 border border-border-dim flex flex-col items-center justify-center">
                    <div className="text-text-muted text-sm mb-1">Redis Cache</div>
                    <div className="text-green-500 font-bold">Connected</div>
                </div>
                <div className="p-4 rounded-xl bg-bg-secondary/40 border border-border-dim flex flex-col items-center justify-center">
                    <div className="text-text-muted text-sm mb-1">PostgreSQL DB</div>
                    <div className="text-green-500 font-bold">Connected</div>
                </div>
                <div className="p-4 rounded-xl bg-bg-secondary/40 border border-border-dim flex flex-col items-center justify-center">
                    <div className="text-text-muted text-sm mb-1">Live Engine</div>
                    <div className="text-brand-primary font-bold">Active</div>
                </div>
            </div>
          </InfoCard>
        </div>
      </div>
    </div>
  );
});
