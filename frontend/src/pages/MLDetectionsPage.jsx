import { useEffect, useState, memo } from 'react';
import { 
  CpuChipIcon, 
  InformationCircleIcon, 
  ShieldCheckIcon, 
  BeakerIcon,
  CommandLineIcon
} from '@heroicons/react/24/outline';
import { InfoCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { getMLLogs } from '../api/endpoints';
import { formatDate, formatIP } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const columns = [
  { key: 'timestamp', label: 'Timestamp', render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span> },
  { key: 'ip', label: 'Source IP', render: (v) => <span className="font-mono font-semibold">{formatIP(v)}</span> },
  { key: 'attack_type', label: 'Attack Type', render: (v) => <span className="text-text-primary font-bold">{v}</span> },
  { key: 'detection_type', label: 'Method', render: (v) => <Badge label={v || 'ML Engine'} className="bg-bg-secondary text-brand-primary border-brand-primary/20" /> },
  { key: 'confidence', label: 'Confidence', render: (v) => {
    const val = (v * 100).toFixed(0);
    let cls = 'text-severity-critical bg-severity-critical/10 border-severity-critical/30';
    if (v >= 0.9) cls = 'text-success bg-success/10 border-success/30';
    else if (v >= 0.7) cls = 'text-severity-medium bg-severity-medium/10 border-severity-medium/30';
    return <Badge label={`${val}%`} className={cls} />;
  }},
  { key: 'snippet', label: 'Payload Analysis', render: (v) => (
    <code className="text-ds-micro text-text-muted truncate max-w-[250px] block font-mono bg-bg-secondary p-ds-1 rounded-ds-sm" title={v}>
      {v || 'N/A'}
    </code>
  )},
  { key: 'blocked', label: 'Status', render: (v) => (
    v ? (
      <span className="inline-flex items-center gap-ds-1 text-ds-caption text-severity-critical font-bold">
        <ShieldCheckIcon className="w-3.5 h-3.5" /> Auto-Blocked
      </span>
    ) : (
      <span className="inline-flex items-center gap-ds-1 text-ds-caption text-severity-medium">
        <InformationCircleIcon className="w-3.5 h-3.5" /> Flags Only
      </span>
    )
  )},
];

export default memo(function MLDetectionsPage() {
  const { addToast } = useToast();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getMLLogs()
      .then((r) => setData(Array.isArray(r) ? r : r?.logs ?? []))
      .catch((e) => addToast(e.message || 'Failed to load ML detections', 'error'))
      .finally(() => setLoading(false));
  }, [addToast]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-xl bg-brand-primary/10 flex items-center justify-center text-brand-primary">
            <CpuChipIcon className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary">ML Detections</h1>
        </div>
        <p className="text-text-muted text-sm">Advanced threats detected by VIREX&apos;s AI/ML Engine in real-time.</p>
      </div>

      {/* Info Panel */}
      <div className="p-4 rounded-xl bg-brand-primary/5 border-l-4 border-brand-primary flex items-start gap-4">
        <div className="mt-0.5"><InformationCircleIcon className="w-5 h-5 text-brand-primary" /></div>
        <div className="text-sm text-text-secondary leading-relaxed">
          <strong className="text-brand-primary uppercase text-xs tracking-wider">Note:</strong> &quot;Attack Type&quot; is the label assigned based on classification. 
          &quot;Detection Method&quot; identifies the specific model (Random Forest, LSTM, etc.). 
          Our AI model flags anomalous behavior even when signatures don&apos;t match.
        </div>
      </div>

      <InfoCard>
        <DataTable
          columns={columns}
          data={data}
          loading={loading}
          pageSize={15}
          emptyMessage="No machine learning records found yet. Generate some traffic to see the engine in action."
          caption="ML Engine detection logs"
        />
      </InfoCard>

      {/* Bottom Insights */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <InfoCard title="Engine Health">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-full bg-success/10 flex items-center justify-center text-success">
              <ShieldCheckIcon className="w-6 h-6" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary">Active Protection</div>
              <div className="text-xs text-text-muted">Analyzing 2,400 req/sec</div>
            </div>
          </div>
        </InfoCard>
        <InfoCard title="Last Re-train">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-full bg-info/10 flex items-center justify-center text-info">
              <BeakerIcon className="w-6 h-6" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary">Model v2.1.0</div>
              <div className="text-xs text-text-muted">2 hours ago</div>
            </div>
          </div>
        </InfoCard>
        <InfoCard title="Model Vectorizer">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-full bg-brand-primary/10 flex items-center justify-center text-brand-primary">
              <CommandLineIcon className="w-6 h-6" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary">TF-IDF Vectorizer</div>
              <div className="text-xs text-text-muted">5,000 components</div>
            </div>
          </div>
        </InfoCard>
      </div>
    </div>
  );
});
