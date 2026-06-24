import React, { useEffect, useState, memo } from 'react';
import { useParams } from 'react-router-dom';
import { 
  MagnifyingGlassIcon, 
  CheckCircleIcon, 
  NoSymbolIcon, 
  ClockIcon, 
  ArrowDownTrayIcon,
  ExclamationCircleIcon,
  UserIcon
} from '@heroicons/react/24/outline';
import { InfoCard } from '../components/Cards';
import DataTable, { Badge } from '../components/DataTable';
import { SecondaryButton, DangerButton } from '../components/Buttons';
import { TextareaInput } from '../components/Forms';
import { getIncident, updateIncident } from '../api/endpoints';
import { formatDate, formatIP, severityClass, statusClass } from '../utils/formatters';
import { useToast } from '../utils/useToast';

const eventColumns = [
  { key: 'timestamp', label: 'Timestamp', render: (v) => <span className="font-mono text-xs">{formatDate(v)}</span> },
  { key: 'endpoint', label: 'Endpoint', render: (v) => <code className="text-brand-primary text-xs">{v || '/'}</code> },
  { key: 'method', label: 'Method', render: (v) => <Badge label={v || 'GET'} className="bg-bg-secondary text-text-secondary border-border-dim" /> },
  { key: 'snippet', label: 'Snippet', render: (v) => <span className="text-xs text-text-muted truncate max-w-[200px] block" title={v}>{v || 'N/A'}</span> },
  { key: 'severity', label: 'Severity', render: (v) => <Badge label={v} className={severityClass(v)} /> },
];

export default memo(function IncidentDetailPage() {
  const { id } = useParams();
  const { addToast } = useToast();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [comment, setComment] = useState('');

  // const isAdmin = user?.role === 'admin'; (removed unused)

  useEffect(() => {
    setLoading(true);
    getIncident(id)
      .then(setIncident)
      .catch((e) => addToast(e.message || 'Failed to load incident details', 'error'))
      .finally(() => setLoading(false));
  }, [id, addToast]);

  const handleAction = async (actionType) => {
    setActionLoading(true);
    try {
      await updateIncident(id, { action: actionType, comment });
      addToast(`Action "${actionType}" applied successfully`, 'success');
      // Refresh data
      const updated = await getIncident(id);
      setIncident(updated);
      setComment('');
    } catch (e) {
      addToast(e.message || 'Failed to apply action', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="w-8 h-8 rounded-full border-2 border-brand-primary border-t-transparent animate-spin" />
      </div>
    );
  }

  if (!incident) return <div className="text-center py-12 text-text-muted">Incident not found.</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-2xl font-bold text-text-primary">Incident #{incident.id}</h1>
            <Badge label={incident.status} className={statusClass(incident.status)} />
          </div>
          <p className="text-text-muted text-sm flex flex-wrap gap-x-4">
            <span>Type: <strong className="text-brand-primary">{incident.category}</strong></span>
            <span>Source: <strong className="text-text-primary font-mono">{formatIP(incident.source_ip)}</strong></span>
            <span>Detected: <strong>{formatDate(incident.first_seen)}</strong></span>
          </p>
        </div>
        <SecondaryButton onClick={() => addToast('Exporting incident data...', 'info')}>
          <ArrowDownTrayIcon className="w-4 h-4 mr-2" />
          Export JSON
        </SecondaryButton>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          {/* Events Table */}
          <InfoCard title={`Event Log Activity (${incident.events?.length || 0} Events)`}>
            <DataTable
              columns={eventColumns}
              data={incident.events || []}
              loading={false}
              pageSize={10}
              searchable={false}
              emptyMessage="No events recorded for this incident."
            />
          </InfoCard>

          {/* Audit Trail */}
          <InfoCard title="Action Audit Trail">
            <div className="space-y-4">
              {incident.actions && incident.actions.length > 0 ? (
                incident.actions.map((action, idx) => (
                  <div key={idx} className="flex gap-4 p-4 rounded-xl bg-bg-secondary/30 border border-border-dim/50">
                    <div className="w-10 h-10 rounded-full bg-brand-primary/10 flex items-center justify-center flex-shrink-0">
                      <UserIcon className="w-5 h-5 text-brand-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex justify-between items-start mb-1">
                        <span className="text-xs text-text-muted">{formatDate(action.timestamp)}</span>
                        <span className="text-xs font-bold text-brand-primary uppercase">{action.action}</span>
                      </div>
                      <p className="text-sm text-text-primary mb-1">
                        Applied by <strong className="text-brand-secondary">{action.actor}</strong>
                      </p>
                      {action.comment && (
                        <p className="text-sm text-text-secondary italic">&quot; {action.comment} &quot;</p>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-sm text-text-muted text-center py-4 italic">No actions recorded yet.</p>
              )}
            </div>
          </InfoCard>
        </div>

        {/* Action Panel */}
        <div className="lg:col-span-1 space-y-6">
          <InfoCard title="Response Actions">
            <div className="space-y-4">
              <p className="text-xs text-text-muted"> mitigation steps and update incident status.</p>
              
              <div>
                <label htmlFor="action-comment" className="block text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
                  Internal Comment
                </label>
                <TextareaInput
                  id="action-comment"
                  placeholder="Describe the action or reasoning..."
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  className="text-sm"
                  rows={4}
                />
              </div>

              <div className="grid grid-cols-1 gap-2">
                <SecondaryButton 
                  onClick={() => handleAction('Investigate')} 
                  disabled={actionLoading}
                  className="justify-start px-4"
                >
                  <MagnifyingGlassIcon className="w-5 h-5 mr-3 text-info" />
                  Investigate
                </SecondaryButton>
                
                <SecondaryButton 
                  onClick={() => handleAction('Close')} 
                  disabled={actionLoading}
                  className="justify-start px-4"
                >
                  <CheckCircleIcon className="w-5 h-5 mr-3 text-success" />
                  Close
                </SecondaryButton>

                <DangerButton 
                  onClick={() => handleAction('Block IP')} 
                  disabled={actionLoading}
                  className="justify-start px-4"
                >
                  <NoSymbolIcon className="w-5 h-5 mr-3" />
                  Block IP
                </DangerButton>

                <SecondaryButton 
                  onClick={() => handleAction('Rate Limit')} 
                  disabled={actionLoading}
                  className="justify-start px-4 border-orange-500/30 hover:border-orange-500/60"
                >
                  <ClockIcon className="w-5 h-5 mr-3 text-orange-500" />
                  Rate Limit
                </SecondaryButton>

                <SecondaryButton 
                  onClick={() => handleAction('False Positive')} 
                  disabled={actionLoading}
                  className="justify-start px-4"
                >
                  <ExclamationCircleIcon className="w-5 h-5 mr-3 text-text-muted" />
                  False Positive
                </SecondaryButton>
              </div>
            </div>
          </InfoCard>

          {/* Incident Context */}
          <InfoCard title="Inference Context">
            <div className="space-y-3">
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Attack Subtype:</span>
                <span className="text-text-primary">{incident.detection_type || 'Unknown'}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Confidence Score:</span>
                <span className="text-brand-primary font-mono">{(incident.ml_score * 100).toFixed(2)}%</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Environment:</span>
                <span className="text-text-primary">Production API</span>
              </div>
            </div>
          </InfoCard>
        </div>
      </div>
    </div>
  );
});
