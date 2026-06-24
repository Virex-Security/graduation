import { memo } from 'react';
import { ShieldCheckIcon } from '@heroicons/react/24/outline';

const SCORE_BAD = { stroke: '#ef4444', label: 'At risk' };
const SCORE_OK = { stroke: '#f59e0b', label: 'Moderate' };
const SCORE_GOOD = { stroke: '#10b981', label: 'Strong' };

function band(score) {
  if (score >= 80) return SCORE_GOOD;
  if (score >= 50) return SCORE_OK;
  return SCORE_BAD;
}

function Ring({ pct, stroke }) {
  return (
    <div className="relative w-24 h-24 flex-shrink-0">
      <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90" aria-hidden>
        <circle cx="18" cy="18" r="15.9" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
        <circle
          cx="18"
          cy="18"
          r="15.9"
          fill="none"
          stroke={stroke}
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={`${pct} 100`}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-ds-title font-black text-text-primary tabular-nums leading-none">{pct}</span>
        <span className="text-ds-micro text-text-muted mt-0.5">/ 100</span>
      </div>
    </div>
  );
}

/**
 * Primary posture KPI: score ring + short supporting metrics.
 */
function SecurityScoreCard({ score = 0, detectionRate, falsePositives, loading }) {
  const pct = Math.min(Math.max(Number(score) || 0, 0), 100);
  const { stroke, label } = band(pct);

  if (loading) {
    return (
      <div className="card h-full min-h-[200px] flex flex-col justify-center">
        <div className="flex items-center gap-ds-5">
          <div className="w-24 h-24 rounded-full bg-bg-secondary animate-pulse flex-shrink-0" />
          <div className="flex-1 space-y-ds-2">
            <div className="h-3 bg-bg-secondary rounded animate-pulse w-2/3" />
            <div className="h-8 bg-bg-secondary rounded animate-pulse w-1/2" />
            <div className="h-3 bg-bg-secondary rounded animate-pulse w-full" />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card h-full flex flex-col">
      <div className="flex items-start gap-ds-5">
        <Ring pct={pct} stroke={stroke} />
        <div className="flex-1 min-w-0 pt-ds-1">
          <div className="flex items-center gap-ds-2 text-ds-micro font-semibold text-text-muted uppercase tracking-ds-wider">
            <ShieldCheckIcon className="w-4 h-4 text-brand-primary flex-shrink-0" aria-hidden />
            Security score
          </div>
          <p className="text-ds-body-sm font-semibold mt-ds-2" style={{ color: stroke }}>
            {label}
          </p>
          <dl className="mt-ds-4 space-y-ds-2 border-t border-border-dim/60 pt-ds-4">
            <div className="flex justify-between gap-ds-4 text-ds-caption">
              <dt className="text-text-muted">Detection rate</dt>
              <dd className="font-semibold text-text-primary tabular-nums">{detectionRate ?? 0}%</dd>
            </div>
            <div className="flex justify-between gap-ds-4 text-ds-caption">
              <dt className="text-text-muted">False positives</dt>
              <dd className="font-semibold text-text-primary tabular-nums">{falsePositives ?? 0}%</dd>
            </div>
          </dl>
        </div>
      </div>
    </div>
  );
}

export default memo(SecurityScoreCard);
