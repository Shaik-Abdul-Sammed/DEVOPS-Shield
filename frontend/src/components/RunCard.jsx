import React from 'react';
import RiskBadge from './RiskBadge';
import { describeRiskReasons } from '../utils/riskFormatter';
import { formatDateTime } from '../utils/dateHelpers';

const RunCard = ({ run, onAction }) => {
  if (!run) return null;
  const primaryReason = run.risk?.reasons?.[0]?.detail || 'No high-risk reasons reported';
  const disableQuarantine = (run.risk?.score ?? 0) < 50;

  return (
    <article className="card run-card">
      <div className="run-card-header">
        <div>
          <h3>{run.pipelineId} — {run.runId}</h3>
          <p className="muted">Started {formatDateTime(run.startedAt)} · Status {run.status}</p>
        </div>
        <RiskBadge score={run.risk?.score} level={run.risk?.level} size="lg" />
      </div>

      <div className="run-card-metrics">
        <div>
          <span className="label">ML Confidence</span>
          <span>{Math.round((run.risk?.mlConfidence ?? 0) * 100)}%</span>
        </div>
        <div>
          <span className="label">Rule Score</span>
          <span>{run.risk?.ruleScore ?? '—'}</span>
        </div>
        <div>
          <span className="label">Trust Score</span>
          <span>{Math.round((run.risk?.trustScore ?? 0) * 100)}%</span>
        </div>
      </div>

      <p className="run-card-primary">{primaryReason}</p>
      <pre className="run-card-reasons" aria-label="Risk rationale">{describeRiskReasons(run.risk?.reasons)}</pre>

      <div className="run-card-actions">
        <button type="button" onClick={() => onAction?.('view', run)} className="btn-primary">Open Run</button>
        <button
          type="button"
          onClick={() => onAction?.('quarantine', run)}
          className="btn-outline"
          disabled={run.status === 'QUARANTINED'}
        >
          {run.status === 'QUARANTINED' ? 'Quarantined' : 'Quarantine'}
        </button>
        <button
          type="button"
          onClick={() => onAction?.('rollback', run)}
          className="btn-outline"
          disabled={run.status === 'ROLLING_BACK'}
        >
          {run.status === 'ROLLING_BACK' ? 'Rolling back...' : 'Trigger Rollback'}
        </button>
      </div>
    </article>
  );
};

export default RunCard;
