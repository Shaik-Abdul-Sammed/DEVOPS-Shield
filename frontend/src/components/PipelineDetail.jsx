import React from 'react';
import RunCard from './RunCard';
import Timeline from './Timeline';
import RiskBadge from './RiskBadge';
import { formatDateTime } from '../utils/dateHelpers';
import { verifySignature } from '../utils/verifySignature';

const PipelineDetail = ({ pipeline, runs = [], activeRunId, onSelectRun, onAction, inlineMode = false }) => {
  if (!pipeline) {
    if (inlineMode) return null;
    return (
      <section className="card pipeline-detail">
        <header className="card-header"><h2>Select a pipeline</h2></header>
        <p className="muted">Choose a pipeline to review detailed run history and risk posture.</p>
      </section>
    );
  }

  const selectedRun = runs.find((run) => run.runId === activeRunId) || runs[0];
  const proofCheck = verifySignature(selectedRun?.immutableProof || {});

  return (
    <section className={`pipeline-detail-premium ${inlineMode ? 'inline-mode' : ''}`}>
      {!inlineMode && (
        <header className="detail-hero-card">
          <div className="hero-info">
            <span className="badge-premium" style={{ marginBottom: '12px', display: 'inline-block' }}>
              {pipeline.lastStatus}
            </span>
            <h2>{pipeline.name}</h2>
            <p className="muted" style={{ maxWidth: '400px' }}>{pipeline.description}</p>
            <div className="tags" style={{ marginTop: '16px' }}>
              {pipeline.tags?.map((tag) => <span key={tag} className="tag">{tag}</span>)}
            </div>
          </div>
          <div className="hero-viz">
            <div className="viz-score">{pipeline.lastRiskScore}%</div>
            <div className="viz-label">Security Posture</div>
            <RiskBadge score={pipeline.lastRiskScore} level={pipeline.lastRiskLevel} size="md" />
          </div>
        </header>
      )}

      <div className="detail-content detail-grid">
        <aside className="run-history-sidebar card glass-panel">
          <h3>Run History</h3>
          <p className="muted mb-2">Select a build log to inspect CI/CD events.</p>
          <ul className="run-list">
            {runs.map((run) => (
              <li key={run.runId} className={run.runId === selectedRun?.runId ? 'active-run-item' : 'run-item'}>
                <button type="button" onClick={() => onSelectRun?.(run.runId)}>
                  <div className="run-list-top">
                    <span>{run.runId}</span>
                    <RiskBadge score={run.risk?.score} level={run.risk?.level} size="sm" />
                  </div>
                  <span className="muted">{formatDateTime(run.completedAt)}</span>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <div className="run-detail">
          <RunCard run={selectedRun} onAction={onAction} />

          <section className="card evidence-panel">
            <header className="card-header">
              <h3>Immutable evidence</h3>
              <span className={`proof-status ${proofCheck.valid ? 'proof-valid' : 'proof-invalid'}`}>
                {proofCheck.valid ? 'Valid' : 'Invalid'}
              </span>
            </header>
            {selectedRun?.immutableProof ? (
              <dl className="proof-grid">
                <div><dt>Ledger Hash</dt><dd>{selectedRun.immutableProof.chainHash}</dd></div>
                <div><dt>Transaction Id</dt><dd>{selectedRun.immutableProof.txId}</dd></div>
                <div><dt>Signature</dt><dd>{selectedRun.immutableProof.signature}</dd></div>
                <div><dt>Verification</dt><dd>{proofCheck.reason}</dd></div>
              </dl>
            ) : (
              <p className="muted">No immutable proof attached.</p>
            )}

            <div className="evidence-links">
              <button
                type="button"
                className="evidence-btn"
                onClick={() => onAction?.('viewLogs', selectedRun)}
              >
                <span className="icon">📄</span> View Logs
              </button>
              <button
                type="button"
                className="evidence-btn"
                onClick={() => onAction?.('inspectDiff', selectedRun)}
              >
                <span className="icon">🔀</span> Inspect Diff
              </button>
              <button
                type="button"
                className="evidence-btn"
                onClick={() => onAction?.('scaReport', selectedRun)}
              >
                <span className="icon">🛡️</span> SCA Report
              </button>
            </div>
          </section>

          <section className="card timeline-wrapper">
            <header className="card-header">
              <h3>Stage timeline</h3>
              <p className="muted">Each checkpoint must pass for deployment to proceed.</p>
            </header>
            <Timeline stages={selectedRun?.stages || []} />
          </section>
        </div>
      </div>
    </section>
  );
};

export default PipelineDetail;
