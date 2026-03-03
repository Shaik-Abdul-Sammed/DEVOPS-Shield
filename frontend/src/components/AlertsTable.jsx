import React, { useState } from 'react';
import RiskBadge from './RiskBadge';
import { formatDateTime } from '../utils/dateHelpers';

const AlertsTable = ({ alerts = [], onAction }) => {
  const [filterCritical, setFilterCritical] = useState(false);

  const displayedAlerts = filterCritical
    ? alerts.filter(a => a.severity === 'Critical' || a.severity === 'High')
    : alerts;

  const handleAssign = () => {
    const assignee = window.prompt("Enter assignee username or email (e.g. jdoe@company.com):");
    if (assignee) {
      onAction?.('assign', assignee);
    }
  };

  return (
    <section className="card alerts-table">
      <header className="card-header">
        <div>
          <h2>Active incidents</h2>
          <p className="muted">Prioritized queue: acknowledge, quarantine, or open ticket.</p>
        </div>
        <div className="alerts-actions">
          <button type="button" className={`btn-outline ${filterCritical ? 'active-filter' : ''}`} onClick={() => {
            setFilterCritical(!filterCritical);
            onAction?.('filter', !filterCritical);
          }}>
            <span>{filterCritical ? '❌' : '🔍'}</span>
            {filterCritical ? 'Clear filter' : 'Filter critical'}
          </button>
          <button type="button" className="btn-outline" onClick={handleAssign}>
            <span>👤</span>
            Assign
          </button>
        </div>
      </header>
      <table>
        <thead>
          <tr>
            <th scope="col">Incident</th>
            <th scope="col">Pipeline</th>
            <th scope="col">Severity</th>
            <th scope="col">Risk</th>
            <th scope="col">Status</th>
            <th scope="col">Opened</th>
            <th scope="col">Impact</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {displayedAlerts.length === 0 ? (
            <tr><td colSpan="8" style={{ textAlign: 'center', padding: '2rem' }}>No incidents match the current filters.</td></tr>
          ) : (
            displayedAlerts.map((alert) => {
              const statusLabel = alert.status || 'Open';
              const statusSlug = statusLabel.toLowerCase().replace(/\s+/g, '-');
              const knownStatuses = ['open', 'acknowledged', 'mitigating', 'escalated', 'resolved'];
              const statusClass = `badge ${knownStatuses.includes(statusSlug) ? `badge-${statusSlug}` : 'badge-idle'}`;

              return (
                <tr key={alert.id}>
                  <td>
                    <strong>{alert.title}</strong>
                    <div className="muted">{alert.id}</div>
                  </td>
                  <td>{alert.pipelineId}</td>
                  <td>{alert.severity}</td>
                  <td><RiskBadge score={alert.riskScore} size="sm" /></td>
                  <td><span className={statusClass}>{statusLabel}</span></td>
                  <td>{formatDateTime(alert.createdAt)}</td>
                  <td>{alert.impact}</td>
                  <td className="alerts-actions-cell">
                    <button type="button" className="btn-link" onClick={() => onAction?.('ack', alert)}>
                      <span>✅</span> Acknowledge
                    </button>
                    <button type="button" className="btn-link" onClick={() => onAction?.('rollback', alert)}>
                      <span>⏪</span> Rollback
                    </button>
                    <button type="button" className="btn-link" onClick={() => onAction?.('ticket', alert)}>
                      <span>🎟️</span> Ticket
                    </button>
                    {statusLabel !== 'Resolved' && (
                      <button type="button" className="btn-link" onClick={() => onAction?.('resolve', alert)}>
                        <span>🏁</span> Resolve
                      </button>
                    )}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </section>
  );
};

export default AlertsTable;
