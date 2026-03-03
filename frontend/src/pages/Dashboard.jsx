import React, { useMemo } from 'react';
import RunCard from '../components/RunCard';
import RiskBadge from '../components/RiskBadge';
import AlertsTable from '../components/AlertsTable';
import ImpactMetrics from '../components/ImpactMetrics.jsx';
import SecurityHighlights from '../components/SecurityHighlights.jsx';
import { formatDateTime } from '../utils/dateHelpers';

const Dashboard = ({
  pipelines = [],
  runsByPipeline = {},
  alerts = [],
  impactMetrics = {},
  authSession,
  securityHighlights = [],
  integrations = [],
  latestIncident,
  onRunAction,
  onAlertAction,
  onSelectPipeline,
  onViewAlerts,
  onManageIntegrations
}) => {
  const allRuns = useMemo(() => Object.values(runsByPipeline).flat(), [runsByPipeline]);
  const highestRiskRun = useMemo(() => [...allRuns].sort((a, b) => (b.risk?.score || 0) - (a.risk?.score || 0))[0], [allRuns]);

  const githubIntegration = useMemo(
    () => integrations.find((integration) => integration.id === 'github'),
    [integrations]
  );

  const overallRiskScore = useMemo(() => {
    const runRiskSum = allRuns.reduce((acc, run) => acc + (run.risk?.score || 0), 0);
    const runCount = allRuns.length;

    let totalRiskSum = runRiskSum;
    let totalItems = runCount;

    if (githubIntegration?.repositories?.length) {
      const repoRiskSum = githubIntegration.repositories.reduce((acc, repo) => acc + (repo.riskScore || 0), 0);
      totalRiskSum += repoRiskSum;
      totalItems += githubIntegration.repositories.length;
    }

    return Math.round(totalRiskSum / Math.max(totalItems, 1));
  }, [allRuns, githubIntegration]);

  const topPipelines = pipelines.slice(0, 3);
  const highSeverityAlerts = alerts.filter((alert) => alert.severity === 'High' || alert.severity === 'Critical').length;
  const blockedDeploys = impactMetrics?.blockedMaliciousDeploys ?? 0;
  const protectedUsers = impactMetrics?.protectedUsers ?? 0;



  return (
    <>
      <div className="page-header">
        <div>
          <h1>Security Command Center</h1>
          <p className="page-subtitle">Unified view of CI/CD risk posture, live incidents, and top pipelines to investigate.</p>
        </div>
        <RiskBadge score={overallRiskScore} size="lg" />
      </div>

      <section className="card overview-band">
        <div className="overview-grid">
          <div className="overview-card">
            <div className="overview-icon">🛡️</div>
            <p className="label">Pipelines monitored</p>
            <h3>{pipelines.length}</h3>
            <p className="muted">Active with guardrails</p>
          </div>
          <div className="overview-card">
            <div className="overview-icon">🚨</div>
            <p className="label">Critical / High alerts</p>
            <h3>{highSeverityAlerts}</h3>
            <p className="muted">Requires immediate triage</p>
          </div>
          <div className="overview-card">
            <div className="overview-icon">⛔</div>
            <p className="label">Malicious deploys blocked</p>
            <h3>{blockedDeploys}</h3>
            <p className="muted">Stopped before reaching prod</p>
          </div>
          <div className="overview-card">
            <div className="overview-icon">👥</div>
            <p className="label">Users protected</p>
            <h3>{protectedUsers.toLocaleString()}</h3>
            <p className="muted">Citizens shielded via CI/CD</p>
          </div>
          <div className="overview-card">
            <div className="overview-icon">📉</div>
            <p className="label">Mean pipeline risk</p>
            <h3>{overallRiskScore}</h3>
            <p className="muted">Rolling average across runs</p>
          </div>
        </div>
      </section>

      <div className="grid dashboard-grid">
        <section className="card span-2">
          <header className="card-header">
            <div>
              <h2>Live risk posture</h2>
              <p className="muted">CI/CD guardrails across {pipelines.length} pipelines.</p>
            </div>
            <RiskBadge score={overallRiskScore} size="lg" />
          </header>
          <div className="dashboard-metrics">
            <div>
              <span className="label">Active pipelines</span>
              <span>{pipelines.length}</span>
            </div>
            <div>
              <span className="label">High-risk incidents</span>
              <span>{alerts.filter((alert) => alert.severity === 'High' || alert.severity === 'Critical').length}</span>
            </div>
            <div>
              <span className="label">Malicious deploys blocked</span>
              <span>{impactMetrics.blockedMaliciousDeploys ?? 0}</span>
            </div>
            <div>
              <span className="label">Critical infra pipelines</span>
              <span>{pipelines.filter((p) => p.tags?.includes('civinfra')).length}</span>
            </div>
            <div>
              <span className="label">GitHub OAuth</span>
              <span>{authSession?.status ?? 'Unknown'}</span>
            </div>
            <div>
              <span className="label">PKCE enforced</span>
              <span>{authSession?.pkce ? 'Yes' : 'Review'}</span>
            </div>
          </div>
        </section>

        {githubIntegration && (
          <section className="card integration-card">
            <header className="card-header">
              <div>
                <h2>GitHub posture</h2>
                <p className="muted">OAuth health, runner integrity, and secrets management at a glance.</p>
              </div>
              <button type="button" className="btn-outline" onClick={() => onManageIntegrations?.()}>
                Manage integrations
              </button>
            </header>

            <dl className="status-grid">
              <div>
                <dt>Status</dt>
                <dd>{githubIntegration?.status}</dd>
              </div>
              <div>
                <dt>Last synced</dt>
                <dd>{githubIntegration?.lastSync ? formatDateTime(githubIntegration.lastSync) : 'Never'}</dd>
              </div>
              <div>
                <dt>Runners</dt>
                <dd>{githubIntegration?.runners ?? '—'}</dd>
              </div>
              <div>
                <dt>Quarantines</dt>
                <dd>{githubIntegration?.quarantines ?? 0}</dd>
              </div>
              <div>
                <dt>Secrets rotation</dt>
                <dd>{githubIntegration?.secretsRotated ?? 0}</dd>
              </div>
              <div>
                <dt>PKCE enforced</dt>
                <dd>{githubIntegration?.pkce ? 'Yes' : 'No'}</dd>
              </div>
            </dl>
          </section>
        )}

        <section className="card span-2">
          <header className="card-header">
            <h2>Top watch pipelines</h2>
            <p className="muted">Focus on the pipelines shaping national scale services.</p>
          </header>
          <div className="top-pipelines">
            {topPipelines.length > 0 ? topPipelines.map((pipeline) => (
              <button key={pipeline.id} type="button" className="top-pipeline-card" onClick={() => onSelectPipeline?.(pipeline.id)}>
                <div className="top-pipeline-card-header">
                  <h3>{pipeline.name}</h3>
                  <RiskBadge score={pipeline.lastRiskScore} level={pipeline.lastRiskLevel} />
                </div>
                <p className="muted">Last run status: {pipeline.lastStatus}</p>
                <div className="tags">
                  {pipeline.tags?.map((tag) => <span key={tag} className="tag">{tag}</span>)}
                </div>
                <span className="btn-link" aria-hidden="true" onClick={(e) => { e.stopPropagation(); onSelectPipeline?.(pipeline.id); }}>View pipeline -&gt;</span>
              </button>
            )) : (
              <p className="muted">No pipelines tracked yet. Connect a repository to begin monitoring.</p>
            )}
          </div>
        </section>

        {githubIntegration && (
          <section className="card integration-card">
            <header className="card-header">
              <div>
                <h3>GitHub integration</h3>
                <p className="muted">{githubIntegration.critical ? 'Critical connector' : 'Optional integration'}</p>
              </div>
              <span className={`badge ${githubIntegration.status === 'Connected' ? 'badge-success' : 'badge-idle'}`}>
                {githubIntegration.status}
              </span>
            </header>
            <dl className="integration-meta">
              <div>
                <dt>Last sync</dt>
                <dd>{githubIntegration.lastSync ? formatDateTime(githubIntegration.lastSync) : 'Never'}</dd>
              </div>
              <div>
                <dt>Scopes</dt>
                <dd>{githubIntegration.scopes?.join(', ') || '—'}</dd>
              </div>
              <div>
                <dt>Org coverage</dt>
                <dd>{authSession?.organization || 'Not specified'}</dd>
              </div>
            </dl>
            <p className="muted">Manage GitHub credentials or rotate tokens from the GitHub Connect workspace.</p>
            <button type="button" className="btn-outline" onClick={() => onManageIntegrations?.()}>
              Review integrations
            </button>
          </section>
        )}

        {githubIntegration && githubIntegration.repositories && githubIntegration.repositories.length > 0 && (
          <section className="card span-2 github-risks-widget">
            <header className="card-header">
              <div>
                <h2>GitHub Supply Chain Risks</h2>
                <p className="muted">Top-risk monitored repositories from your connected account.</p>
              </div>
              <span className="badge badge-warning">{githubIntegration.repositories.filter(r => r.riskScore > 50).length} High Risk</span>
            </header>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
              {githubIntegration.repositories
                .sort((a, b) => b.riskScore - a.riskScore)
                .slice(0, 3)
                .map(repo => (
                  <div key={repo.id} className="overview-card" style={{ textAlign: 'left', padding: '1rem', position: 'relative' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
                      <h4 style={{ margin: 0, fontSize: '0.9rem', fontWeight: 'bold' }}>{repo.name.split('/')[1] || repo.name}</h4>
                      <RiskBadge riskScore={repo.riskScore} />
                    </div>
                    {repo.securityFindings && repo.securityFindings.length > 0 ? (
                      <div style={{ fontSize: '0.75rem' }}>
                        <p style={{ margin: '0 0 0.5rem 0', color: 'var(--danger-color)', fontWeight: 'bold' }}>
                          ⚠️ {repo.securityFindings[0].category}: {repo.securityFindings[0].severity}
                        </p>
                        <p className="muted" style={{ margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {repo.securityFindings[0].description}
                        </p>
                      </div>
                    ) : (
                      <p className="muted" style={{ fontSize: '0.75rem', margin: 0 }}>No critical findings detected.</p>
                    )}
                    <div style={{ marginTop: '0.75rem', fontSize: '0.7rem', opacity: 0.6 }}>
                      Last scan: {formatDateTime(repo.lastScan)}
                    </div>
                  </div>
                ))}
            </div>
          </section>
        )}

        {highestRiskRun && (
          <RunCard run={highestRiskRun} onAction={onRunAction} />
        )}

        <AlertsTable alerts={alerts.slice(0, 3)} onAction={onAlertAction} />

        <ImpactMetrics data={impactMetrics} />

        <SecurityHighlights items={securityHighlights} />
      </div>
    </>
  );
};

export default Dashboard;
