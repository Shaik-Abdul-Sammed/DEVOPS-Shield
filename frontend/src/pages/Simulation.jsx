import React, { useMemo, useState, useEffect } from 'react';
import './Simulation.css';
import RiskBadge from '../components/RiskBadge';
import RiskGraph from '../components/RiskGraph';
import zeroTrustService from '../api/zeroTrustService';
import simulateController from '../api/simulateController';
import { formatDateTime } from '../utils/dateHelpers';

const eventTemplates = {
  'supply-chain': [
    { phase: 'Intelligence', detail: 'Unknown package version uploaded to private registry.' },
    { phase: 'Hash Verification', detail: 'SHA-256 integrity check failed for @internal/node-core.' },
    { phase: 'Build', detail: 'Dependency Sentinel detects hash mismatch versus SBOM baseline.' },
    { phase: 'Signing', detail: 'Artifact Hardening rejects unsigned binary and quarantines output.' },
    { phase: 'Blockchain', detail: 'Recording supply-chain breach attempt to Ethereum ledger.' },
    { phase: 'Response', detail: 'Runner token revoked, maintainers alerted, incident ticket created.' }
  ],
  'secret-leak': [
    { phase: 'Scan', detail: 'Entropy-based secret scanning triggered on build stdout.' },
    { phase: 'Build', detail: 'Log sanitization rules flag PAT string inside test output.' },
    { phase: 'Identity', detail: 'Verifying actor "contractor-447" against behavioral baseline.' },
    { phase: 'Source Integrity', detail: 'Identity model lowers trust score due to leaked token usage.' },
    { phase: 'Response', detail: 'Credential revoked and SIEM notified for downstream investigation.' }
  ],
  'rogue-runner': [
    { phase: 'Provision', detail: 'New runner joined with unrecognized fingerprint and outdated kernel patches.' },
    { phase: 'Fingerprinting', detail: 'Hardware ID 0x882f-ac matched against blacklisted VM templates.' },
    { phase: 'Behaviour', detail: 'Behavioral AI flags inconsistent command invocation pattern.' },
    { phase: 'Containment', detail: 'Runner isolated, PKCE challenge re-authenticates maintainer, SOC escalated.' }
  ]
};

const remediationData = {
  'supply-chain': {
    title: 'Supply Chain Hardening',
    steps: [
      'Implement SHA-256 pinning for all external dependencies.',
      'Enable mandatory signed commits and artifact signing.',
      'Configure private registry to reject overrides of stable versions.'
    ]
  },
  'secret-leak': {
    title: 'Secret Management Strategy',
    steps: [
      'Rotate all affected credentials immediately (Automated).',
      'Enable pre-commit hooks to block secrets before they reach the CI.',
      'Migrate to short-lived OIDC tokens for runner authentication.'
    ]
  },
  'rogue-runner': {
    title: 'Runner Security Policy',
    steps: [
      'Enforce hardware-backed identity (TPM) for all private runners.',
      'Apply egress filtering to block unrecognized outbound connections.',
      'Scale down the infected runner group and re-image from golden source.'
    ]
  }
};

const Simulation = ({ scenarios = [], history = [], onIncident, onReset, currentRisk = 0 }) => {
  const [riskHistory, setRiskHistory] = useState(history);
  const [activeScenarioId, setActiveScenarioId] = useState(null);
  const [events, setEvents] = useState([]);
  const [loadingScenario, setLoadingScenario] = useState(false);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [lastRunAt, setLastRunAt] = useState(null);
  const [incidentSummary, setIncidentSummary] = useState(null);
  const [currentRiskScore, setCurrentRiskScore] = useState(currentRisk);

  // Sync with prop from App.jsx
  useEffect(() => {
    if (currentRisk !== undefined) {
      setCurrentRiskScore(currentRisk);
    }
  }, [currentRisk]);

  const activeScenario = useMemo(
    () => scenarios.find((scenario) => scenario.id === activeScenarioId) || null,
    [scenarios, activeScenarioId]
  );

  const runScenario = async (scenario) => {
    setLoadingScenario(true);
    setActiveScenarioId(scenario.id);
    setEvents([]);
    setBackendStatus('checking');
    setIncidentSummary(null);
    setCurrentRiskScore(scenario.riskScore || 0);

    const timeline = [];
    const addEvent = (phase, detail, timestamp = new Date()) => {
      timeline.push({
        phase,
        detail,
        timestamp: timestamp instanceof Date ? timestamp.toISOString() : timestamp
      });
    };

    const clampRisk = (value) => Math.min(100, Math.max(0, value));
    const randomHex = (length = 16) => Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join('');

    let computedRisk = scenario.riskScore ?? 60;
    let fraudEvent = null;

    try {
      const health = await zeroTrustService.healthCheck();
      const status = health?.status ?? 'healthy';
      setBackendStatus(status);
      addEvent('Health Check', `Core services responded: ${status}`);
    } catch (error) {
      console.error('Health check failed before simulation', error);
      setBackendStatus('unavailable');
      addEvent('Health Check', `Health check failed: ${error.message || 'backend unreachable'}`);
    }

    try {
      const response = await simulateController.simulateFraud(scenario.id);
      fraudEvent = response?.fraud_event || response?.data?.fraud_event || response;

      if (fraudEvent?.event_id) {
        const fraudRisk = typeof fraudEvent.risk_score === 'number' ? fraudEvent.risk_score * 100 : 0;
        if (!Number.isNaN(fraudRisk)) {
          computedRisk = Math.round((computedRisk + fraudRisk) / 2);
        }
        addEvent(
          'Fraud Signal',
          `${fraudEvent.message || 'Simulated fraudulent activity detected'} · risk ${(fraudRisk || computedRisk).toFixed(0)}%`,
          fraudEvent.timestamp || new Date().toISOString()
        );
      } else {
        addEvent('Fraud Signal', 'Simulation service responded without details');
      }
    } catch (error) {
      console.error('Simulation API error', error);
      addEvent('Fraud Signal', `Simulation API error: ${error.message || 'Unknown failure'}`);
    }

    const handleScenario = async () => {
      switch (scenario.id) {
        case 'supply-chain': {
          try {
            const manifest = {
              'trusted-core': '1.4.2',
              'zero-day-kit': '4.2.1',
              '@internal/telemetry': '2.1.0'
            };
            const deps = await zeroTrustService.checkDependencies(manifest);
            const blocked = deps?.blocked_packages?.length || 0;
            addEvent(
              'Dependency Sentinel',
              blocked
                ? `Blocked packages: ${deps.blocked_packages.join(', ')}`
                : 'All packages matched SBOM baseline'
            );
            computedRisk = clampRisk(computedRisk + (blocked ? 12 : -8));
          } catch (error) {
            console.error('Dependency check failed', error);
            addEvent('Dependency Sentinel', `Dependency service error: ${error.message || 'Unable to verify packages'}`);
          }

          try {
            const ledger = await zeroTrustService.recordToBlockchain({
              step: 'supply_chain_response',
              hash: randomHex(64),
              previous_hash: randomHex(64),
              metadata: {
                scenario: scenario.id,
                pipeline_id: scenario.pipeline || 'global-supply-chain',
                initiated_by: 'attack-simulator'
              }
            });
            addEvent(
              'Blockchain Ledger',
              ledger?.recorded
                ? 'Immutable ledger entry stored for forensic audit'
                : 'Ledger rejected the record — investigate integrity'
            );
            if (!ledger?.recorded) {
              computedRisk = clampRisk(computedRisk + 6);
            }
          } catch (error) {
            console.error('Ledger write failed', error);
            addEvent('Blockchain Ledger', `Ledger service error: ${error.message || 'Unable to record event'}`);
            computedRisk = clampRisk(computedRisk + 8);
          }
          break;
        }

        case 'secret-leak': {
          try {
            const sourceVerdict = await zeroTrustService.verifySourceIntegrity({
              developer_id: 'contractor-447',
              commit_sha: randomHex(40),
              device_id: 'runner-12f',
              ip_address: '185.44.12.9',
              timestamp: new Date().toISOString(),
              has_secrets: true
            });
            addEvent(
              'Source Integrity',
              `Identity score ${(sourceVerdict.identity_score * 100).toFixed(1)}% · ${sourceVerdict.approved ? 'Approved' : 'Blocked'}${sourceVerdict.secrets_found ? ' · Secrets detected' : ''}`
            );
            computedRisk = clampRisk(
              computedRisk + (sourceVerdict.secrets_found ? 18 : sourceVerdict.approved ? -10 : 5)
            );
          } catch (error) {
            console.error('Source integrity check failed', error);
            addEvent('Source Integrity', `Verification error: ${error.message || 'Identity model unreachable'}`);
            computedRisk = clampRisk(computedRisk + 10);
          }

          try {
            const ledger = await zeroTrustService.recordToBlockchain({
              step: 'secret_rotation',
              hash: randomHex(64),
              previous_hash: randomHex(64),
              metadata: {
                scenario: scenario.id,
                action: 'credential-rotation',
                rotation_window_minutes: 5
              }
            });
            addEvent(
              'Credential Ledger',
              ledger?.recorded
                ? 'Secret rotation recorded immutably'
                : 'Ledger write skipped — verify backup rotation'
            );
          } catch (error) {
            console.error('Credential ledger write failed', error);
            addEvent('Credential Ledger', `Ledger error: ${error.message || 'Audit trail unavailable'}`);
          }
          break;
        }

        case 'rogue-runner': {
          try {
            const artifact = await zeroTrustService.verifyArtifact({
              artifact_hash: randomHex(96),
              signature: `sig-${randomHex(48)}`
            });
            addEvent(
              'Artifact Hardening',
              artifact?.approved
                ? 'Artifact signature verified and sandbox clean'
                : 'Artifact verification blocked — signature mismatch'
            );
            computedRisk = clampRisk(computedRisk + (artifact?.approved ? -12 : 15));
          } catch (error) {
            console.error('Artifact verification failed', error);
            addEvent('Artifact Hardening', `Verification error: ${error.message || 'Sandbox offline'}`);
            computedRisk = clampRisk(computedRisk + 12);
          }

          try {
            const deps = await zeroTrustService.checkDependencies({
              '@security/kernel-patch': '5.17.12',
              'runner-image': '2025.12.01',
              'rogue-runner': 'latest'
            });
            const rogueBlocked = deps?.blocked_packages?.includes('rogue-runner');
            addEvent(
              'Runner Integrity',
              rogueBlocked
                ? 'Untrusted runner binary quarantined'
                : 'Runner packages align with baseline'
            );
            computedRisk = clampRisk(computedRisk + (rogueBlocked ? -14 : 6));
          } catch (error) {
            console.error('Runner dependency check failed', error);
            addEvent('Runner Integrity', `Runner verification error: ${error.message || 'Unable to inspect image'}`);
          }
          break;
        }

        default:
          break;
      }
    };

    try {
      await handleScenario();
    } catch (error) {
      console.error('Scenario execution failed', error);
      addEvent('Simulation', `Scenario execution failed: ${error.message || 'Unexpected error'}`);
      computedRisk = clampRisk(computedRisk + 6);
    } finally {
      const template = eventTemplates[scenario.id] || [];
      const existingPhases = new Set(timeline.map((event) => event.phase));
      template.forEach((step, index) => {
        if (!existingPhases.has(step.phase)) {
          addEvent(step.phase, step.detail, new Date(Date.now() + (index + 1) * 1000));
        }
      });

      setEvents(timeline);

      const normalizedRisk = clampRisk(computedRisk) / 100;
      const finalRiskScore = Math.max(0, Math.round(normalizedRisk * 100));
      const fraudRisk = fraudEvent?.risk_score ? Math.max(fraudEvent.risk_score * 100, 1) : computedRisk;
      const riskPoint = {
        date: new Date().toISOString().split('T')[0],
        riskScore: normalizedRisk,
        analyses: 18 + Math.round(fraudRisk / 10),
        alerts: Math.max(1, Math.round(normalizedRisk * 12))
      };

      setRiskHistory((prev) => [...prev, riskPoint]);
      setLastRunAt(new Date().toISOString());
      setLoadingScenario(false);

      const incident = {
        id: `SIM-${(fraudEvent?.event_id || randomHex(6)).toString().toUpperCase()}`,
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        pipelineId: scenario.pipeline || 'global-secops',
        riskScore: finalRiskScore,
        alerts: riskPoint.alerts,
        timestamp: new Date().toISOString(),
        message: timeline[0]?.detail || scenario.description
      };

      setIncidentSummary(incident);
      setCurrentRiskScore(finalRiskScore);
      onIncident?.(incident);

      // Trigger popup for High/Critical scores
      if (finalRiskScore >= 75) {
        setTimeout(() => {
          window.alert(`🚨 ${finalRiskScore >= 90 ? 'CRITICAL' : 'HIGH'} RISK DETECTED!\nScenario: ${scenario.name}\nRisk Score: ${finalRiskScore}%`);
        }, 500);
      }
    }
  };

  const resetSimulation = () => {
    setActiveScenarioId(null);
    setEvents([]);
    setLastRunAt(null);
    setBackendStatus('checking');
    setIncidentSummary(null);
    setCurrentRiskScore(0);
    onReset?.();
  };

  const displayRiskScore = useMemo(() => {
    // Priority: 1. Current simulation result, 2. Prop from App.jsx, 3. active scenario baseline
    if (incidentSummary) return incidentSummary.riskScore;
    if (currentRiskScore > 0) return currentRiskScore;
    return activeScenario ? activeScenario.riskScore : 0;
  }, [incidentSummary, currentRiskScore, activeScenario]);

  return (
    <div className="simulation-page">
      <div className="page-header">
        <div>
          <h1>Attack Simulation</h1>
          <p className="page-subtitle">Run supply-chain and secret-leak drills, watch mitigation steps, and capture audit evidence.</p>
        </div>
      </div>

      <section className="card simulation-hero">
        <header className="card-header">
          <div>
            <h2>Attack simulation lab</h2>
            <p className="muted">Recreate real-world supply-chain incidents and watch DevOps Shield contain the breach in real time.</p>
            <div className="simulation-levels" style={{ marginTop: '12px', display: 'flex', gap: '16px' }}>
              <span className="level-item"><span className="dot critical"></span> Critical (90+)</span>
              <span className="level-item"><span className="dot high"></span> High (75-89)</span>
              <span className="level-item"><span className="dot medium"></span> Medium (50-74)</span>
            </div>
          </div>
          <div className="simulation-risk-indicator">
            <span className="label">Simulated risk</span>
            <RiskBadge score={displayRiskScore} size="lg" />
          </div>
        </header>
      </section>

      <div className="simulation-grid">
        <div className="simulation-stat-card">
          <span className="label">Current risk</span>
          <strong className="stat-value">{displayRiskScore}%</strong>
        </div>
        <div className="simulation-stat-card">
          <span className="label">Backend status</span>
          <strong className="stat-value">{backendStatus}</strong>
        </div>
        <div className="simulation-stat-card">
          <span className="label">Last drill</span>
          <strong className="stat-value">{lastRunAt ? formatDateTime(lastRunAt) : 'Not run yet'}</strong>
        </div>
        <div className="simulation-stat-card">
          <span className="label">Risk history points</span>
          <strong className="stat-value">{riskHistory.length}</strong>
        </div>
      </div>

      <div className="simulation-actions">
        {scenarios.map((scenario) => (
          <button
            key={scenario.id}
            type="button"
            className={`btn-outline scenario-button ${scenario.id === activeScenarioId ? 'active' : ''}`}
            onClick={() => runScenario(scenario)}
            disabled={loadingScenario}
          >
            {loadingScenario && scenario.id === activeScenarioId ? 'Simulating...' : `Run ${scenario.name}`}
          </button>
        ))}
        <button type="button" className="btn-ghost" onClick={resetSimulation} disabled={loadingScenario}>Reset</button>
      </div>

      <section className="simulation-content">
        <div className="simulation-main">
          <RiskGraph data={riskHistory} />
        </div>
        <aside className="simulation-sidebar">
          {activeScenario ? (
            <div className="card scenario-detail">
              <h3>{activeScenario.name}</h3>
              <p className="muted">{activeScenario.description}</p>
              <div className="scenario-stats">
                <div className="stat-item">
                  <span className="label">Risk score</span>
                  <strong>{displayRiskScore}</strong>
                </div>
                <div className="stat-item">
                  <span className="label">Threat level</span>
                  <strong>{activeScenario.type}</strong>
                </div>
              </div>
              <div className="scenario-meta">
                <span className="label">Detections triggered</span>
                <ul className="detections">
                  {activeScenario.detections.map((detection) => (
                    <li key={detection}>{detection}</li>
                  ))}
                </ul>
              </div>
              <div className="scenario-meta">
                <span className="label">Mitigation</span>
                <p>{activeScenario.mitigation}</p>
              </div>
            </div>
          ) : (
            <div className="card scenario-placeholder">
              <h3>Select a scenario to begin</h3>
              <p className="muted">Choose a simulated attack from the left to generate risk telemetry and incident timeline.</p>
            </div>
          )}
        </aside>
      </section>

      {incidentSummary && (
        <section className="card simulation-incident">
          <header className="card-header">
            <div>
              <h3>Latest simulated incident</h3>
              <p className="muted">Alert broadcast to responders and surfaced in the incident queue.</p>
            </div>
            <RiskBadge score={incidentSummary.riskScore} level={activeScenario?.type} />
          </header>
          <dl className="incident-grid">
            <div>
              <dt>Incident id</dt>
              <dd>{incidentSummary.id}</dd>
            </div>
            <div>
              <dt>Pipeline</dt>
              <dd>{incidentSummary.pipelineId}</dd>
            </div>
            <div>
              <dt>Risk</dt>
              <dd>{incidentSummary.riskScore}%</dd>
            </div>
            <div>
              <dt>Alerts generated</dt>
              <dd>{incidentSummary.alerts}</dd>
            </div>
            <div>
              <dt>Detected at</dt>
              <dd>{formatDateTime(incidentSummary.timestamp)}</dd>
            </div>
          </dl>
          <p className="muted">{incidentSummary.message}</p>

          <div className="simulation-remediation glass-panel">
            <h4>🛡️ High-Yield Remediation</h4>
            <p className="remediation-title">{remediationData[incidentSummary.scenarioId]?.title}</p>
            <ul>
              {remediationData[incidentSummary.scenarioId]?.steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </div>
        </section>
      )}

      <section className="card simulation-events">
        <header className="card-header">
          <h3>Incident timeline</h3>
          <p className="muted">Every control plane that activates during the simulated compromise.</p>
        </header>
        {events.length > 0 ? (
          <ol className="event-timeline">
            {events.map((event) => (
              <li key={`${event.phase}-${event.timestamp}`}>
                <div className="event-phase">{event.phase}</div>
                <div className="event-detail">{event.detail}</div>
                <div className="event-time">{formatDateTime(event.timestamp)}</div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="muted">No events yet — run a scenario to populate the timeline.</p>
        )}
      </section>
    </div>
  );
};

export default Simulation;
