import React, { useMemo, useState, useEffect, useCallback, useRef } from 'react';
import './Simulation.css';
import RiskBadge from '../components/RiskBadge';
import RiskGraph from '../components/RiskGraph';
import simulateController from '../api/simulateController';
import { formatDateTime } from '../utils/dateHelpers';

// Orchestration Pipeline Stages
const PIPELINE_STAGES = [
  { id: 'source', label: 'SOURCE', icon: '📝' },
  { id: 'scan', label: 'SCAN', icon: '🔍' },
  { id: 'risk', label: 'RISK ENGINE', icon: '⚙️' },
  { id: 'policy', label: 'POLICY', icon: '⚖️' },
  { id: 'gate', label: 'GATE', icon: '🚪' }
];

const Simulation = ({ scenarios = [], history = [], onIncident, onReset }) => {
  const [riskHistory, setRiskHistory] = useState(history);
  const [activeScenarioId, setActiveScenarioId] = useState(null);
  const [loadingScenario, setLoadingScenario] = useState(false);
  const [currentRiskScore, setCurrentRiskScore] = useState(0);
  const [riskFactors, setRiskFactors] = useState(null);
  const [activeStage, setActiveStage] = useState(null);
  const [terminalLogs, setTerminalLogs] = useState([]);
  const [policyDecision, setPolicyDecision] = useState(null); // 'ALLOW' or 'BLOCK'
  const [incidentSummary, setIncidentSummary] = useState(null);
  const [showRemediation, setShowRemediation] = useState(false);

  const logEndRef = useRef(null);

  const activeScenario = useMemo(
    () => scenarios.find((s) => s.id === activeScenarioId) || null,
    [scenarios, activeScenarioId]
  );

  const scrollToBottom = () => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [terminalLogs]);

  const addLog = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setTerminalLogs(prev => [...prev, { timestamp, message, type }]);
  };

  const runSimulationAction = async (scenario) => {
    setLoadingScenario(true);
    setActiveScenarioId(scenario.id);
    setTerminalLogs([]);
    setPolicyDecision(null);
    setActiveStage(null);
    setIncidentSummary(null);
    setShowRemediation(false);
    setCurrentRiskScore(0);
    setRiskFactors(null);

    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    try {
      // 1. SOURCE PHASE
      setActiveStage('source');
      addLog(`Initializing drill: ${scenario.name}`, 'command');
      await sleep(800);
      addLog(`Analyzing source integrity for target: ${scenario.pipeline || 'global-secops'}`, 'info');
      addLog(`Identity verified: ${scenario.id === 'rogue-runner' ? 'ANOMALOUS' : 'VALID'}`, scenario.id === 'rogue-runner' ? 'warn' : 'success');
      await sleep(1000);

      // 2. SCAN PHASE
      setActiveStage('scan');
      addLog('Triggering high-fidelity scanners...', 'command');
      await sleep(500);

      if (scenario.id === 'supply-chain') {
        addLog('Scanning SBOM for dependency anomalies...', 'info');
        await sleep(800);
        addLog('CRITICAL: Malicious package version detected in private registry!', 'error');
        addLog('Hash mismatch: @internal/node-core (Expected: 0x8f2a, Found: 0x3c9e)', 'error');
      } else if (scenario.id === 'secret-leak') {
        addLog('Executing entropy-based secret scanning on build output...', 'info');
        await sleep(800);
        addLog('PATTERN MATCH: GitHub Personal Access Token string found in line 442', 'error');
        addLog('Credential leakage risk level: HIGH', 'warn');
      } else {
        addLog('Monitoring runner behavioral patterns...', 'info');
        await sleep(800);
        addLog('ANOMALY DETECTED: Unrecognized command invocation sequence', 'error');
        addLog('Kernel fingerprint mismatch: 0x882f-ac != golden-baseline', 'error');
      }
      await sleep(1200);

      // 3. RISK ENGINE PHASE
      setActiveStage('risk');
      addLog('Calculating dynamic risk vector...', 'command');
      await sleep(600);

      const response = await simulateController.simulateFraud(scenario.id);
      const fraudData = response?.fraud_event || response;
      const backendFactors = response?.factors || {
        threat: scenario.riskScore / 100,
        exposure: 0.8,
        exploitability: 0.7,
        asset_value: 0.9
      };

      setRiskFactors(backendFactors);
      const finalScore = Math.round(fraudData.risk_score * 100);
      setCurrentRiskScore(finalScore);

      addLog(`Risk Engine Verdict: ${finalScore}% Score`, 'warn');
      addLog(`Factors Analyzed: Threat(${backendFactors.threat}), Exposure(${backendFactors.exposure}), Asset(${backendFactors.asset_value})`, 'info');
      await sleep(1000);

      // 4. POLICY ENGINE PHASE
      setActiveStage('policy');
      addLog('Consulting Governance Policy Engine...', 'command');
      await sleep(800);
      const decision = finalScore > 75 ? 'BLOCK' : 'ALLOW';
      setPolicyDecision(decision);
      addLog(`Policy Decision: ${decision}`, decision === 'BLOCK' ? 'error' : 'success');
      await sleep(1000);

      // 5. GATE PHASE
      setActiveStage('gate');
      if (decision === 'BLOCK') {
        addLog('ENFORCEMENT: Pipeline execution halted.', 'error');
        addLog('ACTION: Triggering automated remediation protocols...', 'warn');
        addLog(`RESPONSE: ${scenario.id === 'supply-chain' ? 'Quarantining artifact' : 'Revoking tokens'}`, 'success');
      } else {
        addLog('ENFORCEMENT: Deployment gateway cleared.', 'success');
      }

      // Wrap up
      const incident = {
        id: `SIM-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        pipelineId: scenario.pipeline || 'global-secops',
        riskScore: finalScore,
        timestamp: new Date().toISOString(),
        message: fraudData.message,
        automated_response: decision === 'BLOCK' ? 'Automated containment active' : 'Monitored'
      };

      setIncidentSummary(incident);
      onIncident?.(incident);

      const riskPoint = {
        date: new Date().toISOString().split('T')[0],
        riskScore: finalScore / 100,
        analyses: 1,
        alerts: 1
      };
      setRiskHistory(prev => [...prev.slice(-10), riskPoint]);

    } catch (error) {
      addLog(`Simulation aborted: ${error.message}`, 'error');
    } finally {
      setLoadingScenario(false);
    }
  };

  const resetSimulation = () => {
    setActiveScenarioId(null);
    setTerminalLogs([]);
    setPolicyDecision(null);
    setActiveStage(null);
    setIncidentSummary(null);
    setCurrentRiskScore(0);
    setRiskFactors(null);
    onReset?.();
  };

  return (
    <div className="simulation-page cyber-theme">
      <div className="page-header">
        <div className="cyber-glitch-container">
          <h1 className="cyber-title" data-text="ATTACK SIMULATION LAB">ATTACK SIMULATION LAB</h1>
          <p className="page-subtitle muted">High-fidelity cyber-range for DevSecOps orchestration and response validation.</p>
        </div>
      </div>

      <div className="simulation-layout">
        {/* Left Column: Scenarios & Controls */}
        <div className="sim-controls">
          <section className="card scenario-selector">
            <h3 className="section-label">SELECT VECTOR</h3>
            <div className="scenario-grid">
              {scenarios.map((s) => (
                <button
                  key={s.id}
                  className={`scenario-card ${s.id === activeScenarioId ? 'active' : ''}`}
                  onClick={() => runSimulationAction(s)}
                  disabled={loadingScenario}
                >
                  <div className="scenario-card-header">
                    <span className="scenario-icon">
                      {s.id === 'supply-chain' ? '📦' : s.id === 'secret-leak' ? '🔑' : '🤖'}
                    </span>
                    <RiskBadge score={s.riskScore} size="sm" />
                  </div>
                  <div className="scenario-card-body">
                    <h4 className="scenario-name">{s.name}</h4>
                    <p className="scenario-desc">{s.description}</p>
                  </div>
                  {s.id === activeScenarioId && <div className="active-scan-line" />}
                </button>
              ))}
            </div>
            <button className="btn-ghost reset-btn" onClick={resetSimulation}>RESET LAB</button>
          </section>

          {/* Risk Engine Visualization */}
          <section className="card risk-engine-viz">
            <h3 className="section-label">DYNAMIC RISK ENGINE</h3>
            <div className="risk-formula">
              <div className="formula-part">
                <span className="part-label">Threat</span>
                <span className="part-value">{(riskFactors?.threat || 0).toFixed(2)}</span>
              </div>
              <span className="operator">×</span>
              <div className="formula-part">
                <span className="part-label">Exposure</span>
                <span className="part-value">{(riskFactors?.exposure || 0).toFixed(2)}</span>
              </div>
              <span className="operator">×</span>
              <div className="formula-part">
                <span className="part-label">Exploit</span>
                <span className="part-value">{(riskFactors?.exploitability || 0).toFixed(2)}</span>
              </div>
              <span className="operator">×</span>
              <div className="formula-part">
                <span className="part-label">Asset</span>
                <span className="part-value">{(riskFactors?.asset_value || 0).toFixed(2)}</span>
              </div>
              <span className="operator">=</span>
              <div className="formula-result">
                <span className="part-label">RESULT</span>
                <span className="risk-value-glitch">{currentRiskScore}%</span>
              </div>
            </div>
            <div className="risk-engine-status">
              <span className="engine-node online">ENGINE v4.2 ONLINE</span>
              <span className="engine-node online">REAL-TIME TELEMETRY ACTIVE</span>
            </div>
          </section>
        </div>

        {/* Right Column: Orchestration & Logs */}
        <div className="sim-orchestration">
          {/* Pipeline Viz */}
          <div className="orchestration-pipeline card">
            {PIPELINE_STAGES.map((stage, idx) => (
              <React.Fragment key={stage.id}>
                <div className={`pipeline-node ${activeStage === stage.id ? 'active' : ''} ${idx < PIPELINE_STAGES.findIndex(s => s.id === activeStage) ? 'completed' : ''}`}>
                  <div className="node-icon">{stage.icon}</div>
                  <span className="node-label">{stage.label}</span>
                </div>
                {idx < PIPELINE_STAGES.length - 1 && (
                  <div className={`pipeline-connector ${idx < PIPELINE_STAGES.findIndex(s => s.id === activeStage) ? 'completed' : ''}`} />
                )}
              </React.Fragment>
            ))}

            {policyDecision && (
              <div className={`policy-badge ${policyDecision.toLowerCase()}`}>
                {policyDecision}
              </div>
            )}
          </div>

          {/* Terminal Logs */}
          <div className="security-terminal">
            <div className="terminal-header">
              <span className="terminal-dot red"></span>
              <span className="terminal-dot yellow"></span>
              <span className="terminal-dot green"></span>
              <span className="terminal-title">INCIDENT_COMMAND_LOG</span>
            </div>
            <div className="terminal-body">
              {terminalLogs.length === 0 ? (
                <div className="terminal-empty">WAITING FOR DRILL INITIALIZATION...</div>
              ) : (
                terminalLogs.map((log, i) => (
                  <div key={i} className={`log-entry log-${log.type}`}>
                    <span className="log-time">[{log.timestamp}]</span>
                    <span className="log-msg">{log.message}</span>
                  </div>
                ))
              )}
              <div ref={logEndRef} />
            </div>
          </div>

          {/* AI Insights & Remediation */}
          {incidentSummary && (
            <div className="ai-insight-panel card animate-slide-up">
              <div className="insight-header">
                <span className="ai-icon">🛡️</span>
                <h3>AI PREDICTIVE REMEDIATION</h3>
              </div>
              <div className="insight-content">
                <p className="impact-prediction">
                  <strong>IMPACT PREDICTION:</strong> High probability of lateral movement if uncontained. Asset value at risk: Multi-tenant build isolation.
                </p>
                <div className="automated-response">
                  <span className="label">AUTOMATED ACTION:</span>
                  <span className="action-text">{incidentSummary.automated_response}</span>
                </div>
                <button
                  className="btn-primary remediation-btn"
                  onClick={() => setShowRemediation(!showRemediation)}
                >
                  {showRemediation ? 'HIDE MITIGATION STEPS' : 'REview MITIGATION STRATEGY'}
                </button>

                {showRemediation && (
                  <div className="mitigation-detail animate-fade-in">
                    <h5>SUGGESTED NEXT STEPS:</h5>
                    <ul>
                      <li>Rotate all service account credentials in Environment ${incidentSummary.pipelineId}</li>
                      <li>Enable mandatory OIDC for all runner registrations.</li>
                      <li>Initiate SBOM re-verification for upstream dependencies.</li>
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Simulation;
