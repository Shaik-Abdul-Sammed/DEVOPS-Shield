import React, { useState, useEffect } from 'react';
import './ThreatIntel.css';
import RiskBadge from '../components/RiskBadge';

const ThreatIntel = ({ addNotification }) => {
  const [feed, setFeed] = useState([
    {
      id: "CVE-2026-10492",
      severity: "CRITICAL",
      description: "Remote Code Execution in unpatched Webpack plugins",
      published: "10 mins ago",
      affected: "React Build Pipelines",
      score: 98
    },
    {
      id: "SIG-APT29-A",
      severity: "HIGH",
      description: "Anomalous GitHub Token exfiltration patterns detected across EU cloud instances",
      published: "1 hour ago",
      affected: "GitHub Actions",
      score: 85
    },
    {
      id: "CVE-2026-09221",
      severity: "MEDIUM",
      description: "Denial of service via algorithmic complexity in FastAPI dependency resolver",
      published: "3 hours ago",
      affected: "Backend Microservices",
      score: 62
    },
    {
      id: "MAL-WORM-JS",
      severity: "HIGH",
      description: "NPM package poisoning campaign targeting specific DevOps CLI tools",
      published: "5 hours ago",
      affected: "Node.js Environment",
      score: 74
    }
  ]);

  const [isScanning, setIsScanning] = useState(false);

  const simulateScan = () => {
    setIsScanning(true);
    addNotification('Synchronizing with global threat feeds...', 'info', 2000);
    setTimeout(() => {
      setIsScanning(false);
      addNotification('Threat intelligence feeds updated.', 'success');
      setFeed(prev => [
        {
          id: `CVE-2026-${Math.floor(Math.random() * 10000)}`,
          severity: "LOW",
          description: "Minor dependency confusion risk in development utilities",
          published: "Just now",
          affected: "Development environment",
          score: 35
        },
        ...prev
      ]);
    }, 2000);
  };

  return (
    <div className="page threat-intel-page">
      <header className="page-header">
        <div>
          <h1>Global Threat Intelligence</h1>
          <p className="page-subtitle">Live CVE tracking, malicious signature streams, and ecosystem vulnerability alerts.</p>
        </div>
        <button
          className={`btn-primary enhance-hover ${isScanning ? 'scanning' : ''}`}
          onClick={simulateScan}
          disabled={isScanning}
        >
          <span className="btn-icon">📡</span> {isScanning ? 'Syncing Feeds...' : 'Force Sync Feed'}
        </button>
      </header>

      <section className="threat-summary">
        <div className="card overview-card threat-stat-card critical">
          <div className="stat-header">
            <h3>Global Critical Threat Level</h3>
            <span className="pulse-dot red"></span>
          </div>
          <div className="stat-value-large">ELEVATED</div>
          <p className="muted">Multiple active zero-days in CI tools.</p>
        </div>

        <div className="card overview-card threat-stat-card">
          <div className="stat-header">
            <h3>Signatures Tracked</h3>
          </div>
          <div className="stat-value-num">1.2M+</div>
          <p className="muted">Updated 2 minutes ago</p>
        </div>

        <div className="card overview-card threat-stat-card">
          <div className="stat-header">
            <h3>Your Exposure Risk</h3>
          </div>
          <RiskBadge score={12} size="lg" />
          <p className="muted" style={{ marginTop: '0.5rem' }}>Shield is active.</p>
        </div>
      </section>

      <section className="card threat-feed-section">
        <div className="card-header">
          <h2>Live Vulnerability Feed</h2>
          <span className="badge badge-idle">Showing Latest</span>
        </div>

        <div className="feed-list">
          {feed.map(item => (
            <div key={item.id} className="feed-item">
              <div className="feed-item-severity">
                <RiskBadge score={item.score} />
              </div>
              <div className="feed-item-content">
                <div className="feed-item-header">
                  <strong>{item.id}</strong>
                  <span className="feed-time">{item.published}</span>
                </div>
                <p className="feed-desc">{item.description}</p>
                <div className="feed-meta">
                  <span className="affected-badge">Target: {item.affected}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

export default ThreatIntel;
