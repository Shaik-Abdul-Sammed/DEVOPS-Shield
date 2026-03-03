import React, { useState } from 'react';
import './Integrations.css';

const MOCK_INTEGRATIONS = [
  { id: 'github', name: 'GitHub', type: 'Source Control', status: 'Connected', icon: '🐱', description: 'Monitor CI/CD workflows and repository alerts.' },
  { id: 'slack', name: 'Slack', type: 'Notifications', status: 'Disconnected', icon: '💬', description: 'Route high-severity alerts to specific channels.' },
  { id: 'jira', name: 'Jira', type: 'Ticketing', status: 'Connected', icon: '🎫', description: 'Automatically create Jira tickets for critical incidents.' },
  { id: 'pagerduty', name: 'PagerDuty', type: 'Incident Response', status: 'Disconnected', icon: '🚨', description: 'Trigger on-call pages for urgent security events.' },
  { id: 'datadog', name: 'Datadog', type: 'Monitoring', status: 'Disconnected', icon: '🐶', description: 'Export telemetry data to Datadog dashboards.' },
  { id: 'aws', name: 'AWS Security Hub', type: 'Cloud Security', status: 'Connected', icon: '☁️', description: 'Sync findings directly to AWS Security Hub.' }
];

const Integrations = ({ addNotification }) => {
  const [integrations, setIntegrations] = useState(MOCK_INTEGRATIONS);

  const handleToggle = (id) => {
    setIntegrations(prev => prev.map(integration => {
      if (integration.id === id) {
        const newStatus = integration.status === 'Connected' ? 'Disconnected' : 'Connected';
        addNotification(`${integration.name} integration ${newStatus.toLowerCase()}.`, newStatus === 'Connected' ? 'success' : 'warning');
        return {
          ...integration,
          status: newStatus
        };
      }
      return integration;
    }));
  };

  return (
    <div className="page integrations-page">
      <header className="page-header">
        <div>
          <h1>Integration Hub</h1>
          <p className="page-subtitle">Connect third-party tools to extend DevOps Shield capabilities.</p>
        </div>
      </header>

      <div className="integrations-grid">
        {integrations.map(integration => (
          <div key={integration.id} className="card integration-tile">
            <div className="integration-tile-header">
              <div className="integration-icon-wrapper">
                <span className="integration-icon">{integration.icon}</span>
              </div>
              <span className={`badge badge-${integration.status === 'Connected' ? 'success' : 'idle'}`}>
                {integration.status}
              </span>
            </div>

            <div className="integration-info">
              <h3>{integration.name}</h3>
              <p className="muted type">{integration.type}</p>
              <p className="description">{integration.description}</p>
            </div>

            <div className="integration-actions">
              <button
                className={`btn-${integration.status === 'Connected' ? 'outline' : 'primary'} enhance-hover full-width`}
                onClick={() => handleToggle(integration.id)}
              >
                {integration.status === 'Connected' ? 'Configure' : 'Connect'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Integrations;
