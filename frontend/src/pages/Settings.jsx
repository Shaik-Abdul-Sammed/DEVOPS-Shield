import React from 'react';
import { formatDateTime } from '../utils/dateHelpers';
import AuthBanner from '../components/AuthBanner.jsx';
import SecurityHighlights from '../components/SecurityHighlights.jsx';

import apiClient from '../services/apiClient';

const SettingsPage = ({ integrations = [], policies = [], authSession, onReconnect, onDisconnect, onManageIntegrations, securityHighlights = [], onUpdateProfile = () => { } }) => {
  const [isEditing, setIsEditing] = React.useState(false);
  const [formData, setFormData] = React.useState({
    username: authSession?.account || '',
    email: authSession?.email || ''
  });
  const [status, setStatus] = React.useState({ type: '', message: '' });

  // Update form data if authSession changes
  React.useEffect(() => {
    setFormData({
      username: authSession?.account || '',
      email: authSession?.email || ''
    });
  }, [authSession]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (status.message) setStatus({ type: '', message: '' });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (formData.username === authSession?.account && formData.email === authSession?.email) {
      setIsEditing(false);
      return;
    }

    setStatus({ type: 'info', message: 'Updating profile...' });
    try {
      const response = await apiClient.updateProfile(formData);

      if (response.status === 'success') {
        setStatus({ type: 'success', message: 'Profile updated successfully' });
        setTimeout(() => {
          setIsEditing(false);
          setStatus({ type: '', message: '' });
        }, 2000);

        if (typeof onUpdateProfile === 'function') {
          onUpdateProfile(response.user);
        }
      } else {
        setStatus({ type: 'error', message: response.message || 'Update failed' });
      }
    } catch (error) {
      console.error('Profile update failed:', error);
      setStatus({ type: 'error', message: 'Connection error. Please try again.' });
    }
  };

  return (
    <div className="settings-page">
      <div className="page-header">
        <div>
          <h1>Settings & Controls</h1>
          <p className="page-subtitle">Manage integrations, enforce policies, and keep guardrails aligned to standards.</p>
        </div>
      </div>

      <AuthBanner session={authSession} onReconnect={onReconnect} onDisconnect={onDisconnect} />

      {/* Profile Settings Section */}
      <section className="card">
        <header className="card-header">
          <div>
            <h2>Profile Settings</h2>
            <p className="muted">Manage your personal information</p>
          </div>
          {!isEditing && (
            <button type="button" className="btn-outline" onClick={() => setIsEditing(true)}>Edit Profile</button>
          )}
        </header>

        {status.message && (
          <div className={`alert alert-${status.type}`} style={{ padding: '1rem', marginBottom: '1rem', borderRadius: '4px', backgroundColor: status.type === 'error' ? '#fdecea' : '#e8f5e9', color: status.type === 'error' ? '#d32f2f' : '#2e7d32' }}>
            {status.message}
          </div>
        )}

        {isEditing ? (
          <form onSubmit={handleSubmit} className="settings-form" style={{ padding: '1rem' }}>
            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', marginBottom: '0.5rem' }}>Username</label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                className="form-control"
                style={{ padding: '0.5rem', width: '100%', maxWidth: '300px' }}
              />
            </div>
            <div className="form-group" style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', marginBottom: '0.5rem' }}>Email</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleInputChange}
                className="form-control"
                style={{ padding: '0.5rem', width: '100%', maxWidth: '300px' }}
              />
            </div>
            <div className="form-actions" style={{ display: 'flex', gap: '1rem' }}>
              <button type="submit" className="btn-primary">Save Changes</button>
              <button type="button" className="btn-ghost" onClick={() => setIsEditing(false)}>Cancel</button>
            </div>
          </form>
        ) : (
          <div style={{ padding: '0 1.5rem 1.5rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '1rem', alignItems: 'center' }}>
              <strong>Username:</strong> <span>{authSession?.account}</span>
              <strong>Email:</strong> <span>{authSession?.email || 'N/A'}</span>
            </div>
          </div>
        )}
      </section>

      <SecurityHighlights items={securityHighlights} />
      <section className="card">
        <header className="card-header">
          <div>
            <h2>Integrations</h2>
            <p className="muted">Connect code hosts, CI engines, and ticketing systems.</p>
          </div>
          <button type="button" className="btn-outline" onClick={() => onManageIntegrations?.()}>Add integration</button>
        </header>
        <table>
          <thead>
            <tr>
              <th scope="col">Service</th>
              <th scope="col">Status</th>
              <th scope="col">Critical</th>
              <th scope="col">Last sync</th>
              <th scope="col">Scopes</th>
            </tr>
          </thead>
          <tbody>
            {integrations.map((integration) => (
              <tr key={integration.id}>
                <td>{integration.name}</td>
                <td>{integration.status}</td>
                <td>{integration.critical ? 'Yes' : 'No'}</td>
                <td>{integration.lastSync ? formatDateTime(integration.lastSync) : 'Never'}</td>
                <td>{integration.scopes.join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <header className="card-header">
          <h2>Policies & controls</h2>
          <p className="muted">Enforce least privilege, MFA, and artifact quarantine across the platform.</p>
        </header>
        <ul className="policies">
          {policies.map((policy) => (
            <li key={policy.id}>
              <div>
                <h3>{policy.name}</h3>
                <p className="muted">{policy.description}</p>
              </div>
              <span className="policy-status">{policy.status}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
};

export default SettingsPage;
