import React from 'react';
import './GitHubScoreCard.css';

const GitHubScoreCard = ({ scoreData }) => {
    if (!scoreData) return null;

    const { scores, metrics, trust_level, repository, real_data } = scoreData;

    const getScoreColor = (score) => {
        if (score > 0.8) return '#10b981'; // Green
        if (score > 0.5) return '#f59e0b'; // Amber
        return '#ef4444'; // Red
    };

    const getTrustBadgeStyle = (level) => {
        switch (level) {
            case 'High': return { background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', border: '1px solid #10b981' };
            case 'Medium': return { background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', border: '1px solid #f59e0b' };
            default: return { background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid #ef4444' };
        }
    };

    return (
        <div className={`github-score-card glass-panel ${real_data ? 'live-data' : 'simulated-data'}`}>
            <header className="score-header">
                <div className="repo-info">
                    <div className="repo-title-row">
                        <h3>{repository}</h3>
                        <span className={`data-source-badge ${real_data ? 'live' : 'sim'}`}>
                            {real_data ? '● Live' : '○ Simulated'}
                        </span>
                    </div>
                    <p className="muted">Security Posture Analysis</p>
                </div>
                <div className="trust-badge" style={getTrustBadgeStyle(trust_level)}>
                    {trust_level} Trust
                </div>
            </header>

            <div className="overall-score-section">
                <div className="score-circle" style={{ borderColor: getScoreColor(scores.overall) }}>
                    <span className="score-value">{Math.round(scores.overall * 100)}</span>
                    <span className="score-label">Overall</span>
                </div>
                <div className="score-breakdown">
                    <div className="metric">
                        <span>Reputation</span>
                        <div className="progress-bar">
                            <div className="progress-fill" style={{ width: `${scores.reputation * 100}%`, backgroundColor: getScoreColor(scores.reputation) }}></div>
                        </div>
                        <span className="metric-val">{Math.round(scores.reputation * 100)}%</span>
                    </div>
                    <div className="metric">
                        <span>Health</span>
                        <div className="progress-bar">
                            <div className="progress-fill" style={{ width: `${scores.health * 100}%`, backgroundColor: getScoreColor(scores.health) }}></div>
                        </div>
                        <span className="metric-val">{Math.round(scores.health * 100)}%</span>
                    </div>
                    <div className="metric">
                        <span>Security</span>
                        <div className="progress-bar">
                            <div className="progress-fill" style={{ width: `${scores.security * 100}%`, backgroundColor: getScoreColor(scores.security) }}></div>
                        </div>
                        <span className="metric-val">{Math.round(scores.security * 100)}%</span>
                    </div>
                </div>
            </div>

            <div className="metrics-grid">
                <div className={`metric-tag ${metrics.signed_commits ? 'pass' : 'fail'}`}>
                    {metrics.signed_commits ? '✓' : '✗'} Signed Commits
                </div>
                <div className={`metric-tag ${metrics.branch_protection ? 'pass' : 'fail'}`}>
                    {metrics.branch_protection ? '✓' : '✗'} Protected Branch
                </div>
                <div className={`metric-tag ${metrics.secret_scanning ? 'pass' : 'fail'}`}>
                    {metrics.secret_scanning ? '✓' : '✗'} Secret Scan
                </div>
                {real_data ? (
                    <>
                        <div className="metric-tag info">
                            ★ {metrics.stars || 0} Stars
                        </div>
                        <div className="metric-tag info">
                            ⑂ {metrics.forks || 0} Forks
                        </div>
                        <div className="metric-tag info">
                            {metrics.open_issues || 0} Issues
                        </div>
                    </>
                ) : (
                    <>
                        <div className={`metric-tag ${metrics.has_2fa ? 'pass' : 'fail'}`}>
                            {metrics.has_2fa ? '✓' : '✗'} 2FA
                        </div>
                        <div className={`metric-tag ${metrics.is_verified ? 'pass' : 'fail'}`}>
                            {metrics.is_verified ? '✓' : '✗'} Verified
                        </div>
                        <div className="metric-tag info">
                            {metrics.account_age_days}d Age
                        </div>
                    </>
                )}
            </div>
        </div>
    );
};

export default GitHubScoreCard;
