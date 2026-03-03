import React from 'react';
import './RiskAnalysis.css';

const RiskAnalysis = ({ addNotification }) => {
    // Mock data for Risk vs Commits correlation
    const commitData = [
        { id: '32b8e32', author: 'Abdul Sammed', lines: 364, risk: 12, date: '2026-02-27', msg: 'feat: add project chatbot assistant' },
        { id: 'f3ccc6f', author: 'Shaik Muzkeer', lines: 1420, risk: 78, date: '2026-02-26', msg: 'fix: major simulation engine overhaul' },
        { id: '94b1cbf', author: 'Suhail B K', lines: 45, risk: 5, date: '2026-02-25', msg: 'chore: update blockchain dependencies' },
        { id: 'a2d1f44', author: 'Abdul Sammed', lines: 890, risk: 45, date: '2026-02-24', msg: 'feat: implement enhanced data viz' },
        { id: 'c8e1a2b', author: 'External Contributor', lines: 2100, risk: 92, date: '2026-02-23', msg: 'refactor: legacy auth migration' }
    ];

    const radarMetrics = [
        { label: 'Supply Chain', value: 'High' },
        { label: 'Secret Exposure', value: 'Low' },
        { label: 'Identity Risk', value: 'Medium' },
        { label: 'Rogue Nodes', value: 'Very Low' }
    ];

    const handleExport = () => {
        addNotification('Preparing Risk Analysis CSV export...', 'info');
        setTimeout(() => {
            const header = 'Commit ID,Author,Lines,Risk Score,Date,Message\n';
            const rows = commitData.map(c =>
                `${c.id},"${c.author}",${c.lines},${c.risk},${c.date},"${c.msg}"`
            ).join('\n');
            const csvContent = header + rows;
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `risk-analysis-${new Date().toISOString().slice(0, 10)}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            link.remove();
            window.URL.revokeObjectURL(url);
            addNotification('Risk Analysis Report downloaded.', 'success');
        }, 1200);
    };

    return (
        <div className="risk-analysis-page">
            <header className="page-header">
                <div>
                    <h1>Risk vs Commits Analysis</h1>
                    <p className="muted">Detailed correlation between code velocity and security exposure.</p>
                </div>
                <div className="header-actions">
                    <button
                        className="btn-outline"
                        onClick={handleExport}
                    >Export PDF Report</button>
                </div>
            </header>

            <div className="analysis-grid">
                {/* Velocity vs Risk Summary */}
                <section className="card velocity-risk-summary">
                    <h3>Security Velocity Score</h3>
                    <div className="velocity-score">
                        <span className="score-value">84</span>
                        <span className="score-label">Optimized</span>
                    </div>
                    <p className="muted">Your pipeline is moving 22% faster than last month with only a 3% increase in risk density.</p>
                </section>

                {/* Risk Heatmap Mock */}
                <section className="card risk-heatmap">
                    <h3>Risk Heatmap by Package</h3>
                    <div className="heatmap-container">
                        <div className="heatmap-cell high" title="@internal/auth (88%)">Auth</div>
                        <div className="heatmap-cell medium" title="@internal/api (45%)">API</div>
                        <div className="heatmap-cell low" title="@internal/utils (12%)">Utils</div>
                        <div className="heatmap-cell high" title="@internal/sim-engine (92%)">Engine</div>
                        <div className="heatmap-cell low" title="@internal/ui (5%)">UI</div>
                        <div className="heatmap-cell medium" title="@internal/blockchain (52%)">Chain</div>
                    </div>
                </section>

                {/* Radar Summary */}
                <section className="card attack-surface-radar">
                    <h3>Attack Surface Profile</h3>
                    <div className="radar-grid">
                        {radarMetrics.map(m => (
                            <div key={m.label} className="radar-metric">
                                <span className="label">{m.label}</span>
                                <span className={`value ${m.value.toLowerCase().replace(' ', '-')}`}>{m.value}</span>
                            </div>
                        ))}
                    </div>
                </section>
            </div>

            {/* High Risk Commits Table */}
            <section className="card high-risk-commits">
                <header className="card-header">
                    <h3>Top High-Risk Commits</h3>
                    <span className="badge-critical">Needs Review</span>
                </header>
                <div className="commit-table-wrapper">
                    <table className="commit-table">
                        <thead>
                            <tr>
                                <th>Commit ID</th>
                                <th>Author</th>
                                <th>Impact (Lines)</th>
                                <th>Risk Score</th>
                                <th>Sentiment</th>
                            </tr>
                        </thead>
                        <tbody>
                            {commitData.map(c => (
                                <tr key={c.id}>
                                    <td className="commit-id"><code>{c.id}</code></td>
                                    <td>{c.author}</td>
                                    <td>{c.lines}</td>
                                    <td>
                                        <div className="risk-progress-bar">
                                            <div className="progress" style={{ width: `${c.risk}%`, backgroundColor: c.risk > 70 ? 'var(--danger)' : c.risk > 40 ? 'var(--warning)' : 'var(--success)' }}></div>
                                            <span>{c.risk}%</span>
                                        </div>
                                    </td>
                                    <td className="muted">{c.msg}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
};

export default RiskAnalysis;
