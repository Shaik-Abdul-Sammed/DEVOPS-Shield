import React, { useState } from 'react';
import './Help.css';

const Help = ({ addNotification }) => {
  const [activeFaq, setActiveFaq] = useState(null);

  const faqs = [
    {
      q: "How does the AI detect fraud in CI/CD?",
      a: "Our engine analyzes commit patterns, dependency shifts, and runner behavior using calibrated Machine Learning models to identify anomalies that deviate from your baseline."
    },
    {
      q: "Is the blockchain audit mandatory?",
      a: "Yes, once enabled, every security event is automatically recorded to an Ethereum-backed ledger for immutable proof of compliance."
    },
    {
      q: "Can I integrate with custom self-hosted runners?",
      a: "Absolutely. Our 'Rogue Runner' detection profile can be configured to recognize your hardware fingerprints and TPM signatures."
    }
  ];

  return (
    <div className="help-page">
      <header className="page-header">
        <div>
          <h1>Help & Support</h1>
          <p className="muted">Find documentation, FAQs, and reach out to our security experts.</p>
        </div>
      </header>

      <div className="help-grid">
        {/* Quick Start Card */}
        <section className="card quick-start">
          <div className="card-icon">🚀</div>
          <h3>Quick Start Guide</h3>
          <p className="muted">Get up and running with DevOps Shield in under 5 minutes.</p>
          <ul className="help-links">
            <li><a href="#connect">Connecting GitHub</a></li>
            <li><a href="#simulate">Running your first Attack Drill</a></li>
            <li><a href="#audit">Accessing Blockchain Logs</a></li>
          </ul>
        </section>

        {/* API Docs Card */}
        <section className="card api-docs">
          <div className="card-icon">📂</div>
          <h3>Technical Docs</h3>
          <p className="muted">Deep dive into our architecture, integrations, and security models.</p>
          <button
            className="btn-primary-sm"
            onClick={() => addNotification('Redirecting to official documentation portal...', 'success')}
          >Browse Docs</button>
        </section>

        {/* Contact Card */}
        <section className="card support-card">
          <div className="card-icon">💬</div>
          <h3>Live Support</h3>
          <p className="muted">Need urgent help? Our security team is available 24/7 for MindSprint participants.</p>
          <button
            className="btn-outline-sm"
            onClick={() => addNotification('Support ticket creation dialog opened', 'success')}
          >Open Ticket</button>
        </section>
      </div>

      <section className="card faq-section">
        <h3>Frequently Asked Questions</h3>
        <div className="faq-list">
          {faqs.map((faq, i) => (
            <div key={i} className={`faq-item ${activeFaq === i ? 'active' : ''}`} onClick={() => setActiveFaq(activeFaq === i ? null : i)}>
              <div className="faq-question">
                <span>{faq.q}</span>
                <span className="faq-toggle">{activeFaq === i ? '−' : '+'}</span>
              </div>
              {activeFaq === i && <div className="faq-answer">{faq.a}</div>}
            </div>
          ))}
        </div>
      </section>

      <footer className="help-footer card">
        <div className="footer-content">
          <span className="badge-premium">PREMIUM SUPPORT ENABLED</span>
          <p>MindSprint 2K25 · Team DevOps Security Experts</p>
        </div>
      </footer>
    </div>
  );
};

export default Help;
