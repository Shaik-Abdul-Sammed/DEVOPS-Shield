import React, { useEffect, useMemo, useState, useCallback } from "react";
import { formatDateTime } from "../utils/dateHelpers";
import RiskBadge from "../components/RiskBadge";
import apiClient from "../services/apiClient";

/* ─────────────────────────────────────────────────────────
   Helpers
───────────────────────────────────────────────────────── */
const RISK_LEVELS = ["All", "Critical", "High", "Medium", "Low"];

const riskColor = (level) => {
  switch (level) {
    case "Critical": return "#ef4444";
    case "High": return "#f97316";
    case "Medium": return "#eab308";
    case "Low": return "#22c55e";
    default: return "var(--muted-color, #94a3b8)";
  }
};

const riskBg = (level) => {
  switch (level) {
    case "Critical": return "rgba(239,68,68,0.12)";
    case "High": return "rgba(249,115,22,0.12)";
    case "Medium": return "rgba(234,179,8,0.12)";
    case "Low": return "rgba(34,197,94,0.12)";
    default: return "rgba(148,163,184,0.1)";
  }
};

const visibilityIcon = (v) => (v === "private" ? "🔒" : "🌐");

function ScanGauge({ score }) {
  const c = riskColor(
    score >= 75 ? "Critical" : score >= 55 ? "High" : score >= 30 ? "Medium" : "Low"
  );
  const pct = Math.min(100, score);
  const dasharray = 2 * Math.PI * 20;
  const dashoffset = dasharray * (1 - pct / 100);
  return (
    <svg width="52" height="52" viewBox="0 0 52 52" style={{ flexShrink: 0 }}>
      <circle cx="26" cy="26" r="20" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="5" />
      <circle
        cx="26" cy="26" r="20"
        fill="none"
        stroke={c}
        strokeWidth="5"
        strokeDasharray={dasharray}
        strokeDashoffset={dashoffset}
        strokeLinecap="round"
        style={{ transition: "stroke-dashoffset 0.6s ease", transformOrigin: "center", transform: "rotate(-90deg)" }}
      />
      <text x="26" y="30" textAnchor="middle" fill={c} fontSize="11" fontWeight="700">{score}</text>
    </svg>
  );
}

const defaultFormState = (session) => ({
  username: session?.account || "",
  token: "",
  scopes: session?.scopes?.join(", ") || "repo, admin:repo_hook, workflow",
  org: "",
});

/* ─────────────────────────────────────────────────────────
   Component
───────────────────────────────────────────────────────── */
const GitHubConnect = ({ authSession, integrations, onConnect, onDisconnect, addNotification }) => {
  const [form, setForm] = useState(() => defaultFormState(authSession));
  const [saving, setSaving] = useState(false);
  const [expandedRepo, setExpandedRepo] = useState(null);
  const [filterRisk, setFilterRisk] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [scanningRepos, setScanningRepos] = useState({});   // repoId → bool
  const [repoOverrides, setRepoOverrides] = useState({});   // repoId → partial update
  const [lastToken, setLastToken] = useState("");

  // isDemo is derived from authSession (set by App.jsx on connect response)
  const isDemo = authSession?.isDemo || false;

  const connectionStatus = useMemo(
    () => authSession?.status || "Disconnected",
    [authSession]
  );

  useEffect(() => {
    setForm((prev) => ({
      ...prev,
      username: authSession?.account || prev.username,
      scopes: authSession?.scopes?.join(", ") || prev.scopes,
    }));
  }, [authSession?.account, authSession?.scopes]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    const scopes = form.scopes.split(",").map((s) => s.trim()).filter(Boolean);
    setLastToken(form.token);
    await onConnect?.({ username: form.username, token: form.token, scopes, org: form.org });
    setSaving(false);
    setForm((prev) => ({ ...prev, token: "" }));
  };

  const handleDisconnect = () => {
    setLastToken("");
    setRepoOverrides({});
    onDisconnect?.();
  };

  // Scan a single repo
  const handleScanRepo = useCallback(async (repo) => {
    if (!lastToken) {
      addNotification?.("Re-connect GitHub to enable on-demand scans.", "warning");
      return;
    }
    setScanningRepos((p) => ({ ...p, [repo.id]: true }));
    try {
      const result = await apiClient.scanGitHubRepository(repo.name, {
        token: lastToken,
        username: authSession?.account || form.username,
        org: form.org || undefined,
      });
      setRepoOverrides((p) => ({ ...p, [repo.id]: result }));
      addNotification?.(`Scan complete for ${repo.name}`, "success");
    } catch (err) {
      addNotification?.(`Scan failed: ${err.message}`, "error");
    } finally {
      setScanningRepos((p) => ({ ...p, [repo.id]: false }));
    }
  }, [lastToken, authSession, form, addNotification]);

  const githubIntegration = integrations?.find((i) => i.id === "github");
  const rawRepositories = githubIntegration?.repositories || [];

  // Merge any per-repo scan overrides
  const repositories = rawRepositories.map((r) =>
    repoOverrides[r.id] ? { ...r, ...repoOverrides[r.id] } : r
  );

  // Derive summary counts
  const riskCounts = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    repositories.forEach((r) => { if (counts[r.riskLevel] !== undefined) counts[r.riskLevel]++; });
    return counts;
  }, [repositories]);

  // Filter + search
  const filtered = useMemo(() => {
    return repositories.filter((r) => {
      const matchRisk = filterRisk === "All" || r.riskLevel === filterRisk;
      const matchSearch = !searchQuery || r.name.toLowerCase().includes(searchQuery.toLowerCase());
      return matchRisk && matchSearch;
    });
  }, [repositories, filterRisk, searchQuery]);

  const isConnected = connectionStatus === "Connected";
  const hasRepos = repositories.length > 0;

  return (
    <div className="github-connect grid">
      {/* ─── Page Header ─── */}
      <div className="page-header">
        <div>
          <h1>GitHub Connect</h1>
          <p className="page-subtitle">
            Authorize DevOps Shield, scan your repositories for security threats, and monitor risk posture in real time.
          </p>
        </div>
        {isDemo && (
          <span
            className="badge"
            style={{ background: "rgba(99,102,241,0.15)", color: "#818cf8", border: "1px solid rgba(99,102,241,0.3)" }}
          >
            🧪 Demo Mode
          </span>
        )}
      </div>

      {/* ─── Connect Form ─── */}
      <section className="card span-2">
        <header className="card-header">
          <div>
            <h2>GitHub Integration</h2>
            <p className="muted">
              Connect your GitHub account or organization to scan repositories for security threats,
              supply-chain risks, and secret leaks.
            </p>
          </div>
          <span className={`badge ${isConnected ? "badge-success" : "badge-idle"}`}>
            {connectionStatus}
          </span>
        </header>

        <form className="form-grid" onSubmit={handleSubmit}>
          <label>
            <span>GitHub username</span>
            <input
              type="text"
              name="username"
              placeholder="octocat"
              value={form.username}
              onChange={handleChange}
              required
            />
          </label>

          <label>
            <span>Organization <span style={{ opacity: 0.6 }}>(optional)</span></span>
            <input
              type="text"
              name="org"
              placeholder="my-company"
              value={form.org}
              onChange={handleChange}
            />
          </label>

          <label style={{ gridColumn: "1 / -1" }}>
            <span>Personal access token</span>
            <input
              type="password"
              name="token"
              placeholder="ghp_xxxxxxxxxxxx  (or ghp_dummytoken for demo)"
              value={form.token}
              onChange={handleChange}
              required
            />
            <p className="muted" style={{ marginTop: "0.25rem" }}>
              ✅ Token is stored server-side — never persisted in the browser.
              Needs <code>repo</code>, <code>admin:repo_hook</code>, <code>workflow</code> scopes.
              Use <strong>ghp_dummytoken</strong> for a no-credential demo.
            </p>
          </label>

          <label>
            <span>Scopes</span>
            <input
              type="text"
              name="scopes"
              value={form.scopes}
              onChange={handleChange}
            />
          </label>

          <div className="form-actions" style={{ gridColumn: "1 / -1" }}>
            <button type="submit" className="btn-primary" disabled={saving}>
              {saving ? "Connecting…" : isConnected ? "Re-connect" : "Connect GitHub"}
            </button>
            {isConnected && (
              <button type="button" className="btn-outline" onClick={handleDisconnect}>
                Disconnect
              </button>
            )}
          </div>
        </form>
      </section>

      {/* ─── Connection Health ─── */}
      <section className="card">
        <header className="card-header">
          <h3>Connection Health</h3>
          <p className="muted">OAuth posture &amp; sync cadence.</p>
        </header>
        <dl className="status-grid">
          <div>
            <dt>Account</dt>
            <dd style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              {authSession?.avatarUrl && (
                <img
                  src={authSession.avatarUrl}
                  alt="avatar"
                  style={{ width: 22, height: 22, borderRadius: "50%" }}
                />
              )}
              {authSession?.name || authSession?.account || "Not connected"}
              {isDemo && <span style={{ opacity: 0.6, fontSize: "0.75rem" }}>(demo)</span>}
            </dd>
          </div>
          <div><dt>Username</dt><dd>{authSession?.account || "—"}</dd></div>
          <div><dt>Scopes</dt><dd>{authSession?.scopes?.join(", ") || "—"}</dd></div>
          <div>
            <dt>Last verification</dt>
            <dd>
              {authSession?.lastVerification
                ? formatDateTime(authSession.lastVerification)
                : "Never"}
            </dd>
          </div>
          <div><dt>PKCE enforced</dt><dd>{authSession?.pkce ? "✅ Yes" : "❌ No"}</dd></div>
          <div><dt>Least privilege</dt><dd>{authSession?.leastPrivilege ? "✅ Yes" : "⚠️ Review"}</dd></div>
          <div><dt>Public repos</dt><dd>{authSession?.publicRepos ?? "—"}</dd></div>
          <div><dt>Repositories synced</dt><dd>{hasRepos ? repositories.length : "—"}</dd></div>
        </dl>
      </section>

      {/* ─── Risk Summary Cards ─── */}
      {isConnected && hasRepos && (
        <section className="card">
          <header className="card-header">
            <h3>Risk Summary</h3>
            <p className="muted">Across {repositories.length} monitored repositories.</p>
          </header>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "0.75rem", marginTop: "0.5rem" }}>
            {RISK_LEVELS.filter((l) => l !== "All").map((level) => (
              <div
                key={level}
                onClick={() => setFilterRisk(filterRisk === level ? "All" : level)}
                style={{
                  padding: "0.875rem 1rem",
                  borderRadius: "10px",
                  background: riskBg(level),
                  border: `1.5px solid ${filterRisk === level ? riskColor(level) : "transparent"}`,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  transition: "border-color 0.2s",
                }}
              >
                <span style={{ fontWeight: 600, fontSize: "0.85rem", color: riskColor(level) }}>{level}</span>
                <span style={{ fontSize: "1.5rem", fontWeight: 800, color: riskColor(level) }}>
                  {riskCounts[level]}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ─── Not Connected CTA ─── */}
      {!isConnected && (
        <section className="card span-2" style={{ textAlign: "center", padding: "2.5rem" }}>
          <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>🔗</div>
          <h2 style={{ marginBottom: "0.5rem" }}>Connect your GitHub account</h2>
          <p className="muted" style={{ maxWidth: 480, margin: "0 auto 1.5rem" }}>
            Enter your GitHub username and a Personal Access Token above to start scanning your
            repositories for security threats, CVEs, secret leaks, and supply-chain risks.
          </p>
          <div style={{ display: "flex", gap: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
            {[
              { icon: "🛡️", label: "Risk Scoring" },
              { icon: "🔍", label: "CVE Detection" },
              { icon: "🔑", label: "Secret Scanning" },
              { icon: "📦", label: "Supply Chain" },
            ].map(({ icon, label }) => (
              <span key={label} style={{
                padding: "0.4rem 0.9rem",
                borderRadius: "999px",
                background: "rgba(99,102,241,0.12)",
                color: "#818cf8",
                fontSize: "0.8rem",
                fontWeight: 600,
              }}>
                {icon} {label}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* ─── Repositories Table ─── */}
      {isConnected && hasRepos && (
        <section className="card span-2 repositories-section">
          <header className="card-header" style={{ flexWrap: "wrap", gap: "0.75rem" }}>
            <div>
              <h2 style={{ fontSize: "1.2rem", fontWeight: 700, margin: 0 }}>
                Monitored Repositories
              </h2>
              <p className="muted" style={{ margin: "0.2rem 0 0" }}>
                Real-time security risk scoring. {filtered.length} of {repositories.length} shown.
              </p>
            </div>
            <span className="badge badge-info">{repositories.length} Active</span>
          </header>

          {/* Filter + Search bar */}
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap", marginBottom: "1rem" }}>
            {/* Search */}
            <input
              type="text"
              placeholder="🔍  Search repositories…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                flex: 1,
                minWidth: 200,
                padding: "0.5rem 0.875rem",
                borderRadius: "8px",
                border: "1px solid rgba(255,255,255,0.1)",
                background: "rgba(255,255,255,0.05)",
                color: "inherit",
                fontSize: "0.875rem",
              }}
            />
            {/* Risk level filter chips */}
            <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
              {RISK_LEVELS.map((level) => (
                <button
                  key={level}
                  onClick={() => setFilterRisk(level)}
                  style={{
                    padding: "0.3rem 0.75rem",
                    borderRadius: "999px",
                    border: filterRisk === level
                      ? `1.5px solid ${level === "All" ? "#6366f1" : riskColor(level)}`
                      : "1.5px solid rgba(255,255,255,0.1)",
                    background: filterRisk === level
                      ? level === "All" ? "rgba(99,102,241,0.15)" : riskBg(level)
                      : "transparent",
                    color: filterRisk === level
                      ? level === "All" ? "#818cf8" : riskColor(level)
                      : "inherit",
                    cursor: "pointer",
                    fontSize: "0.78rem",
                    fontWeight: 600,
                    transition: "all 0.15s",
                  }}
                >
                  {level}
                  {level !== "All" && riskCounts[level] > 0 && (
                    <span style={{ marginLeft: 4, opacity: 0.8 }}>({riskCounts[level]})</span>
                  )}
                </button>
              ))}
            </div>
          </div>

          {filtered.length === 0 ? (
            <div style={{ padding: "2rem", textAlign: "center", opacity: 0.5 }}>
              No repositories match the current filter.
            </div>
          ) : (
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>REPOSITORY</th>
                    <th>VISIBILITY</th>
                    <th>LANGUAGE</th>
                    <th>LAST SCAN</th>
                    <th>ISSUES</th>
                    <th>RISK LEVEL</th>
                    <th className="text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((repo) => {
                    const scanning = scanningRepos[repo.id];
                    return (
                      <React.Fragment key={repo.id}>
                        <tr style={{ transition: "background 0.2s" }}>
                          {/* Repo name */}
                          <td>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
                              <ScanGauge score={repo.riskScore} />
                              <div>
                                <a
                                  href={repo.url}
                                  target="_blank"
                                  rel="noreferrer"
                                  style={{ color: "inherit", textDecoration: "none" }}
                                >
                                  {repo.name}
                                </a>
                                <div style={{ fontSize: "0.7rem", opacity: 0.55, marginTop: 2 }}>
                                  ⭐ {repo.stars ?? 0} &nbsp; 🍴 {repo.forks ?? 0}
                                  &nbsp; Branch: {repo.defaultBranch || "main"}
                                </div>
                              </div>
                            </div>
                          </td>

                          {/* Visibility */}
                          <td>
                            <span style={{ fontSize: "0.82rem" }}>
                              {visibilityIcon(repo.visibility)} {repo.visibility || "public"}
                            </span>
                          </td>

                          {/* Language */}
                          <td>
                            <span
                              style={{
                                fontSize: "0.78rem",
                                padding: "0.15rem 0.6rem",
                                borderRadius: 999,
                                background: "rgba(255,255,255,0.07)",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {repo.language || "Unknown"}
                            </span>
                          </td>

                          {/* Last scan */}
                          <td className="muted" style={{ fontSize: "0.8rem" }}>
                            {scanning ? (
                              <span style={{ color: "#6366f1" }}>⏳ Scanning…</span>
                            ) : (
                              formatDateTime(repo.lastScan)
                            )}
                          </td>

                          {/* Issues */}
                          <td>
                            <span
                              className="badge badge-outline"
                              style={{ display: "inline-flex", alignItems: "center", gap: "0.25rem" }}
                            >
                              {repo.issues} OPEN
                            </span>
                          </td>

                          {/* Risk badge */}
                          <td>
                            <RiskBadge score={repo.riskScore} level={repo.riskLevel} />
                          </td>

                          {/* Actions */}
                          <td className="text-right">
                            <div style={{ display: "flex", gap: "0.4rem", justifyContent: "flex-end" }}>
                              <button
                                className="btn-primary btn-sm"
                                onClick={() => {
                                  const isExpanding = expandedRepo !== repo.id;
                                  setExpandedRepo(isExpanding ? repo.id : null);
                                  if (isExpanding) {
                                    handleScanRepo(repo);
                                  }
                                }}
                                disabled={scanning}
                                style={{
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "0.5rem",
                                  padding: "0.5rem 1rem",
                                  fontWeight: 800,
                                  minWidth: "140px",
                                  justifyContent: "center"
                                }}
                              >
                                {scanning ? "⏳ Scanning…" : expandedRepo === repo.id ? "Close Details" : "⚡ Scan Details"}
                              </button>
                            </div>
                          </td>
                        </tr>

                        {/* ─── Expanded findings panel ─── */}
                        {expandedRepo === repo.id && (
                          <tr className="findings-row">
                            <td colSpan="7" style={{ padding: "0 1rem 1rem" }}>
                              <div
                                style={{
                                  background: "rgba(0,0,0,0.12)",
                                  borderRadius: 10,
                                  padding: "1rem 1.25rem",
                                  border: "1px solid rgba(255,255,255,0.06)",
                                }}
                              >
                                {/* Header */}
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
                                  <h4 style={{ margin: 0, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                    ⚠️ Security Analysis — <em style={{ opacity: 0.7, fontWeight: 400 }}>{repo.name}</em>
                                  </h4>
                                  <div style={{ display: "flex", gap: "0.75rem", fontSize: "0.75rem" }}>
                                    <span style={{ color: repo.hasSecretScanning ? "#22c55e" : "#ef4444" }}>
                                      {repo.hasSecretScanning ? "✅" : "❌"} Secret Scanning
                                    </span>
                                    <span style={{ color: repo.hasBranchProtection ? "#22c55e" : "#f97316" }}>
                                      {repo.hasBranchProtection ? "✅" : "⚠️"} Branch Protection
                                    </span>
                                  </div>
                                </div>

                                {/* Findings grid */}
                                {repo.securityFindings && repo.securityFindings.length > 0 ? (
                                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "0.75rem" }}>
                                    {repo.securityFindings.map((finding, idx) => (
                                      <div
                                        key={idx}
                                        style={{
                                          padding: "0.875rem",
                                          borderRadius: 8,
                                          background: "var(--card-bg, rgba(255,255,255,0.03))",
                                          borderLeft: `3px solid ${riskColor(finding.severity)}`,
                                        }}
                                      >
                                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.3rem" }}>
                                          <span style={{ fontWeight: 700, fontSize: "0.82rem" }}>
                                            {finding.category}
                                          </span>
                                          <span
                                            style={{
                                              fontSize: "0.7rem",
                                              textTransform: "uppercase",
                                              color: riskColor(finding.severity),
                                              fontWeight: 700,
                                            }}
                                          >
                                            {finding.severity}
                                          </span>
                                        </div>
                                        <p style={{ margin: "0 0 0.4rem", fontSize: "0.8rem", opacity: 0.85 }}>
                                          {finding.description}
                                        </p>
                                        <p style={{ margin: 0, fontSize: "0.75rem", color: "var(--primary-color, #6366f1)", fontStyle: "italic" }}>
                                          💡 {finding.remediation}
                                        </p>
                                        {finding.cve && (
                                          <span style={{ display: "inline-block", marginTop: "0.3rem", fontSize: "0.68rem", padding: "0.1rem 0.4rem", borderRadius: 4, background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>
                                            {finding.cve}
                                          </span>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <p style={{ opacity: 0.5, margin: 0 }}>✅ No security findings detected for this repository.</p>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* ─── How OAuth works ─── */}
      <section className="card span-2">
        <header className="card-header">
          <h3>How the OAuth flow works</h3>
        </header>
        <ol className="instructions" style={{ lineHeight: 2 }}>
          <li>Create a GitHub Fine-Grained PAT with <code>repo</code>, <code>admin:repo_hook</code>, <code>workflow</code> scopes.</li>
          <li>Paste the token and click <strong>Connect GitHub</strong> above.</li>
          <li>DevOps Shield validates the token with GitHub API and stores it server-side in Vault.</li>
          <li>Your repositories are fetched and each one receives an AI-powered security risk score.</li>
          <li>Click <strong>⚡ Scan</strong> on any repository for a real-time deep analysis of threats, CVEs, and misconfigurations.</li>
          <li>Use the filter chips to focus on <em>Critical</em> or <em>High</em> risk repos that need immediate attention.</li>
        </ol>
        <p className="muted">
          💡 No live GitHub account? Use <code>ghp_dummytoken</code> as the token for a full offline demo.
          Need SSO or GitHub Enterprise? Contact the platform team for service account provisioning.
        </p>
      </section>
    </div>
  );
};

export default GitHubConnect;
