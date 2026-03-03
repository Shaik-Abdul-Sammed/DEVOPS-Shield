import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef,
} from "react";
import "./App.css";
import "./components/EnhancedDataViz.css";
import "./utils/svgFix"; // Import SVG viewBox fix
import Navbar from "./components/Navbar";
import { VIEWS, NAVIGATION_ITEMS } from "./constants/views";
import BlockchainDashboard from "./components/BlockchainDashboard.jsx";
import LoadingSpinner from "./components/LoadingSpinner.jsx";
import ErrorBoundary from "./components/ErrorBoundary.jsx";
import NotificationSystem from "./components/NotificationSystem.jsx";
import ChatAssistant from "./components/ChatAssistant.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import UserProfile from "./pages/UserProfile.jsx";
import ThreatIntel from "./pages/ThreatIntel.jsx";
import Reports from "./pages/Reports.jsx";
import IntegrationsPage from "./pages/Integrations.jsx";
import HelpPage from "./pages/Help.jsx";
import Pipelines from "./pages/Pipelines.jsx";
import AlertsPage from "./pages/Alerts.jsx";
import AuditPage from "./pages/Audit.jsx";
import SettingsPage from "./pages/Settings.jsx";
import ImpactPage from "./pages/Impact.jsx";
import SimulationPage from "./pages/Simulation.jsx";
import GitHubConnect from "./pages/GitHubConnect.jsx";
import LandingPage from "./pages/LandingPage.jsx";
import apiClient from "./services/apiClient.js";
import RiskAnalysis from "./pages/RiskAnalysis.jsx";
import {
  pipelines as pipelineData,
  runsByPipeline as runsData,
  alerts as alertData,
  auditRecords,
  impactMetrics,
  integrations,
  policyControls,
  authSession,
  securityHighlights,
  attackScenarios,
  simulationRiskHistory,
} from "./utils/sampleData.js";

// Navigation logic refactored to constants/views.js and components/Navbar.jsx

const AUTH_STATE_STORAGE_KEY = "devops-shield-auth-state";
const INTEGRATIONS_STATE_STORAGE_KEY = "devops-shield-integrations-state";

const App = () => {
  // State management
  const [view, setView] = useState(VIEWS.DASHBOARD);
  const [activePipelineId, setActivePipelineId] = useState(pipelineData[0]?.id);
  const [activeRunId, setActiveRunId] = useState(
    runsData[pipelineData[0]?.id]?.[0]?.runId,
  );
  const [runsState, setRunsState] = useState(runsData);
  const [alertsState, setAlertsState] = useState(alertData);
  const [authState, setAuthState] = useState(() => {
    if (typeof window === "undefined") return authSession;
    const stored = localStorage.getItem(AUTH_STATE_STORAGE_KEY);
    if (!stored) return authSession;
    try {
      return { ...authSession, ...JSON.parse(stored) };
    } catch {
      return authSession;
    }
  });
  const [integrationsState, setIntegrationsState] = useState(() => {
    if (typeof window === "undefined") return integrations;
    const stored = localStorage.getItem(INTEGRATIONS_STATE_STORAGE_KEY);
    if (!stored) return integrations;
    try {
      const parsed = JSON.parse(stored);
      if (!Array.isArray(parsed)) return integrations;
      return parsed;
    } catch {
      return integrations;
    }
  });
  const [latestIncident, setLatestIncident] = useState(null);
  const [simulationRisk, setSimulationRisk] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [theme, setTheme] = useState("dark");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [keyboardShortcutsEnabled, setKeyboardShortcutsEnabled] =
    useState(true);
  const [showLanding, setShowLanding] = useState(true);

  // Refs
  const mainContentRef = useRef(null);

  // Memoized values
  // Navigation items filtering moved to Navbar.jsx

  const criticalAlertsCount = useMemo(() => {
    return alertsState.filter(
      (alert) => alert.severity === "Critical" && alert.status === "Open",
    ).length;
  }, [alertsState]);

  // Effects
  useEffect(() => {
    // Initialize theme from localStorage
    const savedTheme = localStorage.getItem("devops-shield-theme") || "dark";
    setTheme(savedTheme);
    document.documentElement.setAttribute("data-theme", savedTheme);

    // Initialize sidebar state
    const savedSidebarState = localStorage.getItem(
      "devops-shield-sidebar-collapsed",
    );
    if (savedSidebarState !== null) {
      setSidebarCollapsed(JSON.parse(savedSidebarState));
    }

    // Initialize keyboard shortcuts
    const handleKeyboardShortcuts = (e) => {
      if (!keyboardShortcutsEnabled || !e.key) return;

      const ctrlKey = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();

      if (ctrlKey) {
        switch (key) {
          case "d":
            e.preventDefault();
            setView(VIEWS.DASHBOARD);
            break;
          case "p":
            e.preventDefault();
            setView(VIEWS.PIPELINES);
            break;
          case "a":
            e.preventDefault();
            setView(VIEWS.ALERTS);
            break;
          case "s":
            e.preventDefault();
            setView(VIEWS.SIMULATION);
            break;
          case "u":
            e.preventDefault();
            setView(VIEWS.USER_PROFILE);
            break;
          case "t":
            e.preventDefault();
            setView(VIEWS.THREAT_INTEL);
            break;
          case "r":
            e.preventDefault();
            setView(VIEWS.REPORTS);
            break;
          case "n":
            e.preventDefault();
            setView(VIEWS.INTEGRATIONS);
            break;
          case "h":
            e.preventDefault();
            setView(VIEWS.HELP);
            break;
          case "l":
            e.preventDefault();
            setView(VIEWS.AUDIT);
            break;
          case "i":
            e.preventDefault();
            setView(VIEWS.IMPACT);
            break;
          case "g":
            e.preventDefault();
            setView(VIEWS.GITHUB);
            break;
          case "b":
            e.preventDefault();
            setView(VIEWS.BLOCKCHAIN);
            break;
          case "k":
            e.preventDefault();
            setSearchQuery("");
            document.getElementById("nav-search")?.focus();
            break;
          default:
            break;
        }
      }

      // Escape to clear search
      if (e.key === "Escape" && searchQuery) {
        setSearchQuery("");
      }
    };

    document.addEventListener("keydown", handleKeyboardShortcuts);
    return () =>
      document.removeEventListener("keydown", handleKeyboardShortcuts);
  }, [keyboardShortcutsEnabled, searchQuery]);

  useEffect(() => {
    // Auto-save preferences
    localStorage.setItem("devops-shield-theme", theme);
    localStorage.setItem(
      "devops-shield-sidebar-collapsed",
      JSON.stringify(sidebarCollapsed),
    );
  }, [theme, sidebarCollapsed]);

  useEffect(() => {
    localStorage.setItem(AUTH_STATE_STORAGE_KEY, JSON.stringify(authState));
  }, [authState]);

  useEffect(() => {
    localStorage.setItem(
      INTEGRATIONS_STATE_STORAGE_KEY,
      JSON.stringify(integrationsState),
    );
  }, [integrationsState]);

  useEffect(() => {
    // Focus management for accessibility
    if (mainContentRef.current) {
      mainContentRef.current.focus();
    }
  }, [view]);

  // Callback functions
  const addNotification = useCallback(
    (message, type = "info", duration = 5000) => {
      const id =
        Date.now().toString() + Math.random().toString(36).substr(2, 9);
      const notification = {
        id,
        message,
        type,
        timestamp: new Date(),
        duration,
      };

      setNotifications((prev) => [...prev, notification]);
    },
    [],
  );

  const onSelectPipeline = useCallback(
    (pipelineId) => {
      if (view === VIEWS.PIPELINES && activePipelineId === pipelineId) {
        setActivePipelineId(null);
      } else {
        setActivePipelineId(pipelineId);
        const nextRunId = runsData[pipelineId]?.[0]?.runId;
        setActiveRunId(nextRunId);
        addNotification(`Switched to pipeline: ${pipelineId}`, "success");
      }
      setView(VIEWS.PIPELINES);
    },
    [view, activePipelineId, addNotification],
  );

  const onSelectRun = useCallback(
    (runId) => {
      setActiveRunId(runId);
      addNotification(`Selected run: ${runId}`, "info");
    },
    [addNotification],
  );

  const onRunAction = useCallback(
    (action, payload) => {
      if (action === "view") {
        setView(VIEWS.PIPELINES);
        setActivePipelineId(payload.pipelineId);
        setActiveRunId(payload.runId);
        return;
      }

      if (action === "viewLogs") {
        addNotification(
          payload?.evidence?.logsUrl
            ? "Opening Logs..."
            : "Logs unavailable for this run.",
          payload?.evidence?.logsUrl ? "info" : "warning",
        );
        return;
      }

      if (action === "inspectDiff") {
        addNotification(
          payload?.evidence?.diffUrl
            ? "Opening Diff Tool..."
            : "Diff unavailable for this run.",
          payload?.evidence?.diffUrl ? "info" : "warning",
        );
        return;
      }

      if (action === "scaReport") {
        addNotification(
          payload?.evidence?.scaUrl
            ? "Opening SCA Report..."
            : "SCA Report unavailable.",
          payload?.evidence?.scaUrl ? "info" : "warning",
        );
        return;
      }

      setIsLoading(true);
      // console.info("Run action", action, payload?.runId);

      if (action === "quarantine" || action === "rollback") {
        apiClient[action === "quarantine" ? "quarantineRun" : "rollbackRun"](
          payload.pipelineId,
          payload.runId,
        )
          .then(() => {
            const newStatus =
              action === "quarantine" ? "QUARANTINED" : "ROLLING_BACK";
            setRunsState((prev) => {
              const pipelineRuns = prev[payload.pipelineId] || [];
              return {
                ...prev,
                [payload.pipelineId]: pipelineRuns.map((run) =>
                  run.runId === payload.runId
                    ? { ...run, status: newStatus }
                    : run,
                ),
              };
            });
            addNotification(
              `Action "${action}" executed for run ${payload?.runId}`,
              "success",
            );
          })
          .catch((err) => {
            addNotification(`Failed to ${action}: ${err.message}`, "error");
          })
          .finally(() => setIsLoading(false));
      } else {
        setTimeout(() => {
          setIsLoading(false);
          addNotification(
            `Action "${action}" executed for run ${payload?.runId}`,
            "success",
          );
        }, 1000);
      }
    },
    [addNotification],
  );

  const onAlertAction = useCallback(
    (action, payload) => {
      if (action === "filter") {
        addNotification(
          "Applied critical severity filters to Incidents table",
          "info",
        );
        return;
      }
      if (action === "assign") {
        const assignee = payload;
        addNotification(`Incident assigned to: ${assignee}`, "success");
        return;
      }

      if (!payload?.id) return;

      const alertId = payload.id;
      const updateStatus = (status) => {
        setAlertsState((prev) =>
          prev.map((alert) =>
            alert.id === alertId ? { ...alert, status } : alert,
          ),
        );
      };

      switch (action) {
        case "ack":
          updateStatus("Acknowledged");
          addNotification(`Alert ${alertId} acknowledged`, "success");
          break;
        case "resolve":
          updateStatus("Resolved");
          addNotification(`Alert ${alertId} resolved`, "success");
          if (latestIncident?.id?.toLowerCase() === alertId.toLowerCase()) {
            setLatestIncident(null);
            setSimulationRisk(0);
          }
          break;
        case "rollback":
          updateStatus("Mitigating");
          addNotification(`Rollback initiated for alert ${alertId}`, "warning");
          break;
        case "ticket":
          updateStatus("Escalated");
          addNotification(`Alert ${alertId} escalated to support team`, "info");
          break;
        default:
          break;
      }

      // console.info("Alert action", action, alertId);
    },
    [latestIncident, addNotification],
  );

  const onExport = useCallback(
    (format, record) => {
      setIsLoading(true);
      addNotification(
        `Preparing ${format.toUpperCase()} export for ${record?.id || record?.runId || "audit"}...`,
        "info",
      );

      setTimeout(() => {
        setIsLoading(false);

        let fileContent = "";
        let mimeType = "";

        if (format === "json") {
          fileContent = JSON.stringify(record, null, 2);
          mimeType = "application/json";
        } else {
          // Switch 'pdf' to a simple 'csv' serialization so it works locally and doesn't get corrupted
          const keys = Object.keys(record || {});
          const vals = Object.values(record || {}).map((v) =>
            typeof v === "object" ? JSON.stringify(v) : v,
          );
          fileContent = keys.join(",") + "\n" + vals.join(",");
          mimeType = "text/csv;charset=utf-8;";
          format = "csv";
        }

        const blob = new Blob([fileContent], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute(
          "download",
          `audit-export-${record?.id || record?.runId || "data"}.${format}`,
        );
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);

        addNotification(`Export downloaded successfully`, "success");
      }, 1500);
    },
    [addNotification],
  );

  const onReconnect = useCallback(
    (provider) => {
      setIsLoading(true);
      // console.info("Re-authenticate provider", provider);

      const now = new Date().toISOString();
      setAuthState((prev) => ({
        ...prev,
        status: "Connected",
        lastVerification: now,
      }));
      setIntegrationsState((prev) =>
        prev.map((integration) =>
          integration.id === "github"
            ? { ...integration, status: "Connected", lastSync: now }
            : integration,
        ),
      );

      setTimeout(() => {
        setIsLoading(false);
        addNotification(`Successfully reconnected to ${provider}`, "success");
      }, 1000);
    },
    [addNotification],
  );

  const handleGitHubDisconnect = useCallback(() => {
    const now = new Date().toISOString();
    setAuthState((prev) => ({
      ...prev,
      status: "Disconnected",
      lastVerification: now,
      scopes: prev.scopes || [],
    }));
    setIntegrationsState((prev) =>
      prev.map((integration) =>
        integration.id === "github"
          ? { ...integration, status: "Disconnected", lastSync: now }
          : integration,
      ),
    );
    addNotification("GitHub disconnected", "info");
  }, [addNotification]);

  const handleGitHubConnect = useCallback(
    async ({ username, token, scopes, org }) => {
      setIsLoading(true);
      addNotification("Validating GitHub credentials…", "info");
      try {
        // 1. Validate connection via our real backend
        const connectResponse = await apiClient.connectGitHub({
          username,
          token,
          scopes,
          org,
        });

        const now = new Date().toISOString();
        setAuthState((prev) => ({
          ...prev,
          status: "Connected",
          account: connectResponse.account || username || prev.account,
          scopes: scopes?.length ? scopes : prev.scopes,
          organization: org || prev.organization,
          lastVerification: now,
          pkce: true,
          leastPrivilege: true,
          isDemo: connectResponse.demo || false,
          name: connectResponse.name || connectResponse.account || username,
          avatarUrl: connectResponse.avatar_url || null,
          publicRepos: connectResponse.public_repos || 0,
        }));

        // 2. Fetch real monitored repositories
        addNotification(
          connectResponse.demo
            ? "Loading demo repositories with risk scores…"
            : "Fetching live repositories and calculating risks…",
          "info",
        );
        const reposResponse = await apiClient.getMonitoredRepositories({
          username: connectResponse.account || username,
          token,
          scopes,
          org,
        });

        setIntegrationsState((prev) => {
          return prev.map((integration) =>
            integration.id === "github"
              ? {
                ...integration,
                status: "Connected",
                lastSync: now,
                scopes: scopes?.length ? scopes : integration.scopes,
                repositories: Array.isArray(reposResponse) ? reposResponse : [],
              }
              : integration,
          );
        });

        const repoCount = Array.isArray(reposResponse) ? reposResponse.length : 0;
        addNotification(
          connectResponse.demo
            ? `Demo mode active — showing ${repoCount} simulated repositories with risk scores.`
            : `Connected to GitHub. Scanned ${repoCount} repositories.`,
          "success",
          7000,
        );
      } catch (error) {
        console.error("GitHub connect error:", error);
        const rawMsg = error?.message || "Failed to authenticate with GitHub";
        // Provide actionable guidance when backend is unreachable
        const msg = rawMsg.includes("Cannot reach the backend")
          ? "Backend server not running. Start it: cd backend && python main.py"
          : rawMsg;
        addNotification(`Connection Error: ${msg}`, "error", 10000);
      } finally {
        setIsLoading(false);
      }
    },
    [addNotification],
  );

  const onDisconnect = useCallback(
    (provider) => {
      // console.info("Disconnect provider", provider);
      handleGitHubDisconnect();
    },
    [handleGitHubDisconnect],
  );

  const handleSimulationIncident = useCallback(
    (incident) => {
      const normalizedRisk = Number.isFinite(incident.riskScore)
        ? Math.max(0, Math.round(incident.riskScore))
        : 0;
      const severity =
        normalizedRisk >= 90
          ? "Critical"
          : normalizedRisk >= 75
            ? "High"
            : normalizedRisk >= 50
              ? "Medium"
              : "Low";

      const newAlert = {
        id: incident.id.toLowerCase(),
        pipelineId: incident.pipelineId,
        title: `Simulated ${incident.scenarioName}`,
        severity,
        createdAt: incident.timestamp,
        status: "Open",
        riskScore: normalizedRisk,
        impact: incident.message || "Automated drill impact pending review",
      };

      setAlertsState((prev) => [
        newAlert,
        ...prev.filter((alert) => alert.id !== newAlert.id),
      ]);
      setLatestIncident({ ...incident, riskScore: normalizedRisk, severity });
      setSimulationRisk(normalizedRisk);

      addNotification(
        `Simulation incident: ${incident.scenarioName}`,
        "warning",
        8000,
      );
    },
    [addNotification],
  );

  const handleSimulationReset = useCallback(() => {
    setSimulationRisk(0);
    setLatestIncident(null);
    setAlertsState((prev) =>
      prev.filter((alert) => !alert.title.startsWith("Simulated")),
    );
    addNotification("Simulation system reset. Test logs cleared.", "info");
  }, [addNotification]);

  const toggleTheme = useCallback(() => {
    const newTheme = theme === "dark" ? "light" : "dark";
    setTheme(newTheme);
    document.documentElement.setAttribute("data-theme", newTheme);
    addNotification(`Switched to ${newTheme} theme`, "info");
  }, [theme, addNotification]);

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => !prev);
  }, []);

  const handleNavigation = useCallback((viewId) => {
    setView(viewId);
    setSearchQuery(""); // Clear search when navigating
  }, []);

  // Render content based on current view
  const renderContent = () => {
    const commonProps = {
      isLoading,
      notifications,
      addNotification,
    };

    switch (view) {
      case VIEWS.DASHBOARD:
        return (
          <Dashboard
            pipelines={pipelineData}
            runsByPipeline={runsState}
            alerts={alertsState}
            impactMetrics={impactMetrics}
            authSession={authState}
            securityHighlights={securityHighlights}
            integrations={integrationsState}
            latestIncident={latestIncident}
            onSelectPipeline={onSelectPipeline}
            onRunAction={onRunAction}
            onAlertAction={onAlertAction}
            onViewAlerts={() => handleNavigation(VIEWS.ALERTS)}
            onManageIntegrations={() => handleNavigation(VIEWS.GITHUB)}
            {...commonProps}
          />
        );
      case VIEWS.USER_PROFILE:
        return <UserProfile {...commonProps} />;
      case VIEWS.THREAT_INTEL:
        return <ThreatIntel {...commonProps} />;
      case VIEWS.REPORTS:
        return <Reports {...commonProps} />;
      case VIEWS.INTEGRATIONS:
        return <IntegrationsPage {...commonProps} />;
      case VIEWS.RISK_ANALYSIS:
        return <RiskAnalysis {...commonProps} />;
      case VIEWS.HELP:
        return <HelpPage {...commonProps} />;
      case VIEWS.PIPELINES:
        return (
          <Pipelines
            pipelines={pipelineData}
            runsByPipeline={runsState}
            activePipelineId={activePipelineId}
            activeRunId={activeRunId}
            onSelectPipeline={onSelectPipeline}
            onSelectRun={onSelectRun}
            onRunAction={onRunAction}
            {...commonProps}
          />
        );
      case VIEWS.ALERTS:
        return (
          <AlertsPage
            alerts={alertsState}
            onAction={onAlertAction}
            criticalCount={criticalAlertsCount}
            {...commonProps}
          />
        );
      case VIEWS.AUDIT:
        return (
          <AuditPage
            records={auditRecords}
            onExport={onExport}
            {...commonProps}
          />
        );
      case VIEWS.SETTINGS:
        return (
          <SettingsPage
            integrations={integrationsState}
            policies={policyControls}
            authSession={authState}
            onReconnect={onReconnect}
            onDisconnect={onDisconnect}
            securityHighlights={securityHighlights}
            theme={theme}
            onToggleTheme={toggleTheme}
            keyboardShortcutsEnabled={keyboardShortcutsEnabled}
            onToggleKeyboardShortcuts={() =>
              setKeyboardShortcutsEnabled((prev) => !prev)
            }
            onManageIntegrations={() => handleNavigation(VIEWS.INTEGRATIONS)}
            onUpdateProfile={(updatedUser) => {
              setAuthState((prev) => ({
                ...prev,
                ...updatedUser,
                account: updatedUser.username,
              }));
              addNotification("Profile updated", "success");
            }}
            {...commonProps}
          />
        );
      case VIEWS.IMPACT:
        return <ImpactPage impactMetrics={impactMetrics} {...commonProps} />;
      case VIEWS.SIMULATION:
        return (
          <SimulationPage
            scenarios={attackScenarios}
            history={simulationRiskHistory}
            onIncident={handleSimulationIncident}
            onReset={handleSimulationReset}
            currentRisk={simulationRisk}
            {...commonProps}
          />
        );
      case VIEWS.GITHUB:
        return (
          <GitHubConnect
            authSession={authState}
            integrations={integrationsState}
            onConnect={handleGitHubConnect}
            onDisconnect={handleGitHubDisconnect}
            addNotification={addNotification}
            {...commonProps}
          />
        );
      case VIEWS.BLOCKCHAIN:
        return (
          <BlockchainDashboard
            {...commonProps}
            authSession={authState}
            integrations={integrationsState}
            onNavigate={handleNavigation}
          />
        );
      default:
        return null;
    }
  };

  return (
    <ErrorBoundary>
      {showLanding ? (
        <LandingPage onEnter={() => setShowLanding(false)} />
      ) : (
        <div
          className={`shell ${theme} ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}
        >
          {/* Loading Overlay */}
          {isLoading && <LoadingSpinner />}

          {/* Notification System */}
          <NotificationSystem
            notifications={notifications}
            onRemove={(id) =>
              setNotifications((prev) => prev.filter((n) => n.id !== id))
            }
          />

          {/* Sidebar Navigation */}
          <Navbar
            currentView={view}
            onNavigate={handleNavigation}
            collapsed={sidebarCollapsed}
            onToggleCollapse={toggleSidebar}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            theme={theme}
            onToggleTheme={toggleTheme}
            criticalAlertsCount={criticalAlertsCount}
          />

          {/* Main Content */}
          <main className="shell-content" ref={mainContentRef} tabIndex="-1">
            <div className="content-container">
              {/* Header - Hidden for Blockchain view to avoid redundancy with its premium internal header */}
              {view !== VIEWS.BLOCKCHAIN && (
                <header className="content-header">
                  <div className="header-title-container">
                    <div className="header-title">
                      <h1>
                        {NAVIGATION_ITEMS.find((item) => item.id === view)?.label}
                      </h1>
                      <p className="muted">
                        Production-ready CI/CD risk observability
                      </p>
                    </div>
                  </div>
                  <div className="header-actions">
                    <button
                      type="button"
                      className={`btn-outline simulate-cta ${simulationRisk > 0 ? "armed" : ""}`}
                      onClick={() => handleNavigation(VIEWS.SIMULATION)}
                      aria-label={`Simulate attack - Current risk: ${Math.max(0, Math.round(simulationRisk))}%`}
                    >
                      <span className="btn-icon">🧪</span>
                      <span className="btn-text">Simulate attack</span>
                      <span
                        className="risk-chip"
                        aria-label={`Risk level: ${Math.max(0, Math.round(simulationRisk))}%`}
                      >
                        {Math.max(0, Math.round(simulationRisk))}% risk
                      </span>
                    </button>
                    <button
                      type="button"
                      className="btn-primary"
                      onClick={() => handleNavigation(VIEWS.GITHUB)}
                      aria-label="Connect GitHub repository"
                    >
                      <span className="btn-icon">🔗</span>
                      <span className="btn-text">Connect GitHub</span>
                    </button>
                  </div>
                </header>
              )}

              {/* Incident Banner */}
              {latestIncident && (
                <section
                  className={`card incident-banner ${latestIncident.severity?.toLowerCase()}`}
                  role="alert"
                  aria-live="polite"
                >
                  <div className="incident-content">
                    <div className="incident-header">
                      <strong>
                        {latestIncident.severity} alert · {latestIncident.id}
                      </strong>
                      <p className="muted">
                        Risk {latestIncident.riskScore}% on{" "}
                        {latestIncident.pipelineId}. {latestIncident.message}
                      </p>
                    </div>
                    <div className="incident-banner-actions">
                      <button
                        type="button"
                        className="btn-outline"
                        onClick={() => handleNavigation(VIEWS.ALERTS)}
                        aria-label="View all alerts"
                      >
                        Open alerts
                      </button>
                      <button
                        type="button"
                        className="btn-outline"
                        onClick={handleSimulationReset}
                        aria-label="Reset simulation"
                      >
                        Reset
                      </button>
                    </div>
                  </div>
                </section>
              )}

              {/* Page Content */}
              <div className="content-body">
                <ErrorBoundary key={view}>{renderContent()}</ErrorBoundary>
              </div>
            </div>
          </main>
        </div>
      )}

      {/* Project Assistant Chatbot - Global Viewport Relative */}
      <ChatAssistant />
    </ErrorBoundary>
  );
};

export default App;
