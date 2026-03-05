const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080';

class ApiClient {
  constructor() {
    this.baseURL = API_URL;
    // console.log('[API Client] Initialized with base URL:', this.baseURL || 'same-origin');
  }

  async get(endpoint) {
    return this.request(endpoint, { method: "GET" });
  }

  async post(endpoint, body = {}) {
    return this.request(endpoint, {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  async put(endpoint, body = {}) {
    return this.request(endpoint, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  }

  async request(endpoint, options = {}) {
    // Ensure endpoint starts with /
    let cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    if (cleanEndpoint.length > 1 && cleanEndpoint.endsWith('/')) {
      cleanEndpoint = cleanEndpoint.slice(0, -1);
    }
    const url = `${this.baseURL}${cleanEndpoint}`;

    const config = {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    };

    try {
      const response = await fetch(url, config);

      if (!response.ok) {
        let errorDetail = response.statusText;
        try {
          const errorBody = await response.json();
          errorDetail = errorBody.detail || errorBody.message || errorDetail;
        } catch {
          const text = await response.text().catch(() => '');
          if (text) errorDetail = text;
        }
        throw new Error(`HTTP ${response.status}: ${errorDetail}`);
      }

      return response.json();
    } catch (error) {
      // Provide a clear, actionable message when the backend is unreachable
      if (
        error instanceof TypeError &&
        (error.message.includes('Failed to fetch') ||
          error.message.includes('NetworkError') ||
          error.message.includes('ECONNREFUSED'))
      ) {
        const msg =
          'Cannot reach the backend server. ' +
          'Start it with: cd backend && python main.py';
        throw new Error(msg);
      }
      throw error;
    }
  }

  async getFraudStats() {
    return this.get("/api/fraud/stats");
  }

  async analyzeRepository(projectId) {
    return this.post("/api/fraud/analyze", { project_id: projectId });
  }

  async getRepositoryRisk(projectId) {
    return this.get(`/api/fraud/repositories/${projectId}/risk`);
  }

  async scanRepository(projectId, depth = 50) {
    return this.post(`/api/fraud/repositories/${projectId}/scan`, { depth });
  }

  async checkMLHealth() {
    return this.get("/api/fraud/health/ml");
  }

  async getRecentAlerts(limit = 50) {
    return this.get(`/api/alerts/recent?limit=${limit}`);
  }

  async resolveAlert(alertId) {
    return this.post(`/api/alerts/${alertId}/resolve`);
  }

  async getAlertsSummary() {
    return this.get("/api/alerts/summary");
  }

  async testSlackNotification() {
    return this.post("/api/alerts/test/slack");
  }

  async testEmailNotification() {
    return this.post("/api/alerts/test/email");
  }

  async escalateAlert(alertId, priority = "high") {
    return this.post(`/api/alerts/escalate/${alertId}`, { priority });
  }

  async testWebhook() {
    return this.get("/api/webhook/test");
  }

  async simulateFraud() {
    return this.get("/api/simulate/");
  }

  async updateProfile(data) {
    return this.put("/api/auth/profile", data);
  }

  // ──────────────────────────────────────────────────────────
  // GitHub Integration Endpoints
  // ──────────────────────────────────────────────────────────

  /** Validate a GitHub PAT and return account info */
  async connectGitHub(credentials) {
    return this.post("/api/v1/github/connect", credentials);
  }

  /** Fetch all repositories with risk scores */
  async getMonitoredRepositories(credentials) {
    return this.post("/api/v1/github/repositories", credentials);
  }

  /**
   * Trigger a fresh security scan on a specific repository.
   * @param {string} repoFullName  e.g. "octocat/hello-world"
   * @param {{ token: string, username: string, org?: string }} credentials
   */
  async scanGitHubRepository(repoFullName, credentials) {
    const [owner, ...rest] = repoFullName.split('/');
    const repoName = rest.join('/');
    return this.post(
      `/api/v1/github/repositories/${owner}/${repoName}/scan`,
      credentials
    );
  }

  // ──────────────────────────────────────────────────────────
  // Pipeline Action Endpoints
  // ──────────────────────────────────────────────────────────

  async quarantineRun(pipelineId, runId) {
    return this.post(`/api/pipelines/${pipelineId}/runs/${runId}/quarantine`);
  }

  async rollbackRun(pipelineId, runId) {
    return this.post(`/api/pipelines/${pipelineId}/runs/${runId}/rollback`);
  }
}

const apiClient = new ApiClient();
export default apiClient;

export const simulateFraud = () => apiClient.simulateFraud();
