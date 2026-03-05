export const pipelines = [
  {
    id: 'frontend-ci',
    name: 'Frontend CI',
    tags: ['healthcare', 'ui'],
    owner: 'Blue Horizon DevSecOps',
    integrations: ['GitHub', 'Jenkins'],
    lastRunId: 'run_20260311_1530',
    lastStatus: 'FAILED',
    lastRiskScore: 78,
    lastRiskLevel: 'High',
    trend: [42, 58, 63, 78],
    blockedDeploys: 14,
    description: 'Protects patient portal builds powering national telehealth services.'
  },
  {
    id: 'payments-cd',
    name: 'Payments CD',
    tags: ['banking', 'realtime'],
    owner: 'Critical Payments Guild',
    integrations: ['GitLab', 'ArgoCD'],
    lastRunId: 'run_20260310_0915',
    lastStatus: 'PASSED',
    lastRiskScore: 32,
    lastRiskLevel: 'Low',
    trend: [28, 30, 34, 32],
    blockedDeploys: 21,
    description: 'Handles settlement microservices for inter-bank transfers.'
  },
  {
    id: 'edge-security',
    name: 'Edge Security Firmware',
    tags: ['civinfra', 'edge'],
    owner: 'Smart Grid Ops',
    integrations: ['GitHub', 'CircleCI'],
    lastRunId: 'run_20260309_2200',
    lastStatus: 'FAILED',
    lastRiskScore: 91,
    lastRiskLevel: 'Critical',
    trend: [65, 72, 88, 91],
    blockedDeploys: 37,
    description: 'Controls firmware for energy distribution substations across three cities.'
  }
];

export const runsByPipeline = {
  'frontend-ci': [
    {
      pipelineId: 'frontend-ci',
      runId: 'run_20260311_1530',
      status: 'FAILED',
      startedAt: '2026-03-11T15:30:12Z',
      completedAt: '2026-03-11T15:38:45Z',
      commits: [
        { sha: 'abc123', author: 'devA', message: 'Fix auth redirect loop' }
      ],
      artifacts: [
        { name: 'app.tar.gz', checksum: 'sha256:cd21f0...11b' },
        { name: 'sbom.json', checksum: 'sha256:ab12ff...908' }
      ],
      tags: ['healthcare'],
      risk: {
        score: 78,
        level: 'High',
        reasons: [
          { type: 'SecretLeak', detail: 'ENV_TOKEN found in build logs' },
          { type: 'AnomalousActor', detail: 'New CI runner from unregistered IP 185.44.12.9' }
        ],
        mlConfidence: 0.86,
        ruleScore: 40,
        trustScore: 0.52
      },
      evidence: {
        logsUrl: 'https://logs.devops-shield.io/frontend-ci/run_20260311_1530',
        diffUrl: 'https://git.example.com/frontend/compare/abc123',
        scaUrl: 'https://sca.devops-shield.io/report/frontend-ci/run_20260311_1530'
      },
      immutableProof: {
        chainHash: '0xabcde021ef45',
        txId: '0x123fed90871',
        signature: 'SIG_frontend_ci_20260311'
      },
      stages: [
        {
          id: 'source-integrity',
          name: 'Source Integrity',
          status: 'FAILED',
          riskScore: 82,
          startedAt: '2026-03-11T15:30:12Z',
          completedAt: '2026-03-11T15:31:45Z',
          summary: 'Identity anomaly detected for commit abc123',
          evidence: 'Identity model flagged unknown device fingerprint.',
          action: 'Runner quarantined'
        },
        {
          id: 'dependency',
          name: 'Dependency Sentinel',
          status: 'PASSED',
          riskScore: 18,
          startedAt: '2026-03-11T15:31:45Z',
          completedAt: '2026-03-11T15:33:10Z',
          summary: 'Dependencies match allow list',
          evidence: 'All hashes matched SBOM baseline.'
        },
        {
          id: 'artifact',
          name: 'Artifact Hardening',
          status: 'BLOCKED',
          riskScore: 67,
          startedAt: '2026-03-11T15:33:10Z',
          completedAt: '2026-03-11T15:35:02Z',
          summary: 'Signing profile mismatch',
          evidence: 'PGP signature does not match recorded maintainer key.',
          action: 'Artifact quarantined'
        }
      ]
    },
    {
      pipelineId: 'frontend-ci',
      runId: 'run_20260310_0712',
      status: 'PASSED',
      startedAt: '2026-03-10T07:12:02Z',
      completedAt: '2026-03-10T07:18:11Z',
      commits: [
        { sha: 'def456', author: 'devB', message: 'Upgrade dependency versions' }
      ],
      artifacts: [
        { name: 'app.tar.gz', checksum: 'sha256:cd21f0...998' }
      ],
      tags: ['healthcare'],
      risk: {
        score: 28,
        level: 'Low',
        reasons: [
          { type: 'Behavior', detail: 'Run matched known secure profile' }
        ],
        mlConfidence: 0.93,
        ruleScore: 12,
        trustScore: 0.91
      },
      evidence: {
        logsUrl: 'https://logs.devops-shield.io/frontend-ci/run_20260310_0712',
        diffUrl: 'https://git.example.com/frontend/compare/def456'
      },
      immutableProof: {
        chainHash: '0xbcd90321ffaa',
        txId: '0x991827364aa',
        signature: 'SIG_frontend_ci_20260310'
      },
      stages: [
        {
          id: 'source-integrity',
          name: 'Source Integrity',
          status: 'PASSED',
          riskScore: 12,
          summary: 'Commit signed by expected maintainer',
          evidence: 'MFA + hardware key validated.'
        },
        {
          id: 'dependency',
          name: 'Dependency Sentinel',
          status: 'PASSED',
          riskScore: 20,
          summary: 'Dependencies cleared reputation check'
        },
        {
          id: 'artifact',
          name: 'Artifact Hardening',
          status: 'PASSED',
          riskScore: 8,
          summary: 'Artifact signature verified'
        }
      ]
    }
  ],
  'payments-cd': [
    {
      pipelineId: 'payments-cd',
      runId: 'run_20260310_0915',
      status: 'PASSED',
      startedAt: '2026-03-10T09:15:00Z',
      completedAt: '2026-03-10T09:23:32Z',
      commits: [
        { sha: 'pay991', author: 'finSec', message: 'Patch settlement rounding bug' }
      ],
      artifacts: [
        { name: 'payments.war', checksum: 'sha256:993afc...aa1' }
      ],
      tags: ['banking'],
      risk: {
        score: 32,
        level: 'Low',
        reasons: [
          { type: 'Policy', detail: 'PCI checklist completed automatically' }
        ],
        mlConfidence: 0.88,
        ruleScore: 18,
        trustScore: 0.88
      },
      evidence: {
        logsUrl: 'https://logs.devops-shield.io/payments-cd/run_20260310_0915',
        diffUrl: 'https://git.example.com/payments/compare/pay991'
      },
      immutableProof: {
        chainHash: '0x98aa21def1',
        txId: '0xfed2187acd9',
        signature: 'SIG_payments_cd_20260310'
      },
      stages: [
        {
          id: 'source-integrity',
          name: 'Source Integrity',
          status: 'PASSED',
          riskScore: 22,
          summary: 'Commit chain verified with hardware key'
        },
        {
          id: 'dependency',
          name: 'Dependency Sentinel',
          status: 'PASSED',
          riskScore: 14,
          summary: 'Dependencies match locked versions'
        },
        {
          id: 'artifact',
          name: 'Artifact Hardening',
          status: 'PASSED',
          riskScore: 7,
          summary: 'Runtime sandbox results clean'
        }
      ]
    }
  ],
  'edge-security': [
    {
      pipelineId: 'edge-security',
      runId: 'run_20260309_2200',
      status: 'FAILED',
      startedAt: '2026-03-09T22:00:01Z',
      completedAt: '2026-03-09T22:12:55Z',
      commits: [
        { sha: 'grid771', author: 'firmwareOps', message: 'Emergency patch for voltage regulator' }
      ],
      artifacts: [
        { name: 'firmware.img', checksum: 'sha256:fff232...bb2' }
      ],
      tags: ['civinfra'],
      risk: {
        score: 91,
        level: 'Critical',
        reasons: [
          { type: 'SupplyChain', detail: 'Unsigned dependency pulled from mirror not in allow list' },
          { type: 'CriticalAsset', detail: 'Pipeline tagged as critical infrastructure' }
        ],
        mlConfidence: 0.94,
        ruleScore: 68,
        trustScore: 0.34
      },
      evidence: {
        logsUrl: 'https://logs.devops-shield.io/edge-security/run_20260309_2200',
        diffUrl: 'https://git.example.com/edge/compare/grid771'
      },
      immutableProof: {
        chainHash: '0x1100aacceff',
        txId: '0x7771bb23cc',
        signature: 'SIG_edge_security_20260309'
      },
      stages: [
        {
          id: 'source-integrity',
          name: 'Source Integrity',
          status: 'FAILED',
          riskScore: 88,
          summary: 'Maintainer identity mismatch; requiring multi-factor challenge',
          action: 'Deployment halted, SOC alerted'
        },
        {
          id: 'dependency',
          name: 'Dependency Sentinel',
          status: 'FAILED',
          riskScore: 95,
          summary: 'Package voltage-kit v4.2 fetched from unknown mirror'
        },
        {
          id: 'artifact',
          name: 'Artifact Hardening',
          status: 'BLOCKED',
          riskScore: 74,
          summary: 'Firmware signature invalid on stage cluster'
        }
      ]
    }
  ]
};

export const alerts = [
  {
    id: 'alert-001',
    pipelineId: 'frontend-ci',
    title: 'Secrets leakage in frontend build',
    severity: 'High',
    createdAt: '2026-03-11T15:39:10Z',
    status: 'Open',
    riskScore: 78,
    assignee: null,
    suggestedAction: 'Quarantine runner and rotate credentials',
    impact: 'Potential patient PII exposure if deployed'
  },
  {
    id: 'alert-002',
    pipelineId: 'edge-security',
    title: 'Unsigned firmware detected',
    severity: 'Critical',
    createdAt: '2026-03-09T22:13:02Z',
    status: 'Escalated',
    riskScore: 91,
    assignee: 'soc-duty',
    suggestedAction: 'Notify regulators, block rollout to smart grid nodes',
    impact: 'Prevents power grid instability across 3 cities'
  },
  {
    id: 'alert-003',
    pipelineId: 'payments-cd',
    title: 'New dependency added outside allow list',
    severity: 'Medium',
    createdAt: '2026-03-08T11:18:33Z',
    status: 'Resolved',
    riskScore: 48,
    assignee: 'finsec-ops',
    suggestedAction: 'Dependency removed; follow-up review complete',
    impact: 'Protected 12 banks from compromised settlement library'
  }
];

export const auditRecords = [
  {
    id: 'audit-frontend-ci-run_20260311_1530',
    pipelineId: 'frontend-ci',
    runId: 'run_20260311_1530',
    generatedAt: '2026-03-11T15:40:00Z',
    immutableProof: {
      chainHash: '0xabcde021ef45',
      txId: '0x123fed90871',
      signature: 'SIG_frontend_ci_20260311'
    },
    reviewer: 'auditor-ops',
    status: 'Available'
  },
  {
    id: 'audit-edge-security-run_20260309_2200',
    pipelineId: 'edge-security',
    runId: 'run_20260309_2200',
    generatedAt: '2026-03-09T22:16:00Z',
    immutableProof: {
      chainHash: '0x1100aacceff',
      txId: '0x7771bb23cc',
      signature: 'SIG_edge_security_20260309'
    },
    reviewer: 'regulator-liaison',
    status: 'Shared'
  }
];

export const impactMetrics = {
  blockedMaliciousDeploys: 72,
  protectedUsers: 350000,
  protectedAssets: {
    healthcare: 18,
    banking: 12,
    civinfra: 9
  },
  compliancePosture: [
    { framework: 'PCI-DSS', status: 'Aligned', lastAudit: '2025-11-30' },
    { framework: 'NIST 800-53', status: 'In review', lastAudit: '2025-10-25' },
    { framework: 'DISA STIG', status: 'Aligned', lastAudit: '2025-11-10' }
  ],
  supplyChain: {
    verifiedPublishers: 418,
    quarantinedPackages: 37,
    avgResolutionHours: 2.4
  },
  transparency: {
    publicAlertsIssued: 6,
    regulatorNotifications: 4
  }
};

export const integrations = [
  {
    id: 'github',
    name: 'GitHub',
    status: 'Disconnected',
    lastSync: null,
    scopes: [],
    repositories: [],
    critical: true
  },
  {
    id: 'gitlab',
    name: 'GitLab',
    status: 'Connected',
    lastSync: '2026-03-10T17:44:00Z',
    scopes: ['api'],
    critical: true
  },
  {
    id: 'jenkins',
    name: 'Jenkins',
    status: 'Pending Approval',
    lastSync: null,
    scopes: ['job:read'],
    critical: false
  }
];

export const policyControls = [
  {
    id: 'rbac',
    name: 'Role-Based Access Control',
    description: 'Assign reviewer roles and restrict production deploy approvals to trusted maintainers.',
    status: 'Enforced'
  },
  {
    id: 'mfa',
    name: 'Step-Up MFA',
    description: 'Requires WebAuthn challenge before rollback or production deploy.',
    status: 'Enforced'
  },
  {
    id: 'artifact-quarantine',
    name: 'Artifact Quarantine',
    description: 'Automatically isolates artifacts when risk score exceeds critical thresholds.',
    status: 'Enabled'
  },
  {
    id: 'oauth-pkce',
    name: 'OAuth PKCE Enforcement',
    description: 'GitHub OAuth flows require PKCE + state to prevent token interception.',
    status: 'Enforced'
  },
  {
    id: 'token-vault',
    name: 'Encrypted Token Vault',
    description: 'Access tokens stored server side with HSM-backed envelope encryption, never exposed to browsers.',
    status: 'Enforced'
  }
];

export const authSession = {
  provider: 'GitHub',
  account: '',
  status: 'Disconnected',
  oauthApp: 'DevOps Shield Production',
  scopes: [],
  leastPrivilege: true,
  pkce: true,
  encryptedStorage: 'Hashicorp Vault (HSM backed)',
  tokensExposedToFrontend: false,
  lastVerification: null
};

export const securityHighlights = [
  {
    id: 'token-protection',
    title: 'Encrypted token storage',
    detail: 'GitHub tokens sealed in vault storage, rotated automatically every 12 hours.',
    status: 'Green'
  },
  {
    id: 'pkce-flow',
    title: 'PKCE + strict scopes',
    detail: 'OAuth exchanges require PKCE and minimal scopes, preventing intercepted tokens.',
    status: 'Green'
  },
  {
    id: 'log-sanitization',
    title: 'Log sanitization pipeline',
    detail: 'Secrets scrubbed and ANSI escapes stripped before logs reach analysts.',
    status: 'Green'
  },
  {
    id: 'role-access',
    title: 'Role-based access control',
    detail: 'Ops, auditors, and developers each see only the actions permitted by policy.',
    status: 'Green'
  }
];

export const attackScenarios = [
  {
    id: 'supply-chain',
    name: 'Supply-chain package hijack',
    riskScore: 92,
    type: 'Critical',
    pipeline: 'edge-security',
    description: 'Malicious dependency injected via compromised maintainer, attempting to exfiltrate secrets.',
    detections: ['Dependency Sentinel', 'Artifact Hardening', 'Immutable Ledger'],
    mitigation: 'Package quarantined, runner token revoked, maintainers notified.'
  },
  {
    id: 'secret-leak',
    name: 'Secrets leakage in build logs',
    riskScore: 78,
    type: 'High',
    pipeline: 'frontend-ci',
    description: 'Access token printed to logs during integration tests, risking unauthorized deployments.',
    detections: ['Source Integrity', 'Log Sanitization'],
    mitigation: 'Credential revoked, log scrub pipeline engaged, Jira incident created.'
  },
  {
    id: 'rogue-runner',
    name: 'Untrusted self-hosted runner',
    riskScore: 84,
    type: 'High',
    pipeline: 'payments-cd',
    description: 'CI runner launched from unfamiliar IP range with outdated kernel patches.',
    detections: ['Runner Verification', 'Behavioral AI'],
    mitigation: 'Runner isolated, MFA re-challenge enforced, SOC escalation triggered.'
  }
];

export const simulationRiskHistory = [
  { date: '2025-11-25', riskScore: 0.22, analyses: 14, alerts: 1 },
  { date: '2025-11-28', riskScore: 0.34, analyses: 18, alerts: 2 },
  { date: '2026-03-02', riskScore: 0.28, analyses: 17, alerts: 1 },
  { date: '2026-03-05', riskScore: 0.41, analyses: 20, alerts: 3 },
  { date: '2026-03-07', riskScore: 0.31, analyses: 16, alerts: 2 }
];
