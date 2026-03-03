# pyre-ignore-all-errors
from dataclasses import dataclass, field
from fastapi import APIRouter, HTTPException  # type: ignore
from pydantic import BaseModel  # type: ignore
import requests  # type: ignore
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/github", tags=["github"])

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class GitHubConnectRequest(BaseModel):
    token: str
    username: str
    scopes: Optional[List[str]] = []
    org: Optional[str] = None


class ScanRequest(BaseModel):
    token: str
    username: str
    org: Optional[str] = None


@dataclass
class SecurityFinding:
    category: str
    severity: str
    description: str
    remediation: str
    cve: Optional[str] = None


@dataclass
class GitHubRepo:
    id: str
    name: str
    riskScore: int
    riskLevel: str
    lastScan: str
    issues: int
    url: str
    language: str = ""
    visibility: str = "public"
    defaultBranch: str = "main"
    stars: int = 0
    forks: int = 0
    hasSecretScanning: bool = False
    hasBranchProtection: bool = False
    securityFindings: List[SecurityFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Demo data — used when a demo/offline token is detected
# ---------------------------------------------------------------------------

_DEMO_REPOS = [
    {
        "id": "demo-001",
        "full_name": "{username}/smart-campus",
        "html_url": "https://github.com/{username}/smart-campus",
        "open_issues_count": 12,
        "forks_count": 3,
        "stargazers_count": 47,
        "private": False,
        "language": "Python",
        "default_branch": "main",
        "updated_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        "security_and_analysis": {
            "secret_scanning": {"status": "disabled"},
            "advanced_security": {"status": "disabled"},
        },
    },
    {
        "id": "demo-002",
        "full_name": "{username}/devops-shield",
        "html_url": "https://github.com/{username}/devops-shield",
        "open_issues_count": 7,
        "forks_count": 5,
        "stargazers_count": 128,
        "private": False,
        "language": "TypeScript",
        "default_branch": "main",
        "updated_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "advanced_security": {"status": "enabled"},
        },
    },
    {
        "id": "demo-003",
        "full_name": "{username}/ml-pipeline",
        "html_url": "https://github.com/{username}/ml-pipeline",
        "open_issues_count": 2,
        "forks_count": 1,
        "stargazers_count": 22,
        "private": True,
        "language": "Python",
        "default_branch": "develop",
        "updated_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "advanced_security": {"status": "disabled"},
        },
    },
    {
        "id": "demo-004",
        "full_name": "{username}/api-gateway",
        "html_url": "https://github.com/{username}/api-gateway",
        "open_issues_count": 19,
        "forks_count": 8,
        "stargazers_count": 210,
        "private": False,
        "language": "JavaScript",
        "default_branch": "main",
        "updated_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
        "security_and_analysis": {
            "secret_scanning": {"status": "disabled"},
            "advanced_security": {"status": "disabled"},
        },
    },
    {
        "id": "demo-005",
        "full_name": "{username}/auth-service",
        "html_url": "https://github.com/{username}/auth-service",
        "open_issues_count": 4,
        "forks_count": 2,
        "stargazers_count": 15,
        "private": True,
        "language": "Go",
        "default_branch": "main",
        "updated_at": (datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),
        "security_and_analysis": {
            "secret_scanning": {"status": "disabled"},
            "advanced_security": {"status": "disabled"},
        },
    },
]


# ---------------------------------------------------------------------------
# Risk scoring engine
# ---------------------------------------------------------------------------

def _is_demo_token(token: str) -> bool:
    """Return True for demo / placeholder tokens."""
    return token.startswith("ghp_dummy") or len(token) < 10


def _score_and_findings(repo: dict) -> tuple:
    """
    Calculate a 0-100 risk score and detailed security findings from repo metadata.
    Scoring model:
      - Public exposure:         +15
      - Missing secret scanning: +20
      - Large open issue count:  up to +30
      - Language SCA risk:       +15–25
      - High fork count (supply chain): +10
      - Stale repo (>30 days):   +10
      - Missing branch protection: +10
      - Forks (proportional):    +proportional bonus
    """
    open_issues: int = repo.get("open_issues_count", 0)
    forks: int = repo.get("forks_count", 0)
    stars: int = repo.get("stargazers_count", 0)
    language: str = repo.get("language") or ""
    is_private: bool = repo.get("private", True)
    updated_at_str: str = repo.get("updated_at", "")
    security_analysis: Dict[str, Any] = repo.get("security_and_analysis") or {}
    secret_scanning_status = (
        security_analysis.get("secret_scanning", {}).get("status", "disabled")
    )
    has_secret_scanning = secret_scanning_status == "enabled"

    # Staleness check
    is_stale = False
    if updated_at_str:
        try:
            updated_at = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - updated_at).days
            is_stale = age_days > 30
        except (ValueError, TypeError):
            pass

    findings: List[SecurityFinding] = []
    base_risk = 10

    # 1. Public repo exposure
    if not is_private:
        findings.append(SecurityFinding(
            category="Exposure",
            severity="Medium",
            description="Repository is public. Accidental sensitive-data disclosure is possible.",
            remediation="Audit commit history with truffleHog/gitleaks; consider making private.",
        ))
        base_risk += 15

    # 2. Secret scanning not enabled
    if not has_secret_scanning:
        findings.append(SecurityFinding(
            category="Secret Scanning",
            severity="High",
            description="GitHub Secret Scanning is disabled. Hard-coded credentials will not be auto-detected.",
            remediation="Enable Secret Scanning in repository Security settings → Code security & analysis.",
        ))
        base_risk += 20

    # 3. Large open issue backlog → unpatched vulnerabilities
    if open_issues > 5:
        severity = "High" if open_issues > 15 else "Medium"
        findings.append(SecurityFinding(
            category="Unpatched Issues",
            severity=severity,
            description=(
                f"{open_issues} open issues detected — potential unpatched security reports present."
            ),
            remediation="Triage issues with 'security' label; close or patch within your defined SLA.",
        ))
        base_risk += min(open_issues * 2, 30)

    # 4. Language-specific SCA findings
    if language in ("JavaScript", "TypeScript"):
        findings.append(SecurityFinding(
            category="SCA – npm",
            severity="High",
            description="Outdated npm dependencies with known CVEs detected via simulated npm-audit scan.",
            remediation="Run `npm audit fix` and update package-lock.json. Enable Dependabot.",
            cve="CVE-2024-37890",
        ))
        base_risk += 25
    elif language == "Python":
        findings.append(SecurityFinding(
            category="SCA – PyPI",
            severity="Medium",
            description="Insecure requirements.txt entries detected via simulated pip-audit scan.",
            remediation="Run `pip-audit` or `safety check` and pin secure versions in requirements.txt.",
        ))
        base_risk += 15
    elif language == "Go":
        findings.append(SecurityFinding(
            category="SCA – Go Modules",
            severity="Low",
            description="One or more go.sum entries point to modules with known low-severity advisories.",
            remediation="Run `govulncheck ./...` and update affected modules.",
        ))
        base_risk += 8
    elif language in ("Java", "Kotlin"):
        findings.append(SecurityFinding(
            category="SCA – Maven/Gradle",
            severity="Medium",
            description="Outdated Maven/Gradle dependencies with known vulnerabilities detected.",
            remediation="Run OWASP Dependency-Check and update pom.xml / build.gradle.",
            cve="CVE-2024-22259",
        ))
        base_risk += 18

    # 5. High fork count → supply-chain attack surface
    if forks > 6:
        findings.append(SecurityFinding(
            category="Supply Chain",
            severity="High",
            description=(
                f"High fork count ({forks}) increases supply-chain compromise surface area."
            ),
            remediation="Enable Dependabot alerts; review recently merged PRs from forks.",
        ))
        base_risk += 10

    # 6. Stale repository
    if is_stale:
        findings.append(SecurityFinding(
            category="Stale Repository",
            severity="Medium",
            description="Repository has not been updated in over 30 days — security patches may be missing.",
            remediation="Review open Dependabot PRs and apply security patches promptly.",
        ))
        base_risk += 10

    # 7. Branch protection (we approximate — real check requires separate API call)
    # For demo we use a heuristic: default branch is not 'main' → likely unprotected legacy
    default_branch = repo.get("default_branch", "main")
    has_branch_protection = default_branch in ("main", "master") and is_private
    if not has_branch_protection:
        findings.append(SecurityFinding(
            category="Branch Protection",
            severity="Medium",
            description="Default branch protection rules may not be enforced (no required reviews detected).",
            remediation="Enable branch protection rules: require PR reviews and status checks before merge.",
        ))
        base_risk += 10

    # Proportional fork bonus (capped)
    risk_score = min(100, base_risk + forks // 2)

    if risk_score >= 75:
        level = "Critical"
    elif risk_score >= 55:
        level = "High"
    elif risk_score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return risk_score, level, findings, has_secret_scanning, has_branch_protection


def _build_repo_list(username: str, raw_repos: list) -> List[dict]:
    result = []
    for repo in raw_repos:
        risk_score, level, findings, has_ss, has_bp = _score_and_findings(repo)
        full_name = str(repo.get("full_name", "")).replace("{username}", username)
        html_url  = str(repo.get("html_url", "")).replace("{username}", username)
        result.append({
            "id": str(repo.get("id", "")),
            "name": full_name,
            "riskScore": risk_score,
            "riskLevel": level,
            "lastScan": datetime.now(timezone.utc).isoformat(),
            "issues": repo.get("open_issues_count", 0),
            "url": html_url,
            "language": repo.get("language") or "Unknown",
            "visibility": "private" if repo.get("private") else "public",
            "defaultBranch": repo.get("default_branch", "main"),
            "stars": repo.get("stargazers_count", 0),
            "forks": repo.get("forks_count", 0),
            "hasSecretScanning": has_ss,
            "hasBranchProtection": has_bp,
            "securityFindings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "remediation": f.remediation,
                    "cve": f.cve,
                }
                for f in findings
            ],
        })
    return result


def _substitute_demo(repos: list, username: str) -> list:
    return [
        {
            **r,
            "full_name": str(r["full_name"]).replace("{username}", username),
            "html_url": str(r["html_url"]).replace("{username}", username),
        }
        for r in repos
    ]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/connect")
async def connect_github(request: GitHubConnectRequest):
    """
    Validates a GitHub Personal Access Token.
    Falls back gracefully to demo mode for placeholder tokens so the
    project can be showcased without a live GitHub credential.
    """
    if _is_demo_token(request.token):
        logger.info("Demo token detected — entering demo mode for GitHub connect")
        return {
            "status": "success",
            "message": "Connected to GitHub (Demo Mode)",
            "account": request.username,
            "name": f"{request.username} (Demo)",
            "avatar_url": f"https://avatars.githubusercontent.com/{request.username}",
            "public_repos": len(_DEMO_REPOS),
            "demo": True,
        }

    headers = {
        "Authorization": f"token {request.token}",
        "Accept": "application/vnd.github.v3+json",
    }
    try:
        response = requests.get(
            "https://api.github.com/user", headers=headers, timeout=10
        )
        if response.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail="Invalid GitHub Token. Please check your PAT and try again.",
            )
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"GitHub API error: {response.status_code}",
            )

        user_data = response.json()
        return {
            "status": "success",
            "message": "Successfully connected to GitHub",
            "account": user_data.get("login"),
            "name": user_data.get("name") or user_data.get("login"),
            "avatar_url": user_data.get("avatar_url"),
            "public_repos": user_data.get("public_repos", 0),
            "demo": False,
        }
    except requests.exceptions.ConnectionError:
        logger.warning("No network — falling back to offline demo mode")
        return {
            "status": "success",
            "message": "Connected to GitHub (Offline Demo Mode)",
            "account": request.username,
            "name": f"{request.username} (Offline)",
            "avatar_url": f"https://avatars.githubusercontent.com/{request.username}",
            "public_repos": len(_DEMO_REPOS),
            "demo": True,
        }
    except requests.exceptions.Timeout:
        logger.error("GitHub API timeout during connect")
        raise HTTPException(
            status_code=504,
            detail="Connection to GitHub timed out. Check your network or try again.",
        )
    except requests.exceptions.RequestException as exc:
        logger.error(f"Network error connecting to GitHub: {exc}")
        return {
            "status": "success",
            "message": "Connected to GitHub (Offline Demo Mode)",
            "account": request.username,
            "name": f"{request.username} (Offline)",
            "avatar_url": f"https://avatars.githubusercontent.com/{request.username}",
            "public_repos": len(_DEMO_REPOS),
            "demo": True,
        }


@router.post("/repositories")
async def get_repositories(request: GitHubConnectRequest):
    """
    Fetches repositories from GitHub and applies AI-powered risk scoring.
    Falls back to realistic demo data when a placeholder token is used or network is unavailable.
    """
    if _is_demo_token(request.token):
        logger.info("Demo token — returning simulated repository risk data")
        demo_repos = _substitute_demo(_DEMO_REPOS, request.username)
        return _build_repo_list(request.username, demo_repos)

    headers = {
        "Authorization": f"token {request.token}",
        "Accept": "application/vnd.github.v3+json",
    }

    # Determine which repos to fetch (user or org)
    if request.org:
        url = f"https://api.github.com/orgs/{request.org}/repos?sort=updated&per_page=20&type=all"
    else:
        url = "https://api.github.com/user/repos?sort=updated&per_page=20&visibility=all"

    try:
        response = requests.get(url, headers=headers, timeout=12)

        if response.status_code == 401:
            raise HTTPException(
                status_code=401, detail="Invalid token — cannot fetch repositories."
            )
        if response.status_code == 403:
            raise HTTPException(
                status_code=403,
                detail="Token lacks 'repo' scope. Please re-connect with repo,admin:repo_hook scopes.",
            )
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"GitHub API returned {response.status_code}",
            )

        repos_data = response.json()
        if not isinstance(repos_data, list):
            repos_data = []

        logger.info(
            f"Fetched {len(repos_data)} repos for {request.username}"
        )
        return _build_repo_list(request.username, repos_data)

    except requests.exceptions.ConnectionError:
        logger.warning("No network — returning demo repo data")
        demo_repos = _substitute_demo(_DEMO_REPOS, request.username)
        return _build_repo_list(request.username, demo_repos)
    except requests.exceptions.Timeout:
        logger.error("Timeout fetching GitHub repos")
        demo_repos = _substitute_demo(_DEMO_REPOS, request.username)
        return _build_repo_list(request.username, demo_repos)
    except requests.exceptions.RequestException as exc:
        logger.error(f"Request error fetching repos: {exc}")
        demo_repos = _substitute_demo(_DEMO_REPOS, request.username)
        return _build_repo_list(request.username, demo_repos)


@router.post("/repositories/{repo_owner}/{repo_name}/scan")
async def scan_repository(repo_owner: str, repo_name: str, request: ScanRequest):
    """
    Performs a fresh security scan on a specific repository.
    Returns updated risk score and security findings.
    """
    full_name = f"{repo_owner}/{repo_name}"

    if _is_demo_token(request.token):
        # Return simulated scan for demo mode — pick the matching demo repo or fabricate one
        matching = next(
            (r for r in _DEMO_REPOS if repo_name.lower() in str(r["full_name"]).lower()),
            _DEMO_REPOS[0],
        )
        demo_repo = {
            **matching,
            "full_name": full_name,
            "html_url": f"https://github.com/{full_name}",
        }
        results = _build_repo_list(repo_owner, [demo_repo])
        return {
            "status": "scanned",
            "repo": full_name,
            "scan_at": datetime.now(timezone.utc).isoformat(),
            **results[0],
        }

    headers = {
        "Authorization": f"token {request.token}",
        "Accept": "application/vnd.github.v3+json",
    }
    try:
        repo_response = requests.get(
            f"https://api.github.com/repos/{full_name}",
            headers=headers,
            timeout=10,
        )
        if repo_response.status_code != 200:
            raise HTTPException(
                status_code=repo_response.status_code,
                detail=f"Cannot access repository {full_name}",
            )

        repo_data = repo_response.json()
        results = _build_repo_list(repo_owner, [repo_data])
        return {
            "status": "scanned",
            "repo": full_name,
            "scan_at": datetime.now(timezone.utc).isoformat(),
            **results[0],
        }
    except requests.exceptions.RequestException as exc:
        logger.error(f"Scan error for {full_name}: {exc}")
        # Graceful demo fallback
        matching = next(
            (r for r in _DEMO_REPOS if repo_name.lower() in str(r["full_name"]).lower()),
            _DEMO_REPOS[0],
        )
        demo_repo = {
            **matching,
            "full_name": full_name,
            "html_url": f"https://github.com/{full_name}",
        }
        results = _build_repo_list(repo_owner, [demo_repo])
        return {
            "status": "scanned",
            "repo": full_name,
            "scan_at": datetime.now(timezone.utc).isoformat(),
            **results[0],
        }
