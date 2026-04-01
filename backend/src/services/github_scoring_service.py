import httpx
import random
from datetime import datetime, timezone
import logging
from typing import Optional, List, Dict, Any

try:
    from src.security.performance_cache import performance_optimizer
except ImportError:
    performance_optimizer = None

try:
    from src.security.secrets_manager import secret_vault
except ImportError:
    secret_vault = None

logger = logging.getLogger(__name__)

class GitHubScoringService:
    """
    Service to calculate security and reputation scores for GitHub accounts and repositories.
    Uses real GitHub API data when a token is available.
    """
    
    GITHUB_API_BASE = "https://api.github.com"
    
    async def calculate_repo_score(self, username: str, repo_name: str, user_id: str = None) -> dict:
        """
        Calculate repository score with caching support and real API integration.
        """
        cache_key = {"username": username, "repo_name": repo_name, "user_id": user_id}
        
        if performance_optimizer:
            return await performance_optimizer.cached_operation(
                "github_repo_scoring_real",
                cache_key,
                lambda: self._compute_repo_score(username, repo_name, user_id),
                ttl=900 # 15 minutes cache
            )
        
        return await self._compute_repo_score(username, repo_name, user_id)

    async def _compute_repo_score(self, username: str, repo_name: str, user_id: str = None) -> dict:
        """
        Fetch metrics from GitHub and compute scores.
        """
        token = self._get_user_token(user_id)
        
        if not token:
            logger.warning(f"No GitHub token found for user {user_id}, using simulated data")
            return self._generate_simulated_score(username, repo_name)
            
        try:
            metrics = await self._fetch_github_metrics(username, repo_name, token)
            return self._calculate_scores_from_metrics(username, repo_name, metrics)
        except Exception as e:
            logger.error(f"Error fetching GitHub metrics for {username}/{repo_name}: {e}")
            return self._generate_simulated_score(username, repo_name)

    def _get_user_token(self, user_id: str) -> Optional[str]:
        """Retrieve encrypted token from vault"""
        if not secret_vault or not user_id:
            return None
        return secret_vault.retrieve_secret(f"github_token_{user_id}")

    async def _fetch_github_metrics(self, username: str, repo_name: str, token: str) -> Dict[str, Any]:
        """Fetch actual data from GitHub API"""
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with httpx.AsyncClient() as client:
            # 1. Fetch Repo Info
            repo_url = f"{self.GITHUB_API_BASE}/repos/{username}/{repo_name}"
            repo_resp = await client.get(repo_url, headers=headers)
            repo_resp.raise_for_status()
            repo_data = repo_resp.json()
            
            # 2. Fetch User Info (for account age/followers)
            user_url = f"{self.GITHUB_API_BASE}/users/{username}"
            user_resp = await client.get(user_url, headers=headers)
            user_data = user_resp.json() if user_resp.status_code == 200 else {}
            
            # 3. Check Branch Protection (requires more scopes, failing gracefully)
            protection_url = f"{repo_url}/branches/main/protection"
            prot_resp = await client.get(protection_url, headers=headers)
            has_protection = prot_resp.status_code == 200
            
            # 4. Check for signed commits (check latest commit)
            commits_url = f"{repo_url}/commits"
            commits_resp = await client.get(commits_url, headers=headers, params={"per_page": 1})
            signed_commits = False
            if commits_resp.status_code == 200:
                commits = commits_resp.json()
                if commits and "verification" in commits[0].get("commit", {}):
                    signed_commits = commits[0]["commit"]["verification"].get("verified", False)

            return {
                "account_age_days": (datetime.now(timezone.utc) - datetime.fromisoformat(user_data.get("created_at", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00"))).days,
                "followers": user_data.get("followers", 0),
                "has_2fa": user_data.get("two_factor_authentication", False), # Usually only available via special scopes
                "is_verified": user_data.get("type") == "User",
                "last_push_days": (datetime.now(timezone.utc) - datetime.fromisoformat(repo_data.get("pushed_at", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00"))).days,
                "stars": repo_data.get("stargazers_count", 0),
                "forks": repo_data.get("forks_count", 0),
                "open_issues": repo_data.get("open_issues_count", 0),
                "signed_commits": signed_commits,
                "secret_scanning": repo_data.get("security_and_analysis", {}).get("secret_scanning", {}).get("status") == "enabled",
                "branch_protection": has_protection
            }

    def _calculate_scores_from_metrics(self, username: str, repo_name: str, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Heuristics mapping real metrics to scores"""
        # Reputation Score
        reputation_score = (
            min(metrics["account_age_days"] / 3650, 1.0) * 0.3 +
            min(metrics["followers"] / 100, 1.0) * 0.5 +
            (0.2 if metrics["is_verified"] else 0.0)
        )
        
        # Health Score
        health_score = (
            (1.0 - min(metrics["last_push_days"] / 180, 1.0)) * 0.4 +
            min(metrics["stars"] / 1000, 0.3) +
            (0.3 if metrics["open_issues"] < 100 else 0.1)
        )
        
        # Security Score
        security_score = (
            (0.4 if metrics["signed_commits"] else 0.0) +
            (0.3 if metrics["secret_scanning"] else 0.1) +
            (0.3 if metrics["branch_protection"] else 0.0)
        )
        
        overall_score = (reputation_score * 0.3 + health_score * 0.3 + security_score * 0.4)
        
        return {
            "repository": f"{username}/{repo_name}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "real_data": True,
            "scores": {
                "reputation": round(reputation_score, 2),
                "health": round(health_score, 2),
                "security": round(security_score, 2),
                "overall": round(overall_score, 2)
            },
            "metrics": metrics,
            "trust_level": self._determine_trust_level(overall_score)
        }

    def _generate_simulated_score(self, username: str, repo_name: str) -> dict:
        """Fallback to simulated data if no token or error"""
        seed = hash(f"{username}/{repo_name}")
        random.seed(seed)
        
        account_age_days = random.randint(30, 3650)
        has_2fa = random.choice([True, True, True, False])
        is_verified = random.choice([True, False])
        
        reputation_score = (
            min(account_age_days / 365, 1.0) * 0.4 +
            (1.0 if has_2fa else 0.0) * 0.4 +
            (1.0 if is_verified else 0.0) * 0.2
        )
        
        last_push_days = random.randint(0, 180)
        resolution_rate = random.uniform(0.1, 0.95)
        fresh_dependencies = random.choice([True, True, False])
        
        health_score = (
            (1.0 - min(last_push_days / 90, 1.0)) * 0.5 +
            resolution_rate * 0.3 +
            (1.0 if fresh_dependencies else 0.0) * 0.2
        )
        
        signed_commits = random.choice([True, False])
        secret_scanning = random.choice([True, True, False])
        branch_protection = random.choice([True, False])
        
        security_score = (
            (1.0 if signed_commits else 0.0) * 0.3 +
            (1.0 if secret_scanning else 0.0) * 0.4 +
            (1.0 if branch_protection else 0.0) * 0.3
        )
        
        overall_score = (reputation_score * 0.3 + health_score * 0.3 + security_score * 0.4)
        
        return {
            "repository": f"{username}/{repo_name}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "real_data": False,
            "scores": {
                "reputation": round(reputation_score, 2),
                "health": round(health_score, 2),
                "security": round(security_score, 2),
                "overall": round(overall_score, 2)
            },
            "metrics": {
                "account_age_days": account_age_days,
                "has_2fa": has_2fa,
                "is_verified": is_verified,
                "last_push_days": last_push_days,
                "resolution_rate": round(resolution_rate, 2),
                "signed_commits": signed_commits,
                "secret_scanning": secret_scanning,
                "branch_protection": branch_protection
            },
            "trust_level": self._determine_trust_level(overall_score)
        }

    def _determine_trust_level(self, score: float) -> str:
        if score > 0.8: return "High"
        if score > 0.6: return "Medium"
        return "Low"

    async def list_account_scores(self, username: str, user_id: str = None) -> list:
        """
        Return a list of scores for actual repositories associated with the account if token is available.
        """
        token = self._get_user_token(user_id)
        repo_names = []
        
        if token:
            try:
                # Fetch real repos from user
                headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"{self.GITHUB_API_BASE}/user/repos?sort=updated&per_page=5", headers=headers)
                    if resp.status_code == 200:
                        repos = resp.json()
                        repo_names = [r["name"] for r in repos]
            except Exception as e:
                logger.error(f"Error fetching repo list: {e}")
        
        if not repo_names:
            # Simulated list fallback
            repo_names = ["devops-core", "auth-service", "data-pipeline", "security-mesh", "ui-dashboard"]
            
        scores = []
        for repo in repo_names:
            scores.append(await self.calculate_repo_score(username, repo, user_id))
            
        return scores

github_scoring_service = GitHubScoringService()
