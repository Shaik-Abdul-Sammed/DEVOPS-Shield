"""
Source Integrity Manager
AI-driven behavioral analysis and pre-commit secret scanning for developer identity verification
"""

import os
import re
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.logger import get_logger
from src.core.cybersecurity_analyzer import CybersecurityAnalyzer

try:
    from src.security.performance_cache import performance_optimizer
except ImportError:
    performance_optimizer = None

try:
    from src.security.adaptive_thresholds import adaptive_thresholds
except ImportError:
    adaptive_thresholds = None

logger = get_logger(__name__)

class DeveloperProfile:
    """Profile of developer behavior patterns"""

    def __init__(self, developer_id: str):
        self.developer_id = developer_id
        self.commit_history = []
        self.behavioral_baseline = {
            'avg_commit_size': 0,
            'avg_files_changed': 0,
            'typical_hours': set(),
            'common_file_types': set(),
            'commit_frequency': 0,
            'last_commit_time': None,
            'trusted_devices': set(),
            'trusted_ips': set()
        }
        self.risk_score = 0.0
        self.last_updated = datetime.now(timezone.utc)

    def update_baseline(self, commit_data: Dict[str, Any]):
        """Update behavioral baseline with new commit data"""
        self.commit_history.append(commit_data)

        # Keep only last 100 commits for baseline
        if len(self.commit_history) > 100:
            self.commit_history = self.commit_history[-100:]

        # Update averages
        if self.commit_history:
            sizes = [c.get('lines_added', 0) + c.get('lines_deleted', 0) for c in self.commit_history]
            files_counts = [len(c.get('files_changed', [])) for c in self.commit_history]

            self.behavioral_baseline['avg_commit_size'] = sum(sizes) / len(sizes)
            self.behavioral_baseline['avg_files_changed'] = sum(files_counts) / len(files_counts)

            # Update typical hours
            for commit in self.commit_history[-10:]:  # Last 10 commits
                if 'timestamp' in commit:
                    hour = datetime.fromtimestamp(commit['timestamp']).hour
                    self.behavioral_baseline['typical_hours'].add(hour)

            # Update file types
            for commit in self.commit_history[-20:]:  # Last 20 commits
                for file in commit.get('files_changed', []):
                    ext = Path(file).suffix
                    if ext:
                        self.behavioral_baseline['common_file_types'].add(ext)

        self.last_updated = datetime.now(timezone.utc)

    def calculate_identity_score(self, current_commit: Dict[str, Any], device_id: str, ip_address: str) -> float:
        """Calculate identity verification score based on behavioral patterns"""
        score = 1.0  # Start with perfect score
        anomalies = []

        # Check device consistency
        if device_id not in self.behavioral_baseline['trusted_devices']:
            if self.behavioral_baseline['trusted_devices']:  # Has baseline
                score -= 0.3
                anomalies.append("untrusted_device")
            else:
                # First time, add to trusted devices
                self.behavioral_baseline['trusted_devices'].add(device_id)

        # Check IP consistency
        if ip_address not in self.behavioral_baseline['trusted_ips']:
            if self.behavioral_baseline['trusted_ips']:
                score -= 0.2
                anomalies.append("untrusted_ip")
            else:
                self.behavioral_baseline['trusted_ips'].add(ip_address)

        # Check commit timing
        if 'timestamp' in current_commit:
            commit_hour = datetime.fromtimestamp(current_commit['timestamp']).hour
            if self.behavioral_baseline['typical_hours'] and commit_hour not in self.behavioral_baseline['typical_hours']:
                score -= 0.15
                anomalies.append("unusual_commit_time")

        # Check commit size deviation
        if self.behavioral_baseline['avg_commit_size'] > 0:
            commit_size = current_commit.get('lines_added', 0) + current_commit.get('lines_deleted', 0)
            deviation = abs(commit_size - self.behavioral_baseline['avg_commit_size']) / self.behavioral_baseline['avg_commit_size']
            if deviation > 2.0:  # More than 2x deviation
                score -= min(0.2, deviation * 0.1)
                anomalies.append("unusual_commit_size")

        # Check file types
        if self.behavioral_baseline['common_file_types']:
            current_types = {Path(f).suffix for f in current_commit.get('files_changed', []) if Path(f).suffix}
            new_types = current_types - self.behavioral_baseline['common_file_types']
            if new_types and len(current_types) > 0:
                ratio = len(new_types) / len(current_types)
                score -= min(0.1, ratio * 0.2)
                anomalies.append("unusual_file_types")

        logger.info(f"Identity score for {self.developer_id}: {score:.2f}, anomalies: {anomalies}")
        return max(0.0, score)

class PreCommitSecretsScanner:
    """Pre-commit hooks for secret scanning"""

    def __init__(self):
        self.secret_patterns = self._load_secret_patterns()
        self.whitelist_patterns = [
            r'example\.com',
            r'your-domain\.com',
            r'localhost',
            r'127\.0\.0\.1',
            r'test@example\.com'
        ]

    def _load_secret_patterns(self) -> List[Dict[str, Any]]:
        """Load comprehensive secret detection patterns"""
        return [
            {
                'name': 'AWS Access Key',
                'pattern': r'AKIA[0-9A-Z]{16}',
                'severity': 'critical'
            },
            {
                'name': 'AWS Secret Key',
                'pattern': r'(?i)aws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
                'severity': 'critical'
            },
            {
                'name': 'Generic API Key',
                'pattern': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_-]{20,}["\']?',
                'severity': 'high'
            },
            {
                'name': 'JWT Token',
                'pattern': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
                'severity': 'high'
            },
            {
                'name': 'Private Key',
                'pattern': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                'severity': 'critical'
            },
            {
                'name': 'Password',
                'pattern': r'(?i)password\s*[:=]\s*["\']?[^"\s]{8,}["\']?',
                'severity': 'high'
            },
            {
                'name': 'Database URL',
                'pattern': r'(?i)(mongodb|postgresql|mysql)://[^"\s]+',
                'severity': 'high'
            },
            {
                'name': 'Slack Token',
                'pattern': r'xox[baprs]-([0-9a-zA-Z]{10,48})',
                'severity': 'high'
            },
            {
                'name': 'GitHub Token',
                'pattern': r'ghp_[A-Za-z0-9]{36}',
                'severity': 'high'
            }
        ]

    def scan_commit(self, commit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan commit for hardcoded secrets

        Args:
            commit_data: Commit information including files and changes

        Returns:
            Scan results with found secrets
        """
        findings = []
        total_risk = 0.0

        try:
            # Get files changed in commit
            files_changed = commit_data.get('files_changed', [])
            commit_content = commit_data.get('content', {})

            for file_path in files_changed:
                if file_path in commit_content:
                    content = commit_content[file_path]
                    file_findings = self._scan_file_content(content, file_path)
                    findings.extend(file_findings)

            # Calculate risk score
            severity_weights = {'low': 0.1, 'medium': 0.3, 'high': 0.6, 'critical': 1.0}
            for finding in findings:
                total_risk += severity_weights.get(finding['severity'], 0.3)

            total_risk = min(total_risk, 1.0)

            return {
                'secrets_found': len(findings) > 0,
                'findings': findings,
                'risk_score': total_risk,
                'files_scanned': len(files_changed),
                'scan_timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Error scanning commit for secrets: {e}")
            return {
                'secrets_found': False,
                'findings': [],
                'risk_score': 0.0,
                'error': str(e)
            }

    def _scan_file_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan individual file content for secrets"""
        findings = []

        # Skip binary files and certain file types
        if self._should_skip_file(file_path):
            return findings

        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern_info in self.secret_patterns:
                matches = re.findall(pattern_info['pattern'], line, re.IGNORECASE)
                if matches:
                    # Check if it's in whitelist
                    if not self._is_whitelisted(line):
                        findings.append({
                            'type': pattern_info['name'],
                            'severity': pattern_info['severity'],
                            'file': file_path,
                            'line': line_num,
                            'matched_text': self._sanitize_match(line),
                            'pattern': pattern_info['pattern']
                        })

        return findings

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped"""
        skip_extensions = {'.jpg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll'}
        skip_patterns = ['node_modules', '.git', '__pycache__', '.venv']

        if Path(file_path).suffix.lower() in skip_extensions:
            return True

        for pattern in skip_patterns:
            if pattern in file_path:
                return True

        return False

    def _is_whitelisted(self, line: str) -> bool:
        """Check if line contains whitelisted content"""
        for pattern in self.whitelist_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

    def _sanitize_match(self, line: str) -> str:
        """Sanitize matched line to avoid exposing secrets in logs"""
        # Replace potential secrets with [REDACTED]
        sanitized = re.sub(r'["\'][A-Za-z0-9_-]{10,}["\']', '[REDACTED]', line)
        sanitized = re.sub(r'[A-Za-z0-9+/=]{20,}', '[REDACTED]', sanitized)
        return sanitized.strip()

class SourceIntegrityManager:
    """Main manager for source integrity verification"""

    def __init__(self):
        self.developer_profiles = {}
        self.cyber_analyzer = CybersecurityAnalyzer()
        self.secrets_scanner = PreCommitSecretsScanner()
        self.profiles_file = Path("data/developer_profiles.json")
        self._load_profiles()

    def _load_profiles(self):
        """Load developer profiles from storage"""
        try:
            if self.profiles_file.exists():
                with open(self.profiles_file, 'r') as f:
                    data = json.load(f)
                    for dev_id, profile_data in data.items():
                        profile = DeveloperProfile(dev_id)
                        profile.behavioral_baseline = profile_data.get('baseline', profile.behavioral_baseline)
                        profile.commit_history = profile_data.get('history', [])
                        profile.risk_score = profile_data.get('risk_score', 0.0)
                        self.developer_profiles[dev_id] = profile
                logger.info(f"Loaded {len(self.developer_profiles)} developer profiles")
        except Exception as e:
            logger.error(f"Error loading developer profiles: {e}")

    def _save_profiles(self):
        """Save developer profiles to storage"""
        try:
            self.profiles_file.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            for dev_id, profile in self.developer_profiles.items():
                data[dev_id] = {
                    'baseline': profile.behavioral_baseline,
                    'history': profile.commit_history[-50:],  # Keep last 50 commits
                    'risk_score': profile.risk_score
                }
            with open(self.profiles_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving developer profiles: {e}")

    def verify_source_integrity(self, developer_id: str, commit_sha: str, device_id: str,
                              ip_address: str, commit_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Comprehensive source integrity verification with performance optimizations

        Args:
            developer_id: Developer identifier
            commit_sha: Commit SHA hash
            device_id: Device identifier
            ip_address: IP address
            commit_data: Optional commit details for analysis

        Returns:
            Verification results
        """
        logger.info(f"Starting source integrity verification for {developer_id}, commit {commit_sha[:8]}")

        # Use cached results for repeated verifications
        cache_key = {
            'developer_id': developer_id,
            'commit_sha': commit_sha,
            'device_id': device_id,
            'ip_address': ip_address
        }

        def compute_verification():
            return self._compute_source_integrity(developer_id, commit_sha, device_id, ip_address, commit_data)

        # Cache for 5 minutes (300 seconds) for repeated checks
        result = performance_optimizer.cached_operation(
            'source_integrity_check',
            cache_key,
            compute_verification,
            ttl=300
        )

        logger.warning(f"Source Integrity result: approved={result['approved']}, score={result['combined_score']:.2f}, secrets={result.get('secrets_found', False)}")
        return result

    def _compute_source_integrity(self, developer_id: str, commit_sha: str, device_id: str,
                                ip_address: str, commit_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Internal computation of source integrity (not cached)"""
        # Get or create developer profile
        if developer_id not in self.developer_profiles:
            self.developer_profiles[developer_id] = DeveloperProfile(developer_id)

        profile = self.developer_profiles[developer_id]

        # Prepare commit data for analysis
        if not commit_data:
            commit_data = {
                'commit_sha': commit_sha,
                'timestamp': datetime.now(timezone.utc).timestamp(),
                'files_changed': [],
                'lines_added': 0,
                'lines_deleted': 0
            }

        # 1. Behavioral Analysis - Identity Verification
        identity_score = profile.calculate_identity_score(commit_data, device_id, ip_address)

        # 2. Advanced Behavioral Analysis using CybersecurityAnalyzer
        behavioral_analysis = self.cyber_analyzer.analyze_behavioral_anomaly(developer_id, commit_data)

        # 3. Pre-commit Secret Scanning (only scan if not cached)
        secrets_scan = self.secrets_scanner.scan_commit(commit_data)

        # 4. Update developer profile with this commit
        profile.update_baseline(commit_data)
        self._save_profiles()

        # Calculate overall approval using adaptive thresholds
        behavioral_risk = behavioral_analysis.get('risk_score', 0.0)
        secrets_risk = secrets_scan.get('risk_score', 0.0)

        # Get adaptive thresholds
        identity_threshold = adaptive_thresholds.get_adaptive_threshold('source_integrity', 'identity_score_threshold')
        behavioral_threshold = adaptive_thresholds.get_adaptive_threshold('source_integrity', 'behavioral_risk_threshold')
        secrets_threshold = adaptive_thresholds.get_adaptive_threshold('source_integrity', 'secrets_risk_threshold')
        combined_threshold = adaptive_thresholds.get_adaptive_threshold('source_integrity', 'combined_score_threshold')

        # Identity score should be high, behavioral and secrets risk should be low
        combined_score = (identity_score * 0.5) + ((1 - behavioral_risk) * 0.3) + ((1 - secrets_risk) * 0.2)

        # Use adaptive approval logic
        identity_ok = identity_score >= identity_threshold
        behavioral_ok = behavioral_risk <= behavioral_threshold
        secrets_ok = secrets_risk <= secrets_threshold and not secrets_scan.get('secrets_found', False)
        combined_ok = combined_score >= combined_threshold

        approved = identity_ok and behavioral_ok and secrets_ok and combined_ok

        reasons = []
        if not identity_ok:
            reasons.append(".2f")
        if not behavioral_ok:
            reasons.append(f"High behavioral risk: {behavioral_risk:.2f} (threshold: {behavioral_threshold:.2f})")
        if not secrets_ok:
            if secrets_scan.get('secrets_found', False):
                reasons.append(f"Secrets detected: {len(secrets_scan.get('findings', []))} findings")
            else:
                reasons.append(f"High secrets risk: {secrets_risk:.2f} (threshold: {secrets_threshold:.2f})")
        if not combined_ok:
            reasons.append(f"Combined score too low: {combined_score:.2f} (threshold: {combined_threshold:.2f})")

        result = {
            'identity_score': identity_score,
            'behavioral_risk': behavioral_risk,
            'secrets_found': secrets_scan.get('secrets_found', False),
            'secrets_findings': secrets_scan.get('findings', []),
            'combined_score': combined_score,
            'approved': approved,
            'reasons': reasons,
            'developer_id': developer_id,
            'commit_sha': commit_sha,
            'verification_timestamp': datetime.now(timezone.utc).isoformat()
        }

        return result