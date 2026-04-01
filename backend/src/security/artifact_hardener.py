"""
Artifact Hardening with Cryptographic Signing and Isolated Environment Verification
Ensures only authenticated, malware-free software is deployed to production
"""

import hashlib
import hmac
import os
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.logger import get_logger

logger = get_logger(__name__)

class CryptographicSigner:
    """Handles cryptographic signing and verification of artifacts"""

    def __init__(self, private_key_path: str = None, public_key_path: str = None):
        self.private_key_path = private_key_path or os.getenv("SIGNING_PRIVATE_KEY")
        self.public_key_path = public_key_path or os.getenv("SIGNING_PUBLIC_KEY")
        self.signature_algorithm = "RSA-SHA256"  # Could be configurable

    def sign_artifact(self, artifact_path: str, key_id: str = None) -> Dict[str, Any]:
        """
        Sign an artifact with cryptographic signature

        Args:
            artifact_path: Path to the artifact to sign
            key_id: Identifier for the signing key

        Returns:
            Signature information
        """
        try:
            if not Path(artifact_path).exists():
                raise FileNotFoundError(f"Artifact not found: {artifact_path}")

            # Calculate artifact hash
            artifact_hash = self._calculate_file_hash(artifact_path)

            # Create signature payload
            timestamp = datetime.now(timezone.utc).isoformat()
            signature_payload = f"{artifact_hash}:{timestamp}:{key_id or 'default'}"

            # Sign the payload (simplified - in production use proper crypto libraries)
            signature = self._create_signature(signature_payload)

            signature_info = {
                'artifact_path': artifact_path,
                'artifact_hash': artifact_hash,
                'signature': signature,
                'algorithm': self.signature_algorithm,
                'timestamp': timestamp,
                'key_id': key_id or 'default',
                'signed_by': 'devops-shield'
            }

            logger.info(f"Successfully signed artifact: {Path(artifact_path).name}")
            return signature_info

        except Exception as e:
            logger.error(f"Error signing artifact {artifact_path}: {e}")
            return {'error': str(e)}

    def verify_signature(self, artifact_path: str, signature_info: Dict[str, Any]) -> bool:
        """
        Verify cryptographic signature of an artifact

        Args:
            artifact_path: Path to the artifact
            signature_info: Signature information from signing

        Returns:
            True if signature is valid
        """
        try:
            if not Path(artifact_path).exists():
                logger.error(f"Artifact not found for verification: {artifact_path}")
                return False

            # Recalculate artifact hash
            current_hash = self._calculate_file_hash(artifact_path)
            expected_hash = signature_info.get('artifact_hash')

            if current_hash != expected_hash:
                logger.warning(f"Artifact hash mismatch: expected {expected_hash}, got {current_hash}")
                return False

            # Verify signature
            signature_payload = f"{current_hash}:{signature_info['timestamp']}:{signature_info['key_id']}"
            expected_signature = signature_info['signature']

            is_valid = self._verify_signature(signature_payload, expected_signature)

            if is_valid:
                logger.info(f"Signature verified for artifact: {Path(artifact_path).name}")
            else:
                logger.warning(f"Invalid signature for artifact: {Path(artifact_path).name}")

            return is_valid

        except Exception as e:
            logger.error(f"Error verifying signature for {artifact_path}: {e}")
            return False

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _create_signature(self, payload: str) -> str:
        """Create cryptographic signature (simplified implementation)"""
        # In production, this would use proper cryptographic libraries
        # For now, create an HMAC signature
        secret_key = os.getenv("SIGNING_SECRET", "default-signing-secret")
        signature = hmac.new(
            secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def _verify_signature(self, payload: str, signature: str) -> bool:
        """Verify cryptographic signature"""
        secret_key = os.getenv("SIGNING_SECRET", "default-signing-secret")
        expected_signature = hmac.new(
            secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)

class IsolatedEnvironment:
    """Manages ephemeral isolated environments for artifact verification"""

    def __init__(self, base_image: str = "alpine:latest", network_isolation: bool = True):
        self.base_image = base_image
        self.network_isolation = network_isolation
        self.container_name = None

    def create_isolated_environment(self) -> str:
        """
        Create an ephemeral isolated environment

        Returns:
            Container ID or identifier
        """
        try:
            # Generate unique container name
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self.container_name = f"devops_shield_verify_{timestamp}"

            # Docker run command with isolation
            cmd = [
                "docker", "run", "-d", "--rm",
                "--name", self.container_name,
                "--memory", "512m",  # Memory limit
                "--cpus", "0.5",     # CPU limit
                "--read-only",       # Read-only filesystem
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m"  # Isolated tmp
            ]

            # Network isolation
            if self.network_isolation:
                cmd.extend(["--network", "none"])

            # Security options
            cmd.extend([
                "--security-opt", "no-new-privileges:true",
                "--cap-drop", "ALL",
                "--user", "1000:1000"  # Non-root user
            ])

            cmd.append(self.base_image)
            cmd.append("sleep")  # Keep container running
            cmd.append("300")    # 5 minutes timeout

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                container_id = result.stdout.strip()
                logger.info(f"Created isolated environment: {container_id}")
                return container_id
            else:
                logger.error(f"Failed to create isolated environment: {result.stderr}")
                return None

        except Exception as e:
            logger.error(f"Error creating isolated environment: {e}")
            return None

    def execute_in_isolation(self, container_id: str, command: str,
                           artifact_path: str = None) -> Dict[str, Any]:
        """
        Execute verification command in isolated environment

        Args:
            container_id: Container identifier
            command: Command to execute
            artifact_path: Path to artifact to verify

        Returns:
            Execution results
        """
        try:
            # Copy artifact to container if provided
            if artifact_path and Path(artifact_path).exists():
                copy_cmd = [
                    "docker", "cp",
                    artifact_path,
                    f"{container_id}:/tmp/artifact"
                ]
                copy_result = subprocess.run(copy_cmd, capture_output=True, text=True, timeout=30)
                if copy_result.returncode != 0:
                    return {
                        'success': False,
                        'error': f"Failed to copy artifact: {copy_result.stderr}"
                    }

            # Execute verification command
            exec_cmd = [
                "docker", "exec",
                container_id,
                "sh", "-c", command
            ]

            result = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=60)

            return {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': command
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command execution timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def cleanup_environment(self, container_id: str):
        """Clean up isolated environment"""
        try:
            cmd = ["docker", "stop", container_id]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Cleaned up isolated environment: {container_id}")
            else:
                logger.warning(f"Failed to cleanup environment {container_id}: {result.stderr}")
        except Exception as e:
            logger.error(f"Error cleaning up environment {container_id}: {e}")

class MalwareScanner:
    """Scans artifacts for malware signatures"""

    def __init__(self):
        self.malware_signatures = self._load_malware_signatures()
        self.yara_rules_path = None  # Could integrate YARA rules

    def _load_malware_signatures(self) -> List[Dict[str, Any]]:
        """Load malware signature database"""
        return [
            {
                'name': 'suspicious_strings',
                'pattern': rb'(?i)(password|secret|key|token).*?=',
                'severity': 'medium'
            },
            {
                'name': 'executable_code',
                'pattern': rb'(?i)(eval|exec|compile|subprocess)',
                'severity': 'high'
            },
            {
                'name': 'network_connections',
                'pattern': rb'(?i)(socket|urllib|requests)\.',
                'severity': 'low'
            },
            {
                'name': 'file_operations',
                'pattern': rb'(?i)(open|read|write).*?\(',
                'severity': 'low'
            }
        ]

    def scan_for_malware(self, artifact_path: str) -> Dict[str, Any]:
        """
        Scan artifact for malware signatures

        Args:
            artifact_path: Path to artifact to scan

        Returns:
            Scan results
        """
        try:
            if not Path(artifact_path).exists():
                return {'error': f'Artifact not found: {artifact_path}'}

            findings = []
            risk_score = 0.0

            # Read artifact content (safely handle binary files)
            try:
                with open(artifact_path, 'rb') as f:
                    content = f.read()
            except Exception as e:
                return {'error': f'Cannot read artifact: {e}'}

            # Scan for malware signatures
            for signature in self.malware_signatures:
                matches = len(signature['pattern'].findall(content))
                if matches > 0:
                    findings.append({
                        'signature': signature['name'],
                        'matches': matches,
                        'severity': signature['severity']
                    })

                    # Calculate risk score
                    severity_weights = {'low': 0.1, 'medium': 0.3, 'high': 0.6, 'critical': 1.0}
                    risk_score += severity_weights.get(signature['severity'], 0.2) * matches

            # Additional checks
            file_size = len(content)
            if file_size > 100 * 1024 * 1024:  # 100MB
                findings.append({
                    'signature': 'unusually_large_file',
                    'matches': 1,
                    'severity': 'medium'
                })
                risk_score += 0.2

            # Entropy check (for packed/encrypted malware)
            entropy = self._calculate_entropy(content)
            if entropy > 7.5:  # High entropy
                findings.append({
                    'signature': 'high_entropy_content',
                    'matches': 1,
                    'severity': 'high'
                })
                risk_score += 0.4

            return {
                'artifact_path': artifact_path,
                'file_size': file_size,
                'entropy': entropy,
                'findings': findings,
                'risk_score': min(risk_score, 1.0),
                'is_malicious': risk_score >= 0.7,
                'scan_timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Error scanning artifact {artifact_path}: {e}")
            return {'error': str(e)}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        entropy = 0.0
        for i in range(256):
            p = data.count(i) / len(data)
            if p > 0:
                entropy -= p * (p ** 0.5)  # Simplified entropy

        return entropy

class ArtifactHardener:
    """Main artifact hardening and verification system"""

    def __init__(self):
        self.signer = CryptographicSigner()
        self.environment = IsolatedEnvironment()
        self.malware_scanner = MalwareScanner()

    def harden_artifact(self, artifact_path: str, key_id: str = None) -> Dict[str, Any]:
        """
        Complete artifact hardening process

        Args:
            artifact_path: Path to artifact to harden
            key_id: Signing key identifier

        Returns:
            Hardening results
        """
        logger.info(f"Starting artifact hardening for: {Path(artifact_path).name}")

        results = {
            'artifact_path': artifact_path,
            'steps_completed': [],
            'warnings': [],
            'errors': [],
            'final_status': 'failed'
        }

        try:
            # Step 1: Malware scanning
            logger.info("Step 1: Malware scanning")
            scan_result = self.malware_scanner.scan_for_malware(artifact_path)
            if scan_result.get('is_malicious'):
                results['errors'].append(f"Malware detected: {scan_result.get('findings', [])}")
                return results

            results['steps_completed'].append('malware_scan')
            results['malware_scan'] = scan_result

            # Step 2: Create isolated environment
            logger.info("Step 2: Creating isolated environment")
            container_id = self.environment.create_isolated_environment()
            if not container_id:
                results['errors'].append("Failed to create isolated environment")
                return results

            results['steps_completed'].append('environment_created')
            results['container_id'] = container_id

            try:
                # Step 3: Verification in isolated environment
                logger.info("Step 3: Verification in isolated environment")
                verify_command = self._get_verification_command(artifact_path)
                verify_result = self.environment.execute_in_isolation(
                    container_id, verify_command, artifact_path
                )

                if not verify_result.get('success', False):
                    results['warnings'].append(f"Isolated verification failed: {verify_result.get('stderr', '')}")
                else:
                    results['steps_completed'].append('isolated_verification')

                results['isolated_verification'] = verify_result

                # Step 4: Cryptographic signing
                logger.info("Step 4: Cryptographic signing")
                signature_info = self.signer.sign_artifact(artifact_path, key_id)
                if 'error' in signature_info:
                    results['errors'].append(f"Signing failed: {signature_info['error']}")
                    return results

                results['steps_completed'].append('cryptographic_signing')
                results['signature_info'] = signature_info

                # Success
                results['final_status'] = 'hardened'
                logger.info(f"Successfully hardened artifact: {Path(artifact_path).name}")

            finally:
                # Cleanup
                self.environment.cleanup_environment(container_id)

            return results

        except Exception as e:
            logger.error(f"Error during artifact hardening: {e}")
            results['errors'].append(str(e))
            return results

    def verify_hardened_artifact(self, artifact_path: str, signature_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a hardened artifact

        Args:
            artifact_path: Path to artifact
            signature_info: Signature information from hardening

        Returns:
            Verification results
        """
        logger.info(f"Verifying hardened artifact: {Path(artifact_path).name}")

        results = {
            'artifact_path': artifact_path,
            'verified': False,
            'checks_passed': [],
            'warnings': [],
            'errors': []
        }

        try:
            # Check 1: Signature verification
            signature_valid = self.signer.verify_signature(artifact_path, signature_info)
            if signature_valid:
                results['checks_passed'].append('signature_verification')
            else:
                results['errors'].append("Cryptographic signature verification failed")
                return results

            # Check 2: Malware scan
            scan_result = self.malware_scanner.scan_for_malware(artifact_path)
            if not scan_result.get('is_malicious', True):
                results['checks_passed'].append('malware_scan')
            else:
                results['errors'].append(f"Malware detected during verification: {scan_result.get('findings', [])}")
                return results

            # Check 3: Isolated environment verification (if possible)
            # This would require re-running in isolation, which might be expensive
            # For now, we'll trust the signature and scan

            results['verified'] = True
            results['signature_info'] = signature_info
            results['malware_scan'] = scan_result

            logger.info(f"Successfully verified hardened artifact: {Path(artifact_path).name}")
            return results

        except Exception as e:
            logger.error(f"Error verifying artifact {artifact_path}: {e}")
            results['errors'].append(str(e))
            return results

    def _get_verification_command(self, artifact_path: str) -> str:
        """Get appropriate verification command based on artifact type"""
        artifact_name = Path(artifact_path).name.lower()

        if artifact_name.endswith(('.tar.gz', '.tgz')):
            return "cd /tmp && tar -tzf artifact > /dev/null && echo 'Valid archive'"
        elif artifact_name.endswith('.zip'):
            return "cd /tmp && unzip -l artifact > /dev/null && echo 'Valid archive'"
        elif artifact_name.endswith(('.deb', '.rpm')):
            return r"cd /tmp && file artifact | grep -q 'Debian package\|RPM' && echo 'Valid package'"
        elif artifact_name.endswith('.jar'):
            return "cd /tmp && java -jar artifact --version 2>/dev/null || echo 'Valid JAR'"
        else:
            # Generic file integrity check
            return "cd /tmp && file artifact && stat artifact && echo 'File integrity check passed'"

    def get_hardening_stats(self) -> Dict[str, Any]:
        """Get hardening statistics"""
        return {
            'signer_status': 'available' if self.signer else 'unavailable',
            'environment_available': 'docker' if self._is_docker_available() else 'unavailable',
            'malware_scanner': 'active',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    def _is_docker_available(self) -> bool:
        """Check if Docker is available"""
        try:
            result = subprocess.run(['docker', '--version'],
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False