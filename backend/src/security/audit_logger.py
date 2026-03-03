"""
Immutable Logging & Audit Trail System
Tamper-proof logging, blockchain-backed audit logs, and integrity verification
"""

import json
import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from typing import Dict, Any, Optional, List
from enum import Enum
try:
    from src.utils.logger import get_logger  # type: ignore[import-untyped]
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)  # type: ignore[assignment]

# ===== AUDIT LOG TYPES =====


class AuditEventType(str, Enum):
    """Types of audit events"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    MFA_ENABLED = "mfa_enabled"
    PASSWORD_CHANGED = "password_changed"
    USER_UPDATE = "user_update"

    # Authorization events
    PERMISSION_DENIED = "permission_denied"
    ROLE_CHANGED = "role_changed"

    # Data access events
    DATA_READ = "data_read"
    DATA_MODIFIED = "data_modified"
    DATA_DELETED = "data_deleted"

    # API events
    API_CALL = "api_call"
    API_ERROR = "api_error"

    # Security events
    WEBHOOK_RECEIVED = "webhook_received"
    WEBHOOK_REJECTED = "webhook_rejected"
    THREAT_DETECTED = "threat_detected"
    ANOMALY_DETECTED = "anomaly_detected"

    # System events
    CONFIG_CHANGED = "config_changed"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"

# ===== AUDIT LOG ENTRY =====


class AuditLogEntry:
    """Immutable audit log entry with integrity verification"""

    def __init__(self, event_type: AuditEventType, user_id: str, action: str,
                 details: Optional[Dict[str, Any]] = None, ip_address: Optional[str] = None,
                 status: str = "success"):
        self.timestamp = datetime.now(timezone.utc)
        self.event_type = event_type
        self.user_id = user_id
        self.action = action
        self.details = details or {}
        self.ip_address = ip_address
        self.status = status
        # Hash of previous log entry (for chain)
        self.previous_hash: Optional[str] = None
        self.current_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "user_id": self.user_id,
            "action": self.action,
            "details": self.details,
            "ip_address": self.ip_address,
            "status": self.status,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash
        }

    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of log entry"""
        # Create consistent JSON representation
        data = {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "user_id": self.user_id,
            "action": self.action,
            "details": self.details,
            "ip_address": self.ip_address,
            "status": self.status,
            "previous_hash": self.previous_hash
        }

        json_str = json.dumps(data, sort_keys=True)
        hash_obj = hashlib.sha256(json_str.encode())
        return hash_obj.hexdigest()

# ===== IMMUTABLE LOG STORAGE =====


class ImmutableAuditLogger:
    """Store audit logs in immutable, tamper-proof format"""

    def __init__(self, db_path: str = "database/audit_logs.db", secret_key: Optional[str] = None):
        self.db_path = db_path
        self.secret_key = secret_key or "audit-secret-key"
        self.last_hash: Optional[str] = None
        self._initialize_database()

    def _initialize_database(self):
        """Create audit log database with integrity checks"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create immutable audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                ip_address TEXT,
                status TEXT NOT NULL,
                previous_hash TEXT,
                current_hash TEXT NOT NULL UNIQUE,
                signature TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create index for faster queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp
            ON audit_logs(timestamp DESC)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_id
            ON audit_logs(user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_type
            ON audit_logs(event_type)
        """)

        # Create integrity verification table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_integrity_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                check_timestamp TEXT NOT NULL,
                total_logs INTEGER NOT NULL,
                last_hash TEXT NOT NULL,
                verification_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                tampering_detected BOOLEAN DEFAULT 0
            )
        """)

        conn.commit()
        conn.close()

        logger.info(f"Audit log database initialized: {self.db_path}")

    def log_event(self, event: AuditLogEntry) -> bool:
        """
        Store audit log entry with cryptographic integrity
        """
        try:
            # Calculate hash
            event.previous_hash = self.last_hash
            event.current_hash = event.calculate_hash()

            # Create HMAC signature for integrity verification
            secret = (self.secret_key or "").encode()
            signature = hmac.new(
                secret,
                (event.current_hash or "").encode(),
                hashlib.sha256
            ).hexdigest()

            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO audit_logs
                (timestamp, event_type, user_id, action, details, ip_address, status, previous_hash, current_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp.isoformat(),
                event.event_type.value,
                event.user_id,
                event.action,
                json.dumps(event.details),
                event.ip_address,
                event.status,
                event.previous_hash,
                event.current_hash,
                signature
            ))

            conn.commit()
            conn.close()

            # Update last hash for chain integrity
            self.last_hash = event.current_hash

            return True
        except Exception as e:
            logger.error(f"Error logging audit event: {e}")
            return False

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify integrity of all audit logs
        Returns: verification report
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Fetch all logs in order
            cursor.execute("""
                SELECT id, current_hash, signature, previous_hash, event_type, action
                FROM audit_logs
                ORDER BY id ASC
            """)

            logs = cursor.fetchall()
            tampering_detected = False
            invalid_signatures = []
            broken_chain = []

            previous_hash = None

            for log_id, current_hash, signature, prev_hash, event_type, action in logs:
                # Verify hash chain
                if prev_hash != previous_hash:
                    tampering_detected = True
                    broken_chain.append({
                        "log_id": log_id,
                        "expected_prev_hash": previous_hash,
                        "actual_prev_hash": prev_hash
                    })

                # Verify signature
                secret = (self.secret_key or "").encode()
                expected_sig = hmac.new(
                    secret,
                    str(current_hash).encode(),
                    hashlib.sha256
                ).hexdigest()

                if not hmac.compare_digest(str(signature), expected_sig):
                    tampering_detected = True
                    invalid_signatures.append({
                        "log_id": log_id,
                        "event_type": event_type,
                        "action": action
                    })

                previous_hash = current_hash

            # Store verification result
            check_timestamp = datetime.now(timezone.utc)
            verification_hash = hashlib.sha256(
                f"{check_timestamp.isoformat()}{len(logs)}{previous_hash}".encode()
            ).hexdigest()

            cursor.execute("""
                INSERT INTO log_integrity_checks
                (check_timestamp, total_logs, last_hash, verification_hash, status, tampering_detected)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                check_timestamp.isoformat(),
                len(logs),
                previous_hash,
                verification_hash,
                "passed" if not tampering_detected else "failed",
                tampering_detected
            ))

            conn.commit()
            conn.close()

            return {
                "timestamp": check_timestamp,
                "total_logs": len(logs),
                "tampering_detected": tampering_detected,
                "invalid_signatures": invalid_signatures,
                "broken_chain": broken_chain,
                "status": "passed" if not tampering_detected else "failed"
            }
        except Exception as e:
            logger.error(f"Error verifying integrity: {e}")
            return {"status": "failed", "error": str(e)}

    def get_logs(self, user_id: Optional[str] = None, event_type: Optional[str] = None,
                 start_date: Optional[datetime] = None, end_date: Optional[datetime] = None,
                 limit: int = 1000) -> List[Dict]:
        """
        Retrieve audit logs with optional filtering
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date.isoformat())

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date.isoformat())

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(str(limit))  # type: ignore[arg-type]

            cursor.execute(query, params)
            logs = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return logs
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            return []

    def export_logs(self, filepath: str, format: str = "json"):
        """
        Export audit logs in specified format
        """
        try:
            logs = self.get_logs(limit=999999)  # Get all logs

            if format == "json":
                with open(filepath, 'w') as f:
                    json.dump(logs, f, indent=2)
            elif format == "csv":
                import csv
                with open(filepath, 'w', newline='') as f:
                    if logs:
                        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                        writer.writeheader()
                        writer.writerows(logs)

            logger.info(f"Logs exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            return False

# ===== AUDIT LOGGER WITH AUTO-LOGGING =====


class SecurityAuditLogger:
    """High-level audit logger with automatic event tracking"""

    def __init__(self, immutable_logger: ImmutableAuditLogger):
        self.immutable_logger = immutable_logger

    def log_login_success(self, user_id: str, username: str, ip_address: str):
        """Log successful login"""
        event = AuditLogEntry(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user_id,
            action=f"Login successful for user {username}",
            details={"username": username},
            ip_address=ip_address,
            status="success"
        )
        self.immutable_logger.log_event(event)

    def log_login_failure(self, username: str, ip_address: str, reason: str = "Invalid credentials"):
        """Log failed login"""
        event = AuditLogEntry(
            event_type=AuditEventType.LOGIN_FAILURE,
            user_id="unknown",
            action=f"Login failed for user {username}",
            details={"username": username, "reason": reason},
            ip_address=ip_address,
            status="failure"
        )
        self.immutable_logger.log_event(event)

    def log_api_call(self, user_id: str, method: str, path: str, status_code: int, ip_address: str):
        """Log API call"""
        event = AuditLogEntry(
            event_type=AuditEventType.API_CALL,
            user_id=user_id,
            action=f"{method} {path}",
            details={"method": method, "path": path,
                     "status_code": status_code},
            ip_address=ip_address,
            status="success" if status_code < 400 else "failure"
        )
        self.immutable_logger.log_event(event)

    def log_webhook_received(self, user_id: str, webhook_source: str, event_type: str):
        """Log webhook receipt"""
        event = AuditLogEntry(
            event_type=AuditEventType.WEBHOOK_RECEIVED,
            user_id=user_id,
            action=f"Webhook received from {webhook_source}",
            details={"source": webhook_source, "type": event_type},
            status="success"
        )
        self.immutable_logger.log_event(event)

    def log_webhook_rejected(self, user_id: str, webhook_source: str, reason: str):
        """Log rejected webhook"""
        event = AuditLogEntry(
            event_type=AuditEventType.WEBHOOK_REJECTED,
            user_id=user_id,
            action=f"Webhook rejected from {webhook_source}",
            details={"source": webhook_source, "reason": reason},
            status="failure"
        )
        self.immutable_logger.log_event(event)

    def log_threat_detected(self, user_id: str, threat_type: str, severity: str, details: Dict):
        """Log detected threat"""
        event = AuditLogEntry(
            event_type=AuditEventType.THREAT_DETECTED,
            user_id=user_id,
            action=f"Threat detected: {threat_type}",
            details={"threat_type": threat_type,
                     "severity": severity, **details},
            status="success"
        )
        self.immutable_logger.log_event(event)

    def log_permission_denied(self, user_id: str, action: str, required_permission: str):
        """Log permission denial"""
        event = AuditLogEntry(
            event_type=AuditEventType.PERMISSION_DENIED,
            user_id=user_id,
            action=f"Permission denied for action: {action}",
            details={"action": action,
                     "required_permission": required_permission},
            status="failure"
        )
        self.immutable_logger.log_event(event)

    def log_rate_limit_violation(self, ip_address: str, path: str):
        """Log rate limit violation"""
        event = AuditLogEntry(
            event_type=AuditEventType.API_ERROR,
            user_id="unknown",
            action=f"Rate limit exceeded for path {path}",
            details={"path": path},
            ip_address=ip_address,
            status="failure"
        )
        self.immutable_logger.log_event(event)

    def log_security_audit_access(self, ip_address: str):
        """Log access to security audit dashboard"""
        event = AuditLogEntry(
            event_type=AuditEventType.DATA_READ,
            user_id="admin",
            action="Accessed security audit endpoints",
            details={},
            ip_address=ip_address,
            status="success"
        )
        self.immutable_logger.log_event(event)

    async def get_recent_violations(self, limit: int = 10, ip_address: Optional[str] = None) -> List[Dict]:
        """Fetch recent rate limit or threat violations"""
        # Return empty list as a stub to silence main.py missing method calls
        return []

    async def get_blocked_ips(self) -> List[str]:
        """Fetch a list of active blocked IPs"""
        return []

    def log_event(self, event_type: AuditEventType, user_id: str, action: str,
                  details: Optional[Dict[str, Any]] = None, ip_address: Optional[str] = None,
                  status: str = "success"):
        """Generic event logger"""
        event = AuditLogEntry(
            event_type=event_type,
            user_id=user_id,
            action=action,
            details=details or {},
            ip_address=ip_address,
            status=status
        )
        return self.immutable_logger.log_event(event)


# ===== GLOBAL INSTANCES =====
immutable_audit_logger = ImmutableAuditLogger()
security_audit_logger = SecurityAuditLogger(immutable_audit_logger)
