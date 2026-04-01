"""
Incident Response & Security Monitoring
Real-time threat detection, anomaly detection, alerting, and incident response automation
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from enum import Enum
from collections import defaultdict
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ===== SEVERITY LEVELS =====
class SeverityLevel(str, Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# ===== INCIDENT TYPES =====
class IncidentType(str, Enum):
    """Types of security incidents"""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_BREACH = "data_breach"
    MALWARE_DETECTED = "malware_detected"
    DDoS_ATTACK = "ddos_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONFIGURATION_CHANGE = "configuration_change"
    SUSPICIOUS_LOGIN = "suspicious_login"
    API_ABUSE = "api_abuse"
    MODEL_POISONING = "model_poisoning"
    WEBHOOK_SPOOFING = "webhook_spoofing"
    THREAT_DETECTED = "threat_detected"

# ===== INCIDENT RECORD =====
class Incident:
    """Security incident record"""
    
    def __init__(self, incident_type: IncidentType, severity: SeverityLevel, 
                 title: str, description: str, affected_user: str = None,
                 affected_resource: str = None):
        self.id = self._generate_incident_id()
        self.incident_type = incident_type
        self.severity = severity
        self.title = title
        self.description = description
        self.affected_user = affected_user
        self.affected_resource = affected_resource
        self.created_at = datetime.now(timezone.utc)
        self.status = "open"  # open, in_progress, resolved, closed
        self.assigned_to = None
        self.resolution = None
        self.timeline = [{
            "timestamp": self.created_at.isoformat(),
            "action": "Incident created",
            "by": "system"
        }]
        self.evidence = []
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        import random
        random_suffix = random.randint(1000, 9999)
        return f"INC-{timestamp}-{random_suffix}"
    
    def add_evidence(self, evidence_type: str, data: Any):
        """Add evidence to incident"""
        self.evidence.append({
            "type": evidence_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    def add_timeline_entry(self, action: str, by: str = "system"):
        """Add entry to incident timeline"""
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "by": by
        })
    
    def resolve(self, resolution: str, resolved_by: str = "system"):
        """Mark incident as resolved"""
        self.status = "resolved"
        self.resolution = resolution
        self.add_timeline_entry(f"Resolved: {resolution}", resolved_by)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "type": self.incident_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_user": self.affected_user,
            "affected_resource": self.affected_resource,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "assigned_to": self.assigned_to,
            "resolution": self.resolution,
            "timeline": self.timeline,
            "evidence": self.evidence
        }

# ===== ANOMALY DETECTION =====
class AnomalyDetector:
    """Detect anomalous behavior and patterns"""
    
    def __init__(self):
        self.baseline_metrics = {}  # Store baseline metrics
        self.detection_window = timedelta(hours=1)
        self.anomaly_threshold = 0.7  # 70% deviation = anomaly
    
    def establish_baseline(self, metric_name: str, values: List[float]):
        """Establish baseline for metric"""
        if not values:
            return
        
        import statistics
        self.baseline_metrics[metric_name] = {
            "mean": statistics.mean(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0,
            "min": min(values),
            "max": max(values),
            "established_at": datetime.now(timezone.utc).isoformat()
        }
    
    def detect_anomaly(self, metric_name: str, current_value: float) -> tuple[bool, float]:
        """
        Detect anomaly in metric
        Returns: (is_anomaly, anomaly_score)
        """
        if metric_name not in self.baseline_metrics:
            return False, 0.0
        
        baseline = self.baseline_metrics[metric_name]
        mean = baseline["mean"]
        stdev = baseline["stdev"]
        
        if stdev == 0:
            return False, 0.0
        
        # Calculate Z-score
        z_score = abs((current_value - mean) / stdev)
        
        # Anomaly if Z-score > 2.5 (roughly 99.4% confidence)
        is_anomaly = z_score > 2.5
        anomaly_score = min(1.0, z_score / 5.0)  # Normalize to 0-1
        
        return is_anomaly, anomaly_score
    
    def detect_unusual_login(self, user_id: str, ip_address: str, login_history: List[Dict]) -> tuple[bool, Dict]:
        """
        Detect unusual login patterns
        """
        anomalies = []
        score = 0.0
        
        # Check if new IP address
        previous_ips = set(login["ip_address"] for login in login_history[-20:])  # Last 20 logins
        if ip_address not in previous_ips:
            anomalies.append("New IP address")
            score += 0.3
        
        # Check if unusual login time
        if login_history:
            recent_hours = set(datetime.fromisoformat(login["timestamp"]).hour for login in login_history[-10:])
            current_hour = datetime.now(timezone.utc).hour
            if current_hour not in recent_hours:
                anomalies.append(f"Unusual login time: {current_hour}:00")
                score += 0.2
        
        # Check for rapid login attempts from different IPs
        recent_logins = [l for l in login_history if 
                        (datetime.now(timezone.utc) - datetime.fromisoformat(l["timestamp"])) < timedelta(minutes=30)]
        if len(recent_logins) > 5:
            anomalies.append(f"Rapid login attempts: {len(recent_logins)} in 30 minutes")
            score += 0.3
        
        return score > 0.5, {
            "anomalies": anomalies,
            "risk_score": min(1.0, score),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# ===== SECURITY MONITORING =====
class SecurityMonitor:
    """Monitor system security and generate alerts"""
    
    def __init__(self):
        self.incidents = {}  # incident_id -> Incident
        self.alerts = []  # Alert queue
        self.anomaly_detector = AnomalyDetector()
        self.metrics = defaultdict(list)  # Track metrics over time
        self.alert_handlers = []
    
    def register_alert_handler(self, handler):
        """Register handler for alerts"""
        self.alert_handlers.append(handler)
    
    def create_incident(self, incident_type: IncidentType, severity: SeverityLevel,
                       title: str, description: str, affected_user: str = None,
                       affected_resource: str = None) -> Incident:
        """
        Create security incident
        """
        incident = Incident(
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            affected_user=affected_user,
            affected_resource=affected_resource
        )
        
        self.incidents[incident.id] = incident
        
        # Generate alert
        self._generate_alert(
            severity=severity,
            title=title,
            incident_id=incident.id,
            details=description
        )
        
        logger.warning(f"Security incident created: {incident.id} - {title}")
        return incident
    
    def _generate_alert(self, severity: SeverityLevel, title: str, incident_id: str = None, details: str = None):
        """Generate and dispatch alert"""
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity.value,
            "title": title,
            "incident_id": incident_id,
            "details": details
        }
        
        self.alerts.append(alert)
        
        # Dispatch to handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error dispatching alert: {e}")
    
    def monitor_api_calls(self, user_id: str, endpoint: str, method: str, status_code: int):
        """Monitor API call patterns"""
        metric_name = f"api_calls_{user_id}"
        
        # Track metric
        self.metrics[metric_name].append({
            "timestamp": datetime.now(timezone.utc),
            "endpoint": endpoint,
            "method": method,
            "status": status_code
        })
        
        # Detect anomalies
        recent_calls = [m for m in self.metrics[metric_name] 
                       if (datetime.now(timezone.utc) - m["timestamp"]) < timedelta(minutes=5)]
        
        if len(recent_calls) > 100:  # More than 100 calls in 5 minutes
            self.create_incident(
                incident_type=IncidentType.API_ABUSE,
                severity=SeverityLevel.HIGH,
                title="High API call rate detected",
                description=f"User {user_id} made {len(recent_calls)} API calls in 5 minutes",
                affected_user=user_id
            )
    
    def monitor_login_attempts(self, user_id: str, ip_address: str, success: bool, login_history: List[Dict]):
        """Monitor login patterns"""
        if not success:
            # Track failed attempt
            metric_name = f"failed_logins_{user_id}"
            self.metrics[metric_name].append({
                "timestamp": datetime.now(timezone.utc),
                "ip_address": ip_address
            })
            
            recent_failures = [m for m in self.metrics[metric_name]
                             if (datetime.now(timezone.utc) - m["timestamp"]) < timedelta(minutes=15)]
            
            if len(recent_failures) >= 5:
                self.create_incident(
                    incident_type=IncidentType.SUSPICIOUS_LOGIN,
                    severity=SeverityLevel.HIGH,
                    title="Multiple failed login attempts",
                    description=f"User {user_id} had {len(recent_failures)} failed attempts in 15 minutes",
                    affected_user=user_id
                )
        else:
            # Check for unusual login patterns
            is_unusual, details = self.anomaly_detector.detect_unusual_login(user_id, ip_address, login_history)
            if is_unusual:
                self.create_incident(
                    incident_type=IncidentType.SUSPICIOUS_LOGIN,
                    severity=SeverityLevel.MEDIUM,
                    title="Unusual login detected",
                    description=f"Unusual login pattern detected: {json.dumps(details['anomalies'])}",
                    affected_user=user_id
                )
    
    def monitor_webhook(self, webhook_source: str, event_type: str, status: str, reason: str = None):
        """Monitor webhook activity"""
        metric_name = f"webhook_failures_{webhook_source}"
        
        if status == "rejected":
            self.metrics[metric_name].append({
                "timestamp": datetime.now(timezone.utc),
                "reason": reason
            })
            
            recent_failures = [m for m in self.metrics[metric_name]
                             if (datetime.now(timezone.utc) - m["timestamp"]) < timedelta(minutes=10)]
            
            if len(recent_failures) >= 3:
                self.create_incident(
                    incident_type=IncidentType.WEBHOOK_SPOOFING,
                    severity=SeverityLevel.HIGH,
                    title="Multiple webhook rejections",
                    description=f"Webhook source {webhook_source} had {len(recent_failures)} rejected webhooks in 10 minutes",
                    affected_resource=webhook_source
                )
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        return self.incidents.get(incident_id)
    
    def get_incidents(self, status: str = None, severity: str = None, limit: int = 100) -> List[Dict]:
        """Get incidents with optional filtering"""
        incidents = list(self.incidents.values())
        
        if status:
            incidents = [i for i in incidents if i.status == status]
        
        if severity:
            incidents = [i for i in incidents if i.severity.value == severity]
        
        # Sort by creation time (newest first)
        incidents.sort(key=lambda x: x.created_at, reverse=True)
        
        return [i.to_dict() for i in incidents[:limit]]
    
    def get_recent_alerts(self, limit: int = 100, severity: str = None) -> List[Dict]:
        """Get recent alerts"""
        alerts = list(reversed(self.alerts))  # Newest first
        
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        
        return alerts[:limit]

# ===== INCIDENT RESPONSE PLAYBOOK =====
class IncidentResponsePlaybook:
    """Automated incident response procedures"""
    
    @staticmethod
    def respond_to_unauthorized_access(monitor: SecurityMonitor, incident: Incident) -> Dict[str, Any]:
        """
        Incident response playbook for unauthorized access
        Steps: Isolate, Revoke, Investigate, Restore
        """
        response_steps = []
        
        # Step 1: Revoke credentials
        if incident.affected_user:
            response_steps.append({
                "action": "revoke_sessions",
                "target": incident.affected_user,
                "status": "pending"
            })
            response_steps.append({
                "action": "reset_password",
                "target": incident.affected_user,
                "status": "pending"
            })
        
        # Step 2: Isolate affected resources
        if incident.affected_resource:
            response_steps.append({
                "action": "isolate_resource",
                "target": incident.affected_resource,
                "status": "pending"
            })
        
        # Step 3: Investigate
        response_steps.append({
            "action": "review_audit_logs",
            "target": incident.affected_user,
            "status": "pending"
        })
        
        # Step 4: Notify
        response_steps.append({
            "action": "notify_security_team",
            "status": "pending"
        })
        
        incident.add_timeline_entry("Automated response initiated")
        
        return {
            "incident_id": incident.id,
            "response_steps": response_steps,
            "initiated_at": datetime.now(timezone.utc).isoformat()
        }
    
    @staticmethod
    def respond_to_api_abuse(monitor: SecurityMonitor, incident: Incident) -> Dict[str, Any]:
        """
        Incident response playbook for API abuse
        """
        response_steps = []
        
        # Step 1: Rate limit user
        response_steps.append({
            "action": "apply_strict_rate_limit",
            "target": incident.affected_user,
            "status": "pending"
        })
        
        # Step 2: Block user temporarily
        response_steps.append({
            "action": "temporary_block",
            "target": incident.affected_user,
            "duration_minutes": 30,
            "status": "pending"
        })
        
        # Step 3: Review API key
        response_steps.append({
            "action": "rotate_api_key",
            "target": incident.affected_user,
            "status": "pending"
        })
        
        incident.add_timeline_entry("API abuse response initiated")
        
        return {
            "incident_id": incident.id,
            "response_steps": response_steps,
            "initiated_at": datetime.now(timezone.utc).isoformat()
        }
    
    @staticmethod
    def respond_to_webhook_spoofing(monitor: SecurityMonitor, incident: Incident) -> Dict[str, Any]:
        """
        Incident response playbook for webhook spoofing
        """
        response_steps = []
        
        # Step 1: Disable webhook temporarily
        response_steps.append({
            "action": "disable_webhook",
            "target": incident.affected_resource,
            "status": "pending"
        })
        
        # Step 2: Review recent webhook history
        response_steps.append({
            "action": "analyze_webhook_history",
            "target": incident.affected_resource,
            "status": "pending"
        })
        
        # Step 3: Verify webhook configuration
        response_steps.append({
            "action": "verify_webhook_config",
            "target": incident.affected_resource,
            "status": "pending"
        })
        
        incident.add_timeline_entry("Webhook spoofing response initiated")
        
        return {
            "incident_id": incident.id,
            "response_steps": response_steps,
            "initiated_at": datetime.now(timezone.utc).isoformat()
        }

# ===== GLOBAL INSTANCES =====
security_monitor = SecurityMonitor()
incident_response = IncidentResponsePlaybook()

