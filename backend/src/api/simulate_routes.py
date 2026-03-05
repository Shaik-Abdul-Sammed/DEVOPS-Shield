from fastapi import APIRouter, Depends, HTTPException, Query, Request
from datetime import datetime, timezone
import random
from typing import Optional

from ..security.auth_manager import get_current_user
from ..security.audit_logger import security_audit_logger, AuditEventType

# Router prefix is handled in main.py, so we keep this empty
router = APIRouter() 

import os
import json
from .pipelines_controller import add_simulation_run

# Define the data path
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'data', 'intelligence')
ATTACK_PATTERNS_FILE = os.path.join(DATA_DIR, 'attack_patterns.json')

def load_attack_patterns():
    scenarios = {
        "supply-chain": {
            "message": "Critical supply chain compromise detected: Unknown package version injected into private registry.",
            "risk_base": 0.85,
            "factors": {
                "threat": 0.9,
                "exposure": 0.8,
                "exploitability": 0.95,
                "asset_value": 0.8
            },
            "flags": ["untrusted_package", "sbom_mismatch", "runner_token_exposed"],
            "author": "external_adversary_0x",
            "changes": ["package.json", "scripts/preinstall.sh"],
            "impact": "Potential for complete environment compromise and lateral movement.",
            "remediation": [
                "SHA-256 pinning",
                "Artifact Signing",
                "MFA Enforced Access"
            ],
            "automated_response": "Runner token revoked; Build quarantine initiated.",
            "detections": ["Hash Mismatch", "Unauthorized Registry Access"]
        },
        "secret-leak": {
            "message": "Security Alert: Highly sensitive PAT string detected in build logs.",
            "risk_base": 0.78,
            "factors": {
                "threat": 0.7,
                "exposure": 0.9,
                "exploitability": 0.6,
                "asset_value": 0.7
            },
            "flags": ["entropy_threshold_exceeded", "regex_secret_match"],
            "author": "contractor_dev_88",
            "changes": ["tests/output.log", "config/settings.yaml"],
            "impact": "Impersonation of critical service accounts and unauthorized data access.",
            "remediation": [
                "Credential Rotation",
                "OIDC Integration",
                "Log Sanitization Rules"
            ],
            "automated_response": "Credential revoked, log scrub pipeline engaged, Jira incident created.",
            "detections": ["Source Integrity", "Log Sanitization"]
        },
        "rogue-runner": {
            "message": "Behavioral Anomaly: Runner executing unrecognized command patterns.",
            "risk_base": 0.92,
            "factors": {
                "threat": 0.95,
                "exposure": 0.7,
                "exploitability": 0.85,
                "asset_value": 0.9
            },
            "flags": ["behavioral_deviation", "kernel_fingerprint_mismatch", "unrecognized_binary"],
            "author": "system-runner-334",
            "changes": ["/dev/shm/payload", "/etc/hosts"],
            "impact": "System-level privilege escalation and potential backdooring of build images.",
            "remediation": [
                "Hardware Identity (TPM)",
                "Egress Filtering",
                "Golden Image Re-sync"
            ],
            "automated_response": "Runner isolated; PKCE re-challenge enforced.",
            "detections": ["Behavioral Monitor", "Kernel Fingerprinting"]
        }
    }
    
    # Load from external JSON if exists
    if os.path.exists(ATTACK_PATTERNS_FILE):
        try:
            with open(ATTACK_PATTERNS_FILE, 'r') as f:
                external_patterns = json.load(f)
                for pattern in external_patterns:
                    # Map the JSON structure to what the backend expects
                    scenarios[pattern['id']] = pattern
        except Exception as e:
            print(f"Error loading attack patterns: {e}")
            
    return scenarios

SCENARIOS = load_attack_patterns()

@router.get("/")
@router.get("")
async def simulate_fraud_event(
    scenario_id: Optional[str] = Query(None, alias="scenario"),
    current_user: dict = Depends(get_current_user)
):
    """
    Generates realistic fraud data based on attack scenarios.
    """
    
    # 1. Select Scenario
    scenario = SCENARIOS.get(scenario_id)
    if not scenario and scenario_id:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    
    # Defaults for random/unknown scenarios
    selected = scenario or {
        "message": "Simulated suspicious activity detected",
        "risk_base": 0.65,
        "flags": ["generic_suspicion"],
        "author": "unknown",
        "changes": ["modified_file.txt"]
    }
    
    # 2. Randomize details
    event_id = random.randint(5000, 9999)
    commit_suffix = random.randint(10000, 99999)
    
    # Variance in risk score (+/- 5%)
    risk_val = round(selected["risk_base"] + random.uniform(-0.05, 0.05), 2)
    risk_val = max(0.01, min(1.0, risk_val))
    
    # 3. Build the Event Object
    event = {
        "event_id": event_id,
        "scenario_id": scenario_id or "generic",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": risk_val,
        "message": selected["message"],
        "activity": {
            "commit_id": f"sim-{commit_suffix}",
            "author": selected["author"],
            "changes_detected": selected["changes"],
            "flags": selected["flags"]
        }
    }

    # 4. Log to Security Audit Logger (Real auditing)
    security_audit_logger.log_threat_detected(
        user_id=current_user["user_id"],
        threat_type=f"SIMULATED_{scenario_id.upper() if scenario_id else 'GENERIC'}",
        severity="High" if risk_val > 0.8 else "Medium",
        details={
            "simulation": True,
            "event_id": event_id,
            "risk_score": risk_val,
            "flags": selected["flags"]
        }
    )

    # 5. Link to Pipelines (New integration)
    pipeline_map = {
        "supply-chain": "edge-security",
        "secret-leak": "frontend-ci",
        "rogue-runner": "payments-cd"
    }
    target_pipeline = pipeline_map.get(scenario_id, "backend")
    add_simulation_run(target_pipeline, scenario_id or "generic", risk_val)

    return {
        "status": "success",
        "fraud_event": event
    }