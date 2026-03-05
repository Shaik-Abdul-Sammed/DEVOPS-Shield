from fastapi import APIRouter, Query  # type: ignore
from datetime import datetime, timezone, timedelta
import random
import json
from ..utils.logger import get_logger  # type: ignore

router = APIRouter()
logger = get_logger(__name__)

# Pipeline statuses
STATUSES = ["success", "running", "failed", "pending"]

# Store simulation-triggered runs
EXTRA_RUNS = []
BRANCHES = ["main", "develop", "feat/security", "feat/ui-improvements", "hotfix/critical-bug"]
STAGES = [
    {"name": "Checkout", "icon": "📥", "duration_min": 5, "duration_max": 15},
    {"name": "Install Dependencies", "icon": "📦", "duration_min": 30, "duration_max": 120},
    {"name": "Lint & Format", "icon": "✨", "duration_min": 10, "duration_max": 30},
    {"name": "Run Tests", "icon": "🧪", "duration_min": 20, "duration_max": 90},
    {"name": "Security Scan", "icon": "🔒", "duration_min": 15, "duration_max": 60},
    {"name": "Build Artifacts", "icon": "🏗️", "duration_min": 30, "duration_max": 120},
    {"name": "Deploy to Staging", "icon": "🚀", "duration_min": 45, "duration_max": 180},
    {"name": "Integration Tests", "icon": "🔗", "duration_min": 60, "duration_max": 300}
]

PROJECTS = [
    {"id": "backend", "name": "DEVOPS-Shield Backend CI/CD", "owner": "Abdul9010150809"},
    {"id": "frontend", "name": "Frontend React Build", "owner": "devops-team"},
    {"id": "infra", "name": "Infrastructure Deployment", "owner": "devops-ops"},
    {"id": "security", "name": "Security Hardening Pipeline", "owner": "security-team"},
    {"id": "ml", "name": "ML Model Training Pipeline", "owner": "data-science"},
    {"id": "blockchain", "name": "Blockchain Integration Tests", "owner": "blockchain-team"},
    {"id": "database", "name": "Database Migration Pipeline", "owner": "dba-team"},
    {"id": "docs", "name": "Documentation Build", "owner": "tech-writers"}
]

COMMITS = [
    "Add fraud detection module",
    "Improve blockchain integration",
    "Fix security vulnerability CVE-2025-1234",
    "Refactor authentication system",
    "Add rate limiting middleware",
    "Update dependencies",
    "Implement real-time alerts",
    "Optimize database queries",
    "Add Docker support",
    "Implement webhook handlers",
    "Add multi-factor authentication",
    "Improve error handling",
    "Add comprehensive logging",
    "Implement caching layer",
    "Add API documentation",
    "Secure credential storage",
    "Add health check endpoints",
    "Implement circuit breaker pattern",
    "Add monitoring dashboards",
    "Optimize API response times"
]

def generate_stage(stage_template, is_running=False):
    """Generate a realistic stage with duration and status"""
    duration = random.randint(stage_template["duration_min"], stage_template["duration_max"])
    
    if is_running:
        status = "running"
        elapsed = random.randint(0, duration)
        duration_str = f"{elapsed}s / {duration}s"
    else:
        status = random.choices(["success", "pending"], weights=[0.85, 0.15])[0]
        if status == "success":
            duration_str = f"{duration}s"
        else:
            duration_str = "-"
    
    result = {
        "name": stage_template["name"],
        "status": status,
        "duration": duration_str,
        "icon": stage_template["icon"]
    }
    
    # Add test results for test stage
    if "test" in stage_template["name"].lower():
        result["tests"] = f"{random.randint(40, 100)}/{random.randint(100, 150)} passed"
    
    return result

def generate_pipeline():
    """Generate a realistic pipeline with all stages"""
    now = datetime.now(timezone.utc)
    project = random.choice(PROJECTS)
    branch = random.choice(BRANCHES)
    status = random.choices(STATUSES, weights=[0.4, 0.3, 0.15, 0.15])[0]
    
    # Calculate timing based on status
    if status == "running":
        start_time = now - timedelta(seconds=random.randint(30, 600))
        elapsed = (now - start_time).total_seconds()
        progress = min(int((elapsed / 600) * 100), 99)  # Max 600s, capped at 99%
    elif status == "success":
        duration_sec = random.randint(180, 1800)
        start_time = now - timedelta(seconds=duration_sec + random.randint(10, 3600))
        progress = 100
    elif status == "failed":
        start_time = now - timedelta(seconds=random.randint(60, 1200))
        progress = random.randint(20, 80)
    else:  # pending
        start_time = now
        progress = 0
    
    # Generate stages
    stages = []
    for i, stage_template in enumerate(STAGES):
        # Determine which stage we're on
        if status == "running":
            is_this_running = i == min(random.randint(0, 3), len(STAGES) - 1)
        else:
            is_this_running = False
        
        stages.append(generate_stage(stage_template, is_this_running))
    
    return {
        "id": random.randint(10000, 99999),
        "name": project["name"],
        "status": status,
        "branch": branch,
        "commit": f"{random.randint(100000, 999999):x}".lower()[:7],  # type: ignore
        "commitMessage": random.choice(COMMITS),
        "author": project["owner"],
        "startTime": start_time.timestamp() * 1000,
        "duration": f"{random.randint(2, 30)}m {random.randint(0, 59)}s",
        "progress": progress,
        "stages": stages
    }

def add_simulation_run(project_id: str, scenario_name: str, risk_score: float):
    """Add a simulation-triggered run to the pipelines list"""
    now = datetime.now(timezone.utc)
    project = next((p for p in PROJECTS if p["id"] == project_id), PROJECTS[0])
    
    run = {
        "id": random.randint(10000, 99999),
        "name": project["name"],
        "status": "failed" if risk_score > 0.5 else "success",
        "branch": "main",
        "commit": f"{random.randint(100000, 999999):x}".lower()[:7],
        "commitMessage": f"Simulated: {scenario_name}",
        "author": project["owner"],
        "startTime": now.timestamp() * 1000,
        "duration": f"{random.randint(1, 5)}m {random.randint(0, 59)}s",
        "progress": 100,
        "risk_score": risk_score,
        "stages": STAGES[:random.randint(3, 8)]  # Just some stages
    }
    EXTRA_RUNS.insert(0, run)
    return run

@router.get("/")
async def get_pipelines(limit: int = Query(10, ge=1, le=100)):
    """
    Get a list of realistic CI/CD pipelines with large dataset
    Route: GET /api/pipelines/
    """
    try:
        pipelines = [generate_pipeline() for _ in range(limit)]
        
        # Merge with extra runs if any
        if EXTRA_RUNS:
            pipelines = (EXTRA_RUNS + pipelines)[:limit]
        
        # Calculate metrics
        successful = sum(1 for p in pipelines if p["status"] == "success")
        failed = sum(1 for p in pipelines if p["status"] == "failed")
        running = sum(1 for p in pipelines if p["status"] == "running")
        
        return {
            "status": "success",
            "data": {
                "pipelines": pipelines,
                "metrics": {
                    "total": len(pipelines),
                    "successful": successful,
                    "failed": failed,
                    "running": running,
                    "success_rate": round((successful / len(pipelines) * 100), 2) if pipelines else 0,  # type: ignore
                    "avg_duration_minutes": round(random.uniform(2, 30), 2)  # type: ignore
                }
            }
        }
    except Exception as e:
        logger.error(f"Error generating pipelines: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@router.get("/history")
async def get_pipeline_history(days: int = Query(7, ge=1, le=30)):
    """
    Get historical pipeline data for the last N days
    Route: GET /api/pipelines/history?days=7
    """
    try:
        history = []
        now = datetime.now(timezone.utc)
        
        for day in range(days):
            date = now - timedelta(days=day)
            # Generate 5-15 pipelines per day
            num_pipelines = random.randint(5, 15)
            
            for _ in range(num_pipelines):
                pipeline = generate_pipeline()
                pipeline["startTime"] = (date - timedelta(hours=random.randint(0, 23))).timestamp() * 1000
                history.append(pipeline)
        
        # Add extra runs to history too
        if EXTRA_RUNS:
            history = EXTRA_RUNS + history

        return {
            "status": "success",
            "data": {
                "pipelines": history,
                "period_days": days,
                "total_runs": len(history),
                "success_rate": round((sum(1 for p in history if p["status"] == "success") / len(history) * 100), 2) if history else 0  # type: ignore
            }
        }
    except Exception as e:
        logger.error(f"Error generating pipeline history: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@router.get("/{pipeline_id}")
async def get_pipeline_details(pipeline_id: int):
    """
    Get detailed information about a specific pipeline
    Route: GET /api/pipelines/{pipeline_id}
    """
    try:
        pipeline = generate_pipeline()
        pipeline["id"] = pipeline_id
        
        # Add additional details
        pipeline["details"] = {
            "webhook_payload": {
                "push_events": True,
                "merge_requests": True,
                "issues": True,
                "confidential_issues": False,
                "wiki_page_events": False
            },
            "variables": [
                {"key": "REGISTRY_USER", "value": "***", "protected": True},
                {"key": "DEPLOYMENT_ENV", "value": "staging", "protected": False},
                {"key": "LOG_LEVEL", "value": "debug", "protected": False}
            ],
            "artifacts": {
                "paths": ["build/", "dist/", "reports/"],
                "expire_in": "30 days"
            }
        }
        
        return {
            "status": "success",
            "data": pipeline
        }
    except Exception as e:
        logger.error(f"Error getting pipeline details: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@router.post("/{pipeline_id}/runs/{run_id}/quarantine")
async def quarantine_run(pipeline_id: str, run_id: str):
    """
    Quarantine a specific pipeline run
    Route: POST /api/pipelines/{pipeline_id}/runs/{run_id}/quarantine
    """
    logger.info(f"Quarantining run {run_id} in pipeline {pipeline_id}")
    return {
        "status": "success",
        "message": f"Run {run_id} has been quarantined",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.post("/{pipeline_id}/runs/{run_id}/rollback")
async def rollback_run(pipeline_id: str, run_id: str):
    """
    Trigger rollback for a specific pipeline run
    Route: POST /api/pipelines/{pipeline_id}/runs/{run_id}/rollback
    """
    logger.info(f"Triggering rollback for run {run_id} in pipeline {pipeline_id}")
    return {
        "status": "success",
        "message": f"Rollback initiated for run {run_id}",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
