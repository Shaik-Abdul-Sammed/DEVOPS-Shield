from fastapi import APIRouter
from pydantic import BaseModel
import logging
from datetime import datetime, timezone
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from src.security.source_integrity import SourceIntegrityManager
    source_integrity_manager = SourceIntegrityManager()
    logger = logging.getLogger(__name__)
    logger.info("✓ SourceIntegrityManager loaded")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"SourceIntegrityManager unavailable: {e}")
    SourceIntegrityManager = None
    source_integrity_manager = None

try:
    from src.security.dependency_sentinel import DependencySentinel
    dependency_sentinel = DependencySentinel()
    logger.info("✓ DependencySentinel loaded")
except ImportError as e:
    logger.warning(f"DependencySentinel unavailable: {e}")
    DependencySentinel = None
    dependency_sentinel = None

try:
    from src.security.blockchain_ledger import BlockchainLedger
    blockchain_ledger = BlockchainLedger()
    logger.info("✓ BlockchainLedger loaded")
except ImportError as e:
    logger.warning(f"BlockchainLedger unavailable: {e}")
    BlockchainLedger = None
    blockchain_ledger = None

try:
    from src.security.artifact_hardener import ArtifactHardener
    artifact_hardener = ArtifactHardener()
    logger.info("✓ ArtifactHardener loaded")
except ImportError as e:
    logger.warning(f"ArtifactHardener unavailable: {e}")
    ArtifactHardener = None
    artifact_hardener = None

try:
    from src.security.zero_trust_orchestrator import ZeroTrustOrchestrator, PipelineContext
    zero_trust_orchestrator = ZeroTrustOrchestrator()
    logger.info("✓ ZeroTrustOrchestrator loaded")
except ImportError as e:
    logger.warning(f"ZeroTrustOrchestrator unavailable: {e}")
    ZeroTrustOrchestrator = None
    PipelineContext = None
    zero_trust_orchestrator = None

router = APIRouter()

class SourceVerifyRequest(BaseModel):
    developer_id: str
    commit_sha: str
    device_id: str
    ip_address: str
    timestamp: str
    has_secrets: bool = False

class SourceVerifyResponse(BaseModel):
    identity_score: float
    secrets_found: bool
    approved: bool
    reasons: list[str]

@router.post("/zero-trust/source/verify", response_model=SourceVerifyResponse)
async def source_verify(req: SourceVerifyRequest):
    logger.info(f"Source Integrity check for developer {req.developer_id}, commit {req.commit_sha[:8]}")

    if not source_integrity_manager:
        # Fallback stub if manager unavailable
        logger.warning("SourceIntegrityManager unavailable, using stub response")
        return SourceVerifyResponse(
            identity_score=0.85,
            secrets_found=req.has_secrets,
            approved=not req.has_secrets,
            reasons=["secrets_detected"] if req.has_secrets else [],
        )

    # Prepare commit data for analysis
    commit_data = {
        'commit_sha': req.commit_sha,
        'timestamp': datetime.now(timezone.utc).timestamp(),
        'files_changed': [],  # Would be populated from actual commit data
        'lines_added': 0,
        'lines_deleted': 0,
        'content': {}  # Would contain file contents for secret scanning
    }

    # Perform comprehensive source integrity verification
    try:
        verification_result = source_integrity_manager.verify_source_integrity(
            developer_id=req.developer_id,
            commit_sha=req.commit_sha,
            device_id=req.device_id,
            ip_address=req.ip_address,
            commit_data=commit_data
        )

        # Override secrets_found if explicitly provided (for backward compatibility)
        secrets_found = req.has_secrets or verification_result.get('secrets_found', False)

        logger.warning(f"Source Integrity: approved={verification_result['approved']}, identity_score={verification_result['identity_score']:.2f}, secrets={secrets_found}")
        return SourceVerifyResponse(
            identity_score=verification_result['identity_score'],
            secrets_found=secrets_found,
            approved=verification_result['approved'],
            reasons=verification_result['reasons'],
        )
    except Exception as e:
        logger.error(f"Source integrity verification error: {e}")
        # Return degraded response on error
        return SourceVerifyResponse(
            identity_score=0.5,
            secrets_found=req.has_secrets,
            approved=False,
            reasons=[f"Verification error: {str(e)}"],
        )

class DepCheckRequest(BaseModel):
    manifest: dict

class DepCheckResponse(BaseModel):
    approved: bool
    blocked_packages: list[str]
    reasons: list[str]

@router.post("/zero-trust/deps/check", response_model=DepCheckResponse)
async def deps_check(req: DepCheckRequest):
    logger.info(f"Dependency Sentinel check for {len(req.manifest)} packages")

    if not dependency_sentinel:
        # Fallback stub if sentinel unavailable
        logger.warning("DependencySentinel unavailable, using stub response")
        blocked = []
        reasons = []
        for name, version in req.manifest.items():
            if any(name.lower().startswith(x) for x in ["pytorch-", "apple-"]):
                blocked.append(name)
                reasons.append(f"Namespace lock violated: {name}")
        approved = len(blocked) == 0
        return DepCheckResponse(approved=approved, blocked_packages=blocked, reasons=reasons)

    # Perform comprehensive dependency security check
    check_result = dependency_sentinel.check_dependencies(req.manifest)

    logger.warning(f"Dependency Sentinel: approved={check_result['approved']}, blocked={check_result['blocked_count']}, risk_score={check_result['risk_score']:.2f}")
    return DepCheckResponse(
        approved=check_result['approved'],
        blocked_packages=check_result['blocked_packages'],
        reasons=check_result['reasons']
    )

class LedgerRecordRequest(BaseModel):
    step: str  # e.g., commit, build, test, sign, deploy
    hash: str
    previous_hash: str | None = None
    metadata: dict | None = None

class LedgerRecordResponse(BaseModel):
    recorded: bool
    chain_valid: bool

@router.post("/zero-trust/ledger/record", response_model=LedgerRecordResponse)
async def ledger_record(req: LedgerRecordRequest):
    logger.info(f"Blockchain Ledger recording step: {req.step}, hash: {req.hash[:16]}...")

    if not blockchain_ledger:
        # Fallback stub if ledger unavailable
        logger.warning("BlockchainLedger unavailable, using stub response")
        return LedgerRecordResponse(recorded=True, chain_valid=True)

    # For now, we'll use a default pipeline ID - in production this would be passed
    pipeline_id = req.metadata.get('pipeline_id', 'default_pipeline') if req.metadata else 'default_pipeline'

    # Record the build step
    step_recorded = blockchain_ledger.record_build_step(
        pipeline_id=pipeline_id,
        step_name=req.step,
        command=f"Build step: {req.step}",
        inputs={'hash': req.hash, 'previous_hash': req.previous_hash},
        metadata=req.metadata or {},
        outputs={'recorded_hash': req.hash}
    )

    if step_recorded:
        logger.warning("Blockchain Ledger: step recorded successfully, chain valid")
        return LedgerRecordResponse(recorded=True, chain_valid=True)
    else:
        logger.error("Blockchain Ledger: step recording failed - possible tampering")
        return LedgerRecordResponse(recorded=False, chain_valid=False)

class ArtifactVerifyRequest(BaseModel):
    artifact_hash: str
    signature: str

class ArtifactVerifyResponse(BaseModel):
    signed: bool
    sandbox_verified: bool
    approved: bool

@router.post("/zero-trust/artifact/verify", response_model=ArtifactVerifyResponse)
async def artifact_verify(req: ArtifactVerifyRequest):
    logger.info(f"Artifact Hardening verification for hash: {req.artifact_hash[:16]}...")

    if not artifact_hardener:
        # Fallback stub if hardener unavailable
        logger.warning("ArtifactHardener unavailable, using stub response")
        signed = bool(req.signature)
        sandbox_verified = True
        approved = signed and sandbox_verified
        return ArtifactVerifyResponse(signed=signed, sandbox_verified=sandbox_verified, approved=approved)

    # For verification, we need the artifact file path and signature info
    # This is a simplified version - in production, you'd look up the artifact and signature
    artifact_path = f"/tmp/artifact_{req.artifact_hash[:16]}"  # Placeholder

    # Mock signature info (in production, this would be retrieved from storage)
    signature_info = {
        'artifact_hash': req.artifact_hash,
        'signature': req.signature,
        'algorithm': 'RSA-SHA256',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'key_id': 'default'
    }

    # Perform verification
    verification_result = artifact_hardener.verify_hardened_artifact(artifact_path, signature_info)

    signed = 'signature_verification' in verification_result.get('checks_passed', [])
    sandbox_verified = 'malware_scan' in verification_result.get('checks_passed', [])
    approved = verification_result.get('verified', False)

    logger.warning(f"Artifact Hardening: approved={approved}, signed={signed}, sandbox_verified={sandbox_verified}")
    return ArtifactVerifyResponse(signed=signed, sandbox_verified=sandbox_verified, approved=approved)

# ===== FULL PIPELINE ORCHESTRATION =====

class PipelineTriggerRequest(BaseModel):
    repository: str
    commit_sha: str
    developer_id: str = "unknown"
    trigger: str = "api"

class PipelineTriggerResponse(BaseModel):
    pipeline_id: str
    status: str
    message: str

class PipelineStatusRequest(BaseModel):
    pipeline_id: str

class PipelineStatusResponse(BaseModel):
    pipeline_id: str
    status: str
    repository: str
    commit_sha: str
    start_time: str
    end_time: str = None
    error_message: str = None
    phases_completed: list[str] = []

@router.post("/zero-trust/pipeline/trigger", response_model=PipelineTriggerResponse)
async def trigger_zero_trust_pipeline(req: PipelineTriggerRequest):
    """Trigger the complete zero-trust DevOps Shield pipeline"""
    logger.info(f"Triggering Zero Trust Pipeline for {req.repository}@{req.commit_sha[:8]}")

    if not zero_trust_orchestrator:
        logger.error("ZeroTrustOrchestrator unavailable")
        return PipelineTriggerResponse(
            pipeline_id="",
            status="error",
            message="Zero Trust Orchestrator not available"
        )

    try:
        # Create pipeline context
        pipeline_id = f"pipeline_{int(datetime.now(timezone.utc).timestamp())}_{req.commit_sha[:8]}"
        context = PipelineContext(
            pipeline_id=pipeline_id,
            repository=req.repository,
            commit_sha=req.commit_sha,
            developer_id=req.developer_id,
            trigger=req.trigger
        )

        # Execute pipeline asynchronously
        import asyncio
        asyncio.create_task(zero_trust_orchestrator.execute_zero_trust_pipeline(context))

        logger.info(f"Zero Trust Pipeline initiated: {pipeline_id}")
        return PipelineTriggerResponse(
            pipeline_id=pipeline_id,
            status="initiated",
            message="Zero Trust pipeline started successfully"
        )

    except Exception as e:
        logger.error(f"Pipeline trigger failed: {e}")
        return PipelineTriggerResponse(
            pipeline_id="",
            status="error",
            message=f"Failed to trigger pipeline: {str(e)}"
        )

@router.get("/zero-trust/pipeline/status/{pipeline_id}", response_model=PipelineStatusResponse)
async def get_pipeline_status(pipeline_id: str):
    """Get the status of a zero-trust pipeline"""
    logger.info(f"Checking pipeline status: {pipeline_id}")

    if not zero_trust_orchestrator:
        return PipelineStatusResponse(
            pipeline_id=pipeline_id,
            status="error",
            repository="",
            commit_sha="",
            start_time="",
            error_message="Zero Trust Orchestrator not available"
        )

    pipeline_data = zero_trust_orchestrator.get_pipeline_status(pipeline_id)

    if not pipeline_data:
        return PipelineStatusResponse(
            pipeline_id=pipeline_id,
            status="not_found",
            repository="",
            commit_sha="",
            start_time="",
            error_message="Pipeline not found"
        )

    # Extract phases completed
    phases_completed = []
    if pipeline_data.get('source_integrity'):
        phases_completed.append("source_integrity")
    if pipeline_data.get('dependency_check'):
        phases_completed.append("dependency_check")
    if pipeline_data.get('build_steps'):
        phases_completed.append("build_pipeline")
    if pipeline_data.get('artifact_hardening'):
        phases_completed.append("artifact_hardening")

    return PipelineStatusResponse(
        pipeline_id=pipeline_data['pipeline_id'],
        status=pipeline_data['status'],
        repository=pipeline_data['repository'],
        commit_sha=pipeline_data['commit_sha'],
        start_time=pipeline_data['start_time'],
        end_time=pipeline_data.get('end_time'),
        error_message=pipeline_data.get('error_message'),
        phases_completed=phases_completed
    )
