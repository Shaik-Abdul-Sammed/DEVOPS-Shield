"""
Zero Trust Orchestrator
Coordinates the complete DevOps Shield workflow from commit to deployment
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from src.utils.logger import get_logger
from .source_integrity import SourceIntegrityManager
from .dependency_sentinel import DependencySentinel
from .blockchain_ledger import BlockchainLedger
from .artifact_hardener import ArtifactHardener

logger = get_logger(__name__)

class PipelineContext:
    """Context object for pipeline execution"""

    def __init__(self, pipeline_id: str, repository: str, commit_sha: str,
                 developer_id: str = None, trigger: str = "manual"):
        self.pipeline_id = pipeline_id
        self.repository = repository
        self.commit_sha = commit_sha
        self.developer_id = developer_id
        self.trigger = trigger

        # Component results
        self.source_integrity_result = None
        self.dependency_check_result = None
        self.build_steps = []
        self.ledger_records = []
        self.artifact_hardening_result = None

        # Overall status
        self.status = "initialized"
        self.error_message = None
        self.start_time = datetime.now(timezone.utc)
        self.end_time = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary"""
        return {
            'pipeline_id': self.pipeline_id,
            'repository': self.repository,
            'commit_sha': self.commit_sha,
            'developer_id': self.developer_id,
            'trigger': self.trigger,
            'status': self.status,
            'error_message': self.error_message,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'source_integrity': self.source_integrity_result,
            'dependency_check': self.dependency_check_result,
            'build_steps': self.build_steps,
            'ledger_records': self.ledger_records,
            'artifact_hardening': self.artifact_hardening_result
        }

class ZeroTrustOrchestrator:
    """
    Orchestrates the complete zero-trust DevOps Shield workflow:
    1. Source Integrity - AI behavioral analysis & secret scanning
    2. Dependency Sentinel - Namespace locking & supply chain security
    3. Blockchain Ledger - Tamper-proof audit trail
    4. Artifact Hardening - Cryptographic signing & isolated verification
    """

    def __init__(self):
        self.source_integrity = SourceIntegrityManager()
        self.dependency_sentinel = DependencySentinel()
        self.blockchain_ledger = BlockchainLedger()
        self.artifact_hardener = ArtifactHardener()

        # Active pipelines
        self.active_pipelines: Dict[str, PipelineContext] = {}

    async def execute_zero_trust_pipeline(self, context: PipelineContext) -> Dict[str, Any]:
        """
        Execute the complete zero-trust pipeline

        Args:
            context: Pipeline execution context

        Returns:
            Pipeline execution results
        """
        logger.info(f"🚀 Starting Zero Trust Pipeline: {context.pipeline_id}")

        self.active_pipelines[context.pipeline_id] = context
        context.status = "running"

        try:
            # Phase 1: Source Integrity Check
            logger.info("📋 Phase 1: Source Integrity Verification")
            success = await self._execute_source_integrity(context)
            if not success:
                context.status = "failed"
                context.error_message = "Source integrity check failed"
                return self._finalize_pipeline(context)

            # Phase 2: Dependency Sentinel Check
            logger.info("🔒 Phase 2: Dependency Sentinel Check")
            success = await self._execute_dependency_check(context)
            if not success:
                context.status = "failed"
                context.error_message = "Dependency check failed"
                return self._finalize_pipeline(context)

            # Phase 3: Build Pipeline with Ledger Recording
            logger.info("⚙️ Phase 3: Build Pipeline Execution")
            success = await self._execute_build_pipeline(context)
            if not success:
                context.status = "failed"
                context.error_message = "Build pipeline failed"
                return self._finalize_pipeline(context)

            # Phase 4: Artifact Hardening
            logger.info("🔐 Phase 4: Artifact Hardening")
            success = await self._execute_artifact_hardening(context)
            if not success:
                context.status = "failed"
                context.error_message = "Artifact hardening failed"
                return self._finalize_pipeline(context)

            # Success!
            context.status = "completed"
            logger.info(f"✅ Zero Trust Pipeline completed successfully: {context.pipeline_id}")

        except Exception as e:
            logger.error(f"❌ Pipeline execution failed: {e}", exc_info=True)
            context.status = "error"
            context.error_message = str(e)

        finally:
            # Cleanup
            if context.pipeline_id in self.active_pipelines:
                del self.active_pipelines[context.pipeline_id]

        return self._finalize_pipeline(context)

    async def _execute_source_integrity(self, context: PipelineContext) -> bool:
        """Execute source integrity verification"""
        try:
            # Prepare commit data (in production, this would come from git/webhook)
            commit_data = {
                'commit_sha': context.commit_sha,
                'timestamp': datetime.now(timezone.utc).timestamp(),
                'files_changed': ['src/main.py', 'requirements.txt'],  # Mock data
                'lines_added': 150,
                'lines_deleted': 20,
                'content': {}  # Would contain actual file contents
            }

            # Perform source integrity check
            result = self.source_integrity.verify_source_integrity(
                developer_id=context.developer_id or "unknown",
                commit_sha=context.commit_sha,
                device_id="device_123",  # Mock
                ip_address="192.168.1.100",  # Mock
                commit_data=commit_data
            )

            context.source_integrity_result = result

            # Record in blockchain ledger
            self.blockchain_ledger.record_build_step(
                pipeline_id=context.pipeline_id,
                step_name="source_integrity",
                command="Source integrity verification",
                inputs={'commit_sha': context.commit_sha, 'developer_id': context.developer_id},
                outputs={'approved': result['approved'], 'identity_score': result['identity_score']},
                metadata={'secrets_found': result['secrets_found']}
            )

            approved = result.get('approved', False)
            if not approved:
                logger.warning(f"🚫 Source integrity check failed: {result.get('reasons', [])}")

            return approved

        except Exception as e:
            logger.error(f"Source integrity execution failed: {e}")
            return False

    async def _execute_dependency_check(self, context: PipelineContext) -> bool:
        """Execute dependency sentinel check"""
        try:
            # Mock dependency manifest (in production, this would be parsed from requirements.txt, package.json, etc.)
            mock_manifest = {
                'requests': '2.28.0',
                'fastapi': '0.100.0',
                'uvicorn': '0.23.0',
                'pytorch': '2.0.0',  # This should be blocked by namespace locking
                'numpy': '1.24.0'
            }

            # Perform dependency check
            result = self.dependency_sentinel.check_dependencies(mock_manifest)
            context.dependency_check_result = result

            # Record in blockchain ledger
            self.blockchain_ledger.record_build_step(
                pipeline_id=context.pipeline_id,
                step_name="dependency_check",
                command="Dependency security analysis",
                inputs={'manifest': mock_manifest},
                outputs={
                    'approved': result['approved'],
                    'blocked_count': result['blocked_count'],
                    'risk_score': result['risk_score']
                },
                metadata={'blocked_packages': result['blocked_packages']}
            )

            approved = result.get('approved', False)
            if not approved:
                logger.warning(f"🚫 Dependency check failed: {result.get('reasons', [])}")

            return approved

        except Exception as e:
            logger.error(f"Dependency check execution failed: {e}")
            return False

    async def _execute_build_pipeline(self, context: PipelineContext) -> bool:
        """Execute build pipeline with ledger recording"""
        try:
            build_steps = [
                {
                    'name': 'checkout_code',
                    'command': 'git checkout {commit_sha}',
                    'description': 'Checkout source code'
                },
                {
                    'name': 'install_dependencies',
                    'command': 'pip install -r requirements.txt',
                    'description': 'Install Python dependencies'
                },
                {
                    'name': 'run_tests',
                    'command': 'pytest tests/',
                    'description': 'Execute test suite'
                },
                {
                    'name': 'build_artifact',
                    'command': 'python setup.py bdist_wheel',
                    'description': 'Build distribution artifact'
                }
            ]

            for step_info in build_steps:
                # Simulate step execution (in production, this would actually run commands)
                await asyncio.sleep(0.1)  # Simulate processing time

                # Record step in ledger
                step_recorded = self.blockchain_ledger.record_build_step(
                    pipeline_id=context.pipeline_id,
                    step_name=step_info['name'],
                    command=step_info['command'],
                    inputs={'commit_sha': context.commit_sha},
                    outputs={'status': 'success'},
                    metadata={'description': step_info['description']}
                )

                if not step_recorded:
                    logger.error(f"Failed to record build step: {step_info['name']}")
                    return False

                context.build_steps.append({
                    'step': step_info['name'],
                    'command': step_info['command'],
                    'status': 'success',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })

                logger.info(f"✅ Build step completed: {step_info['name']}")

            return True

        except Exception as e:
            logger.error(f"Build pipeline execution failed: {e}")
            return False

    async def _execute_artifact_hardening(self, context: PipelineContext) -> bool:
        """Execute artifact hardening"""
        try:
            # Mock artifact path (in production, this would be the actual build output)
            artifact_path = f"/tmp/build_artifacts/{context.pipeline_id}/dist/myapp-1.0.0-py3-none-any.whl"

            # Ensure artifact directory exists for demo
            import os
            os.makedirs(os.path.dirname(artifact_path), exist_ok=True)

            # Create a mock artifact file
            with open(artifact_path, 'w') as f:
                f.write("# Mock artifact file\n")
                f.write(f"Built from commit: {context.commit_sha}\n")
                f.write(f"Pipeline: {context.pipeline_id}\n")

            # Perform artifact hardening
            hardening_result = self.artifact_hardener.harden_artifact(artifact_path)
            context.artifact_hardening_result = hardening_result

            # Record final step in ledger
            self.blockchain_ledger.record_build_step(
                pipeline_id=context.pipeline_id,
                step_name="artifact_hardening",
                command="Cryptographic signing and verification",
                inputs={'artifact_path': artifact_path},
                outputs={
                    'hardened': hardening_result.get('final_status') == 'hardened',
                    'signed': 'cryptographic_signing' in hardening_result.get('steps_completed', [])
                },
                metadata={'hardening_steps': hardening_result.get('steps_completed', [])}
            )

            # Complete the pipeline in blockchain ledger
            blockchain_receipt = self.blockchain_ledger.complete_pipeline(
                pipeline_id=context.pipeline_id,
                status="completed"
            )

            if blockchain_receipt:
                context.ledger_records.append({
                    'type': 'pipeline_completion',
                    'blockchain_tx': blockchain_receipt.get('transaction_hash'),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })

            hardened = hardening_result.get('final_status') == 'hardened'
            if not hardened:
                logger.warning(f"🚫 Artifact hardening failed: {hardening_result.get('errors', [])}")

            return hardened

        except Exception as e:
            logger.error(f"Artifact hardening execution failed: {e}")
            return False

    def _finalize_pipeline(self, context: PipelineContext) -> Dict[str, Any]:
        """Finalize pipeline execution"""
        context.end_time = datetime.now(timezone.utc)

        result = context.to_dict()

        # Log final status
        if context.status == "completed":
            logger.info(f"🎉 Pipeline {context.pipeline_id} completed successfully")
        elif context.status == "failed":
            logger.warning(f"⚠️ Pipeline {context.pipeline_id} failed: {context.error_message}")
        else:
            logger.error(f"❌ Pipeline {context.pipeline_id} encountered error: {context.error_message}")

        return result

    def get_pipeline_status(self, pipeline_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a pipeline"""
        if pipeline_id in self.active_pipelines:
            return self.active_pipelines[pipeline_id].to_dict()

        # Check completed pipelines via ledger
        pipeline = self.blockchain_ledger.completed_pipelines.get(pipeline_id)
        if pipeline:
            context = PipelineContext(pipeline.pipeline_id, pipeline.repository, pipeline.commit_sha)
            context.status = pipeline.status
            context.start_time = pipeline.start_time
            context.end_time = pipeline.end_time
            return context.to_dict()

        return None

    def get_orchestrator_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        return {
            'active_pipelines': len(self.active_pipelines),
            'ledger_stats': self.blockchain_ledger.get_ledger_stats(),
            'hardener_stats': self.artifact_hardener.get_hardening_stats(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    async def handle_webhook_trigger(self, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle CI/CD webhook trigger and initiate zero-trust pipeline

        Args:
            webhook_data: Webhook payload from GitLab/GitHub

        Returns:
            Pipeline initiation result
        """
        try:
            # Extract pipeline information from webhook
            repository = webhook_data.get('repository', {}).get('full_name', 'unknown')
            commit_sha = webhook_data.get('after', 'unknown')
            developer = webhook_data.get('pusher', {}).get('name', 'unknown')

            # Generate pipeline ID
            pipeline_id = f"pipeline_{int(datetime.now(timezone.utc).timestamp())}_{commit_sha[:8]}"

            # Create pipeline context
            context = PipelineContext(
                pipeline_id=pipeline_id,
                repository=repository,
                commit_sha=commit_sha,
                developer_id=developer,
                trigger="webhook"
            )

            # Execute pipeline asynchronously
            asyncio.create_task(self.execute_zero_trust_pipeline(context))

            return {
                'pipeline_id': pipeline_id,
                'status': 'initiated',
                'message': 'Zero Trust pipeline initiated'
            }

        except Exception as e:
            logger.error(f"Webhook trigger failed: {e}")
            return {
                'error': str(e),
                'status': 'failed'
            }