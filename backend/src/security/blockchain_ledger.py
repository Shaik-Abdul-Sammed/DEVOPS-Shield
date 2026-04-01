"""
Blockchain-based Ledger for Tamper-Proof Audit Trails
Implements immutable hash chains for build step verification and tampering detection
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.utils.logger import get_logger

try:
    from src.services.blockchain_service import BlockchainAuditService
except ImportError:
    BlockchainAuditService = None

logger = get_logger(__name__)

class BuildStep:
    """Represents a single build step in the pipeline"""

    def __init__(self, step_name: str, command: str, inputs: Dict[str, Any] = None,
                 outputs: Dict[str, Any] = None, metadata: Dict[str, Any] = None):
        self.step_name = step_name
        self.command = command
        self.inputs = inputs or {}
        self.outputs = outputs or {}
        self.metadata = metadata or {}
        self.timestamp = datetime.now(timezone.utc)
        self.step_hash = None
        self.previous_step_hash = None

    def calculate_step_hash(self) -> str:
        """Calculate cryptographic hash of this build step"""
        step_data = {
            'step_name': self.step_name,
            'command': self.command,
            'inputs': self.inputs,
            'outputs': self.outputs,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat(),
            'previous_step_hash': self.previous_step_hash
        }

        data_string = json.dumps(step_data, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'step_name': self.step_name,
            'command': self.command,
            'inputs': self.inputs,
            'outputs': self.outputs,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat(),
            'step_hash': self.step_hash,
            'previous_step_hash': self.previous_step_hash
        }

class BuildPipeline:
    """Represents a complete build pipeline with hash chain integrity"""

    def __init__(self, pipeline_id: str, repository: str, commit_sha: str):
        self.pipeline_id = pipeline_id
        self.repository = repository
        self.commit_sha = commit_sha
        self.steps: List[BuildStep] = []
        self.start_time = datetime.now(timezone.utc)
        self.end_time = None
        self.final_hash = None
        self.blockchain_tx = None
        self.status = 'running'  # running, completed, failed, tampered

    def add_step(self, step: BuildStep):
        """Add a build step to the pipeline with hash chaining"""
        if self.steps:
            step.previous_step_hash = self.steps[-1].step_hash

        step.step_hash = step.calculate_step_hash()
        self.steps.append(step)

        logger.info(f"Added build step '{step.step_name}' to pipeline {self.pipeline_id}")

    def complete_pipeline(self, final_status: str = 'completed'):
        """Complete the pipeline and calculate final hash"""
        self.end_time = datetime.now(timezone.utc)
        self.status = final_status

        # Calculate final pipeline hash (hash of all step hashes)
        if self.steps:
            step_hashes = [step.step_hash for step in self.steps]
            pipeline_data = {
                'pipeline_id': self.pipeline_id,
                'repository': self.repository,
                'commit_sha': self.commit_sha,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'status': self.status,
                'step_hashes': step_hashes
            }

            data_string = json.dumps(pipeline_data, sort_keys=True)
            self.final_hash = hashlib.sha256(data_string.encode()).hexdigest()

        logger.info(f"Completed pipeline {self.pipeline_id} with status {final_status}")

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of the entire pipeline hash chain

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        if not self.steps:
            issues.append("No build steps recorded")
            return False, issues

        # Verify step hash chain
        for i, step in enumerate(self.steps):
            # Recalculate step hash
            calculated_hash = step.calculate_step_hash()

            if calculated_hash != step.step_hash:
                issues.append(f"Step {i} ({step.step_name}) hash mismatch: expected {step.step_hash}, got {calculated_hash}")
                continue

            # Verify chain linkage
            if i > 0:
                expected_prev_hash = self.steps[i-1].step_hash
                if step.previous_step_hash != expected_prev_hash:
                    issues.append(f"Step {i} ({step.step_name}) chain broken: expected prev_hash {expected_prev_hash}, got {step.previous_step_hash}")

        # Verify final pipeline hash
        if self.final_hash:
            step_hashes = [step.step_hash for step in self.steps]
            pipeline_data = {
                'pipeline_id': self.pipeline_id,
                'repository': self.repository,
                'commit_sha': self.commit_sha,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat(),
                'status': self.status,
                'step_hashes': step_hashes
            }

            data_string = json.dumps(pipeline_data, sort_keys=True)
            calculated_final_hash = hashlib.sha256(data_string.encode()).hexdigest()

            if calculated_final_hash != self.final_hash:
                issues.append(f"Final pipeline hash mismatch: expected {self.final_hash}, got {calculated_final_hash}")

        is_valid = len(issues) == 0
        if is_valid:
            logger.info(f"Pipeline {self.pipeline_id} integrity verified")
        else:
            logger.warning(f"Pipeline {self.pipeline_id} integrity compromised: {issues}")

        return is_valid, issues

    def to_dict(self) -> Dict[str, Any]:
        """Convert pipeline to dictionary"""
        return {
            'pipeline_id': self.pipeline_id,
            'repository': self.repository,
            'commit_sha': self.commit_sha,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status,
            'final_hash': self.final_hash,
            'blockchain_tx': self.blockchain_tx,
            'steps': [step.to_dict() for step in self.steps]
        }

class BlockchainLedger:
    """Tamper-proof blockchain-based ledger for build pipeline audit trails"""

    def __init__(self):
        self.blockchain_service = BlockchainAuditService() if BlockchainAuditService else None
        self.active_pipelines: Dict[str, BuildPipeline] = {}
        self.completed_pipelines: Dict[str, BuildPipeline] = {}
        self.ledger_file = Path("data/blockchain_ledger.json")
        self._load_ledger()

    def _load_ledger(self):
        """Load ledger from persistent storage"""
        try:
            if self.ledger_file.exists():
                with open(self.ledger_file, 'r') as f:
                    data = json.load(f)

                # Reconstruct completed pipelines
                for pipeline_data in data.get('completed_pipelines', []):
                    pipeline = BuildPipeline(
                        pipeline_data['pipeline_id'],
                        pipeline_data['repository'],
                        pipeline_data['commit_sha']
                    )
                    pipeline.start_time = datetime.fromisoformat(pipeline_data['start_time'])
                    if pipeline_data.get('end_time'):
                        pipeline.end_time = datetime.fromisoformat(pipeline_data['end_time'])
                    pipeline.status = pipeline_data['status']
                    pipeline.final_hash = pipeline_data['final_hash']
                    pipeline.blockchain_tx = pipeline_data.get('blockchain_tx')

                    # Reconstruct steps
                    for step_data in pipeline_data['steps']:
                        step = BuildStep(
                            step_data['step_name'],
                            step_data['command'],
                            step_data.get('inputs', {}),
                            step_data.get('outputs', {}),
                            step_data.get('metadata', {})
                        )
                        step.timestamp = datetime.fromisoformat(step_data['timestamp'])
                        step.step_hash = step_data['step_hash']
                        step.previous_step_hash = step_data.get('previous_step_hash')
                        pipeline.steps.append(step)

                    self.completed_pipelines[pipeline.pipeline_id] = pipeline

                logger.info(f"Loaded {len(self.completed_pipelines)} completed pipelines from ledger")
        except Exception as e:
            logger.error(f"Error loading ledger: {e}")

    def _save_ledger(self):
        """Save ledger to persistent storage"""
        try:
            self.ledger_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                'completed_pipelines': [p.to_dict() for p in self.completed_pipelines.values()],
                'last_updated': datetime.now(timezone.utc).isoformat()
            }

            with open(self.ledger_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Error saving ledger: {e}")

    def start_pipeline(self, pipeline_id: str, repository: str, commit_sha: str) -> BuildPipeline:
        """Start a new build pipeline"""
        if pipeline_id in self.active_pipelines:
            logger.warning(f"Pipeline {pipeline_id} already exists, returning existing")
            return self.active_pipelines[pipeline_id]

        pipeline = BuildPipeline(pipeline_id, repository, commit_sha)
        self.active_pipelines[pipeline_id] = pipeline

        logger.info(f"Started new pipeline {pipeline_id} for {repository}@{commit_sha[:8]}")
        return pipeline

    def record_build_step(self, pipeline_id: str, step_name: str, command: str,
                         inputs: Dict[str, Any] = None, outputs: Dict[str, Any] = None,
                         metadata: Dict[str, Any] = None) -> bool:
        """
        Record a build step in the pipeline

        Returns:
            True if step recorded successfully
        """
        if pipeline_id not in self.active_pipelines:
            logger.error(f"Pipeline {pipeline_id} not found or not active")
            return False

        pipeline = self.active_pipelines[pipeline_id]

        step = BuildStep(step_name, command, inputs, outputs, metadata)
        pipeline.add_step(step)

        # Check for tampering in real-time
        is_valid, issues = pipeline.verify_integrity()
        if not is_valid:
            logger.critical(f"TAMPERING DETECTED in pipeline {pipeline_id}: {issues}")
            pipeline.status = 'tampered'
            # Trigger immediate security response
            self._handle_tampering_detected(pipeline, issues)
            return False

        return True

    def complete_pipeline(self, pipeline_id: str, status: str = 'completed') -> Optional[Dict[str, Any]]:
        """
        Complete a pipeline and store in blockchain ledger

        Returns:
            Blockchain transaction receipt if successful
        """
        if pipeline_id not in self.active_pipelines:
            logger.error(f"Pipeline {pipeline_id} not found")
            return None

        pipeline = self.active_pipelines[pipeline_id]
        pipeline.complete_pipeline(status)

        # Final integrity check
        is_valid, issues = pipeline.verify_integrity()
        if not is_valid:
            logger.critical(f"FINAL TAMPERING DETECTED in completed pipeline {pipeline_id}: {issues}")
            pipeline.status = 'tampered'
            self._handle_tampering_detected(pipeline, issues)

        # Store in blockchain
        blockchain_data = {
            'event_type': 'pipeline_completed',
            'pipeline_id': pipeline.pipeline_id,
            'repository': pipeline.repository,
            'commit_sha': pipeline.commit_sha,
            'final_hash': pipeline.final_hash,
            'status': pipeline.status,
            'step_count': len(pipeline.steps),
            'duration_seconds': (pipeline.end_time - pipeline.start_time).total_seconds(),
            'timestamp': pipeline.end_time.timestamp(),
            'tampering_detected': not is_valid,
            'tampering_issues': issues if not is_valid else []
        }

        tx_receipt = self.blockchain_service.store_fraud_event(blockchain_data)
        if tx_receipt:
            pipeline.blockchain_tx = tx_receipt.get('transaction_hash')
            logger.info(f"Pipeline {pipeline_id} stored on blockchain: {pipeline.blockchain_tx}")

        # Move to completed
        self.completed_pipelines[pipeline_id] = pipeline
        del self.active_pipelines[pipeline_id]

        self._save_ledger()

        return tx_receipt

    def verify_pipeline_integrity(self, pipeline_id: str) -> Tuple[bool, List[str]]:
        """Verify integrity of a completed pipeline"""
        pipeline = self.completed_pipelines.get(pipeline_id)
        if not pipeline:
            return False, [f"Pipeline {pipeline_id} not found"]

        return pipeline.verify_integrity()

    def get_pipeline_history(self, repository: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get pipeline execution history"""
        pipelines = list(self.completed_pipelines.values())

        if repository:
            pipelines = [p for p in pipelines if p.repository == repository]

        # Sort by start time, most recent first
        pipelines.sort(key=lambda p: p.start_time, reverse=True)

        return [p.to_dict() for p in pipelines[:limit]]

    def detect_tampering(self, pipeline_id: str) -> Tuple[bool, List[str]]:
        """
        Detect if a pipeline has been tampered with by comparing against blockchain

        Returns:
            Tuple of (tampering_detected, issues)
        """
        pipeline = self.completed_pipelines.get(pipeline_id)
        if not pipeline:
            return False, [f"Pipeline {pipeline_id} not found"]

        if not pipeline.blockchain_tx:
            return False, ["No blockchain record available for comparison"]

        # Verify local integrity first
        is_valid, issues = pipeline.verify_integrity()
        if not is_valid:
            return True, issues

        # Compare against blockchain record
        blockchain_valid = self.blockchain_service.verify_audit_trail(
            pipeline.blockchain_tx,
            {'final_hash': pipeline.final_hash, 'pipeline_id': pipeline_id}
        )

        if not blockchain_valid:
            issues.append("Blockchain record mismatch - potential tampering")
            return True, issues

        return False, []

    def _handle_tampering_detected(self, pipeline: BuildPipeline, issues: List[str]):
        """Handle tampering detection - trigger security response"""
        logger.critical(f"🚨 TAMPERING DETECTED in pipeline {pipeline.pipeline_id}")

        # In a real system, this would:
        # 1. Immediately halt all builds
        # 2. Alert security team
        # 3. Quarantine the repository
        # 4. Trigger incident response

        # For now, just log and mark as tampered
        pipeline.status = 'tampered'

        # Store tampering event on blockchain
        tampering_event = {
            'event_type': 'tampering_detected',
            'pipeline_id': pipeline.pipeline_id,
            'repository': pipeline.repository,
            'issues': issues,
            'timestamp': datetime.now(timezone.utc).timestamp(),
            'risk_score': 1.0
        }

        self.blockchain_service.store_fraud_event(tampering_event)

    def get_ledger_stats(self) -> Dict[str, Any]:
        """Get ledger statistics"""
        total_pipelines = len(self.completed_pipelines)
        tampered_pipelines = sum(1 for p in self.completed_pipelines.values() if p.status == 'tampered')
        active_pipelines = len(self.active_pipelines)

        return {
            'total_pipelines': total_pipelines,
            'active_pipelines': active_pipelines,
            'tampered_pipelines': tampered_pipelines,
            'tampering_rate': tampered_pipelines / total_pipelines if total_pipelines > 0 else 0,
            'blockchain_connected': self.blockchain_service.connected,
            'last_updated': datetime.now(timezone.utc).isoformat()
        }