"""
Adaptive Security Thresholds
Machine learning-based threshold adaptation to reduce false positives and optimize security
"""

import json
import statistics
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from src.utils.logger import get_logger

logger = get_logger(__name__)

class AdaptiveThresholdManager:
    """
    Adaptive threshold system that learns from historical security events
    to optimize false positive rates and security effectiveness
    """

    def __init__(self):
        self.thresholds_file = Path("data/adaptive_thresholds.json")
        self.historical_data_file = Path("data/security_history.json")
        self.thresholds = self._load_default_thresholds()
        self.historical_events: List[Dict[str, Any]] = []
        self._load_data()

    def _load_default_thresholds(self) -> Dict[str, Any]:
        """Load default adaptive thresholds"""
        return {
            'source_integrity': {
                'identity_score_threshold': 0.8,
                'behavioral_risk_threshold': 0.3,
                'secrets_risk_threshold': 0.1,
                'combined_score_threshold': 0.7,
                'false_positive_rate': 0.05,  # Target 5% false positive rate
                'false_negative_rate': 0.02,  # Target 2% false negative rate
                'adaptation_rate': 0.1,  # How quickly to adapt (0-1)
                'min_samples': 100  # Minimum samples before adaptation
            },
            'dependency_sentinel': {
                'namespace_risk_threshold': 0.6,
                'supply_chain_risk_threshold': 0.4,
                'overall_risk_threshold': 0.5,
                'false_positive_rate': 0.03,
                'false_negative_rate': 0.01,
                'adaptation_rate': 0.05,
                'min_samples': 50
            },
            'artifact_hardening': {
                'malware_risk_threshold': 0.7,
                'signature_verification_required': True,
                'sandbox_verification_required': True,
                'false_positive_rate': 0.01,
                'false_negative_rate': 0.001,
                'adaptation_rate': 0.02,
                'min_samples': 25
            },
            'pipeline_overall': {
                'max_pipeline_duration': 600,  # 10 minutes
                'max_component_failures': 2,
                'circuit_breaker_threshold': 5,
                'circuit_breaker_timeout': 300,  # 5 minutes
                'false_positive_rate': 0.02,
                'false_negative_rate': 0.005,
                'adaptation_rate': 0.05,
                'min_samples': 200
            }
        }

    def _load_data(self):
        """Load historical data and thresholds"""
        try:
            # Load thresholds
            if self.thresholds_file.exists():
                with open(self.thresholds_file, 'r') as f:
                    saved_thresholds = json.load(f)
                    # Merge with defaults
                    for category, thresholds in saved_thresholds.items():
                        if category in self.thresholds:
                            self.thresholds[category].update(thresholds)

            # Load historical events
            if self.historical_data_file.exists():
                with open(self.historical_data_file, 'r') as f:
                    self.historical_events = json.load(f)

            logger.info(f"Loaded {len(self.historical_events)} historical security events")

        except Exception as e:
            logger.error(f"Error loading adaptive threshold data: {e}")

    def _save_data(self):
        """Save thresholds and historical data"""
        try:
            # Save thresholds
            self.thresholds_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.thresholds_file, 'w') as f:
                json.dump(self.thresholds, f, indent=2)

            # Save historical events (keep last 1000)
            if len(self.historical_events) > 1000:
                self.historical_events = self.historical_events[-1000:]

            with open(self.historical_data_file, 'w') as f:
                json.dump(self.historical_events, f, indent=2)

        except Exception as e:
            logger.error(f"Error saving adaptive threshold data: {e}")

    def record_security_event(self, event_type: str, component: str, data: Dict[str, Any],
                            actual_outcome: str, predicted_outcome: str):
        """
        Record a security event for threshold adaptation

        Args:
            event_type: Type of event (e.g., 'source_integrity_check')
            component: Component that generated the event
            data: Event data and scores
            actual_outcome: What actually happened ('approved', 'blocked', 'tampered')
            predicted_outcome: What the system predicted
        """
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'component': component,
            'data': data,
            'actual_outcome': actual_outcome,
            'predicted_outcome': predicted_outcome,
            'was_correct': actual_outcome == predicted_outcome,
            'false_positive': predicted_outcome == 'blocked' and actual_outcome == 'approved',
            'false_negative': predicted_outcome == 'approved' and actual_outcome == 'blocked'
        }

        self.historical_events.append(event)

        # Adapt thresholds if we have enough data
        if len(self.historical_events) >= 50:
            self._adapt_thresholds(component)

        self._save_data()

    def get_adaptive_threshold(self, component: str, threshold_name: str) -> float:
        """
        Get the current adaptive threshold for a component

        Args:
            component: Component name (e.g., 'source_integrity')
            threshold_name: Threshold name (e.g., 'combined_score_threshold')

        Returns:
            Current threshold value
        """
        if component in self.thresholds and threshold_name in self.thresholds[component]:
            return self.thresholds[component][threshold_name]

        # Return conservative defaults if not found
        return 0.8

    def _adapt_thresholds(self, component: str):
        """Adapt thresholds based on historical performance"""
        if component not in self.thresholds:
            return

        config = self.thresholds[component]
        min_samples = config.get('min_samples', 50)

        # Get recent events for this component
        recent_events = [
            e for e in self.historical_events[-200:]  # Last 200 events
            if e['component'] == component
        ]

        if len(recent_events) < min_samples:
            return

        # Calculate current performance metrics
        false_positives = sum(1 for e in recent_events if e.get('false_positive', False))
        false_negatives = sum(1 for e in recent_events if e.get('false_negative', False))
        total_predictions = len(recent_events)

        current_fp_rate = false_positives / total_predictions if total_predictions > 0 else 0
        current_fn_rate = false_negatives / total_predictions if total_predictions > 0 else 0

        target_fp_rate = config.get('false_positive_rate', 0.05)
        target_fn_rate = config.get('false_negative_rate', 0.02)
        adaptation_rate = config.get('adaptation_rate', 0.1)

        logger.info(f"Adapting thresholds for {component}: FP={current_fp_rate:.3f}, FN={current_fn_rate:.3f}")

        # Adapt thresholds based on performance
        for threshold_name in config.keys():
            if not threshold_name.endswith('_threshold') or threshold_name == 'combined_score_threshold':
                continue

            current_threshold = config[threshold_name]

            # If too many false positives, increase threshold (be more lenient)
            if current_fp_rate > target_fp_rate * 1.2:  # 20% above target
                new_threshold = current_threshold * (1 - adaptation_rate)
                config[threshold_name] = max(0.1, new_threshold)  # Don't go below 0.1
                logger.info(f"Increased {threshold_name} to {new_threshold:.3f} (reducing false positives)")

            # If too many false negatives, decrease threshold (be more strict)
            elif current_fn_rate > target_fn_rate * 1.2:  # 20% above target
                new_threshold = current_threshold * (1 + adaptation_rate)
                config[threshold_name] = min(0.95, new_threshold)  # Don't go above 0.95
                logger.info(f"Decreased {threshold_name} to {new_threshold:.3f} (reducing false negatives)")

    def should_apply_security_check(self, component: str, context: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Determine if a security check should be applied based on risk assessment

        Args:
            component: Security component
            context: Context information (urgency, user reputation, etc.)

        Returns:
            Tuple of (should_apply, reason)
        """
        # Skip checks for emergency deployments
        if context.get('emergency', False):
            return False, "Emergency deployment - security checks bypassed"

        # Skip for highly trusted users with good history
        user_reputation = context.get('user_reputation', 0.5)
        if user_reputation > 0.9:
            return False, "High-reputation user - reduced security checks"

        # Apply risk-based checking
        risk_level = context.get('risk_level', 'medium')
        if risk_level == 'low':
            # For low-risk changes, reduce frequency of expensive checks
            if component in ['artifact_hardening']:
                return False, "Low-risk change - skipping expensive verification"

        return True, "Security check required"

    def get_performance_metrics(self, component: str = None, hours: int = 24) -> Dict[str, Any]:
        """Get performance metrics for monitoring"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Filter events
        relevant_events = [
            e for e in self.historical_events
            if datetime.fromisoformat(e['timestamp']) > cutoff_time
        ]

        if component:
            relevant_events = [e for e in relevant_events if e['component'] == component]

        if not relevant_events:
            return {'error': 'No events found in time range'}

        # Calculate metrics
        total_events = len(relevant_events)
        correct_predictions = sum(1 for e in relevant_events if e.get('was_correct', False))
        false_positives = sum(1 for e in relevant_events if e.get('false_positive', False))
        false_negatives = sum(1 for e in relevant_events if e.get('false_negative', False))

        accuracy = correct_predictions / total_events if total_events > 0 else 0
        fp_rate = false_positives / total_events if total_events > 0 else 0
        fn_rate = false_negatives / total_events if total_events > 0 else 0

        return {
            'total_events': total_events,
            'accuracy': accuracy,
            'false_positive_rate': fp_rate,
            'false_negative_rate': fn_rate,
            'correct_predictions': correct_predictions,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'time_range_hours': hours,
            'component': component or 'all'
        }

    def reset_thresholds(self, component: str = None):
        """Reset thresholds to defaults"""
        if component:
            if component in self.thresholds:
                self.thresholds[component] = self._load_default_thresholds()[component]
        else:
            self.thresholds = self._load_default_thresholds()

        self._save_data()
        logger.info(f"Reset thresholds for {component or 'all components'}")

# Global adaptive threshold manager
adaptive_thresholds = AdaptiveThresholdManager()