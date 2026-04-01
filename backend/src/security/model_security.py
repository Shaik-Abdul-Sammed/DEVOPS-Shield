"""
ML Model Security & Data Validation
Data integrity checks, model poisoning detection, secure training, and validation
"""

import hashlib
import json
import pickle
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import numpy as np
from enum import Enum
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ===== MODEL METADATA =====
class ModelMetadata:
    """Track ML model metadata and integrity"""
    
    def __init__(self, model_id: str, model_version: str, training_date: datetime = None):
        self.model_id = model_id
        self.model_version = model_version
        self.training_date = training_date or datetime.now(timezone.utc)
        self.model_hash = None
        self.training_data_hash = None
        self.integrity_verified = False
        self.last_verification = None
        self.poison_detection_score = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "model_id": self.model_id,
            "model_version": self.model_version,
            "training_date": self.training_date.isoformat(),
            "model_hash": self.model_hash,
            "training_data_hash": self.training_data_hash,
            "integrity_verified": self.integrity_verified,
            "last_verification": self.last_verification.isoformat() if self.last_verification else None,
            "poison_detection_score": self.poison_detection_score
        }

# ===== DATA VALIDATION =====
class DataValidator:
    """Validate training and inference data"""
    
    @staticmethod
    def validate_features(data: List[List[float]], expected_features: int) -> Tuple[bool, str]:
        """
        Validate that data has expected number of features
        """
        if not isinstance(data, list) or len(data) == 0:
            return False, "Data is empty or invalid type"
        
        if len(data[0]) != expected_features:
            return False, f"Expected {expected_features} features, got {len(data[0])}"
        
        return True, "Valid"
    
    @staticmethod
    def validate_data_types(data: List[List[float]]) -> Tuple[bool, str]:
        """
        Validate that data contains numeric values
        """
        try:
            for sample in data:
                for value in sample:
                    if not isinstance(value, (int, float)):
                        return False, f"Invalid data type: {type(value)}"
                    # Check for NaN or Inf
                    if np.isnan(value) or np.isinf(value):
                        return False, "Data contains NaN or Inf values"
            return True, "Valid"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def validate_feature_ranges(data: List[List[float]], expected_ranges: Dict[int, Tuple[float, float]]) -> Tuple[bool, List[str]]:
        """
        Validate that features are within expected ranges
        Returns: (is_valid, list_of_warnings)
        """
        warnings = []
        data_array = np.array(data)
        
        for feature_idx, (min_val, max_val) in expected_ranges.items():
            if feature_idx < data_array.shape[1]:
                feature_data = data_array[:, feature_idx]
                
                if np.min(feature_data) < min_val or np.max(feature_data) > max_val:
                    warnings.append(f"Feature {feature_idx} outside expected range [{min_val}, {max_val}]")
        
        return len(warnings) == 0, warnings
    
    @staticmethod
    def detect_outliers(data: List[List[float]], threshold: float = 3.0) -> List[int]:
        """
        Detect outliers using Z-score method
        Returns: list of outlier indices
        """
        data_array = np.array(data)
        outlier_indices = []
        
        for i, sample in enumerate(data_array):
            z_scores = np.abs((sample - np.mean(data_array, axis=0)) / np.std(data_array, axis=0))
            if np.any(z_scores > threshold):
                outlier_indices.append(i)
        
        return outlier_indices
    
    @staticmethod
    def compute_data_hash(data: List[List[float]]) -> str:
        """
        Compute SHA-256 hash of data for integrity verification
        """
        try:
            # Convert data to JSON string for consistent hashing
            data_str = json.dumps(data)
            hash_obj = hashlib.sha256(data_str.encode())
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error computing data hash: {e}")
            return None

# ===== POISONING DETECTION =====
class PoisonDetector:
    """Detect potential data poisoning attacks"""
    
    # Suspicious patterns that indicate poisoning
    POISON_INDICATORS = {
        "extreme_values": 0.2,      # 20% weight for extreme values
        "pattern_anomalies": 0.3,    # 30% weight for pattern anomalies
        "statistical_shift": 0.25,   # 25% weight for statistical shift
        "label_corruption": 0.25     # 25% weight for label corruption
    }
    
    @staticmethod
    def check_extreme_values(data: List[List[float]], threshold: float = 5.0) -> float:
        """
        Check for extreme values that might indicate poisoning
        Returns: score (0.0 to 1.0)
        """
        data_array = np.array(data)
        mean = np.mean(data_array)
        std = np.std(data_array)
        
        # Count extreme values
        extreme_count = 0
        for sample in data_array:
            for value in sample:
                if abs(value - mean) > threshold * std:
                    extreme_count += 1
        
        # Calculate percentage of extreme values
        extreme_ratio = extreme_count / data_array.size
        return min(1.0, extreme_ratio)
    
    @staticmethod
    def check_pattern_anomalies(data: List[List[float]]) -> float:
        """
        Check for unusual patterns that deviate from expected distribution
        Returns: score (0.0 to 1.0)
        """
        try:
            data_array = np.array(data)
            
            # Calculate entropy of each feature
            entropies = []
            for feature_idx in range(data_array.shape[1]):
                feature = data_array[:, feature_idx]
                # Simple entropy calculation
                hist, _ = np.histogram(feature, bins=10)
                hist = hist / len(feature)
                entropy = -np.sum(hist[hist > 0] * np.log2(hist[hist > 0]))
                entropies.append(entropy)
            
            # Check if entropies are too uniform (suspicious)
            entropy_variance = np.var(entropies)
            return min(1.0, 1.0 / (entropy_variance + 1e-10))
        except Exception as e:
            logger.error(f"Error checking pattern anomalies: {e}")
            return 0.0
    
    @staticmethod
    def check_statistical_shift(training_data: List[List[float]], new_data: List[List[float]]) -> float:
        """
        Detect statistical distribution shifts in new data
        Returns: score (0.0 to 1.0)
        """
        try:
            train_array = np.array(training_data)
            new_array = np.array(new_data)
            
            max_shift = 0.0
            for feature_idx in range(train_array.shape[1]):
                train_mean = np.mean(train_array[:, feature_idx])
                new_mean = np.mean(new_array[:, feature_idx])
                
                train_std = np.std(train_array[:, feature_idx])
                
                if train_std > 0:
                    shift = abs(new_mean - train_mean) / train_std
                    max_shift = max(max_shift, shift)
            
            # Normalize to 0-1 range
            return min(1.0, max_shift / 5.0)
        except Exception as e:
            logger.error(f"Error checking statistical shift: {e}")
            return 0.0
    
    @staticmethod
    def check_label_corruption(true_labels: List[int], predicted_labels: List[int]) -> float:
        """
        Check for suspicious label patterns indicating corruption
        Returns: score (0.0 to 1.0)
        """
        if len(true_labels) != len(predicted_labels):
            return 1.0
        
        # Check for unusual label distributions
        true_dist = np.bincount(true_labels) / len(true_labels)
        pred_dist = np.bincount(predicted_labels) / len(predicted_labels)
        
        # Calculate Kullback-Leibler divergence
        kl_div = np.sum(true_dist * np.log(true_dist / (pred_dist + 1e-10) + 1e-10))
        
        return min(1.0, kl_div)
    
    @staticmethod
    def detect_poisoning(data: List[List[float]], labels: List[int] = None) -> Dict[str, Any]:
        """
        Comprehensive poisoning detection
        Returns: detection report with score and indicators
        """
        extreme_score = PoisonDetector.check_extreme_values(data)
        anomaly_score = PoisonDetector.check_pattern_anomalies(data)
        
        # Calculate weighted poison score
        poison_score = (
            extreme_score * PoisonDetector.POISON_INDICATORS["extreme_values"] +
            anomaly_score * PoisonDetector.POISON_INDICATORS["pattern_anomalies"]
        )
        
        return {
            "overall_score": poison_score,
            "is_poisoned": poison_score > 0.5,
            "risk_level": "high" if poison_score > 0.7 else "medium" if poison_score > 0.4 else "low",
            "indicators": {
                "extreme_values": extreme_score,
                "pattern_anomalies": anomaly_score
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# ===== MODEL SECURITY =====
class ModelSecurityManager:
    """Manage ML model security, integrity, and version control"""
    
    def __init__(self, models_dir: str = "ml/models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.model_registry = {}  # Track all models
        self.data_validator = DataValidator()
        self.poison_detector = PoisonDetector()
    
    def validate_and_save_model(self, model, model_metadata: ModelMetadata, filepath: str) -> Tuple[bool, str]:
        """
        Save model with integrity verification
        """
        try:
            # Validate model
            if model is None:
                return False, "Model is None"
            
            # Calculate model hash
            model_bytes = pickle.dumps(model)
            model_hash = hashlib.sha256(model_bytes).hexdigest()
            model_metadata.model_hash = model_hash
            
            # Save model
            model_path = self.models_dir / filepath
            model_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            
            # Save metadata
            metadata_path = model_path.with_suffix('.meta.json')
            with open(metadata_path, 'w') as f:
                json.dump(model_metadata.to_dict(), f, indent=2)
            
            # Register model
            self.model_registry[model_metadata.model_id] = {
                "version": model_metadata.model_version,
                "path": str(model_path),
                "metadata_path": str(metadata_path),
                "hash": model_hash,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Model saved: {model_metadata.model_id} v{model_metadata.model_version}")
            return True, model_hash
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False, str(e)
    
    def verify_model_integrity(self, filepath: str) -> Tuple[bool, str]:
        """
        Verify model integrity by comparing hash
        """
        try:
            model_path = self.models_dir / filepath
            
            if not model_path.exists():
                return False, "Model file not found"
            
            # Load model and calculate hash
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            
            model_bytes = pickle.dumps(model)
            calculated_hash = hashlib.sha256(model_bytes).hexdigest()
            
            # Load metadata and compare
            metadata_path = model_path.with_suffix('.meta.json')
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                expected_hash = metadata.get("model_hash")
                if expected_hash and expected_hash == calculated_hash:
                    return True, "Model integrity verified"
                else:
                    return False, f"Hash mismatch: expected {expected_hash}, got {calculated_hash}"
            
            return True, "Model integrity verified"
        except Exception as e:
            logger.error(f"Error verifying model integrity: {e}")
            return False, str(e)
    
    def check_training_data_safety(self, training_data: List[List[float]], labels: List[int] = None) -> Dict[str, Any]:
        """
        Comprehensive check for training data safety
        """
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data_validation": {},
            "poison_detection": {},
            "outlier_analysis": {},
            "safe_to_train": True,
            "warnings": []
        }
        
        try:
            # Validate data format
            is_valid, msg = self.data_validator.validate_data_types(training_data)
            report["data_validation"]["type_check"] = is_valid
            if not is_valid:
                report["warnings"].append(f"Data type validation failed: {msg}")
                report["safe_to_train"] = False
            
            # Check for poisoning
            poison_report = self.poison_detector.detect_poisoning(training_data, labels)
            report["poison_detection"] = poison_report
            if poison_report["is_poisoned"]:
                report["warnings"].append("Potential data poisoning detected")
                report["safe_to_train"] = False
            
            # Detect outliers
            outlier_indices = self.data_validator.detect_outliers(training_data)
            report["outlier_analysis"]["outlier_count"] = len(outlier_indices)
            report["outlier_analysis"]["outlier_ratio"] = len(outlier_indices) / len(training_data)
            
            if report["outlier_analysis"]["outlier_ratio"] > 0.05:  # More than 5% outliers
                report["warnings"].append(f"High outlier ratio: {report['outlier_analysis']['outlier_ratio']:.2%}")
            
            logger.info(f"Training data safety check completed. Safe: {report['safe_to_train']}")
            return report
        except Exception as e:
            logger.error(f"Error checking training data safety: {e}")
            report["safe_to_train"] = False
            report["warnings"].append(str(e))
            return report

# ===== GLOBAL INSTANCES =====
model_security_manager = ModelSecurityManager()
