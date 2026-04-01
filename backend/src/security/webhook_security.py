"""
Advanced Webhook Security & Input Validation
Signature verification, rate limiting, payload validation, and injection prevention
"""

import hmac
import hashlib
import json
import re
import html
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from threading import Lock
from fastapi import HTTPException
from src.utils.logger import get_logger
from src.utils.config import Config

logger = get_logger(__name__)

# ===== WEBHOOK SIGNATURE VERIFICATION =====
class WebhookSignatureVerifier:
    """Verify incoming webhook signatures using HMAC-SHA256"""
    
    SUPPORTED_ALGORITHMS = ["sha256", "sha512"]
    
    @staticmethod
    def verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
        """
        Verify GitHub webhook signature (format: sha256=<hash>)
        Reference: https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks
        """
        try:
            if not signature or not signature.startswith("sha256="):
                logger.warning("Invalid GitHub signature format")
                return False
            
            expected_sig = "sha256=" + hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(signature, expected_sig)
        except Exception as e:
            logger.error(f"GitHub signature verification error: {e}")
            return False
    
    @staticmethod
    def verify_gitlab_signature(payload: bytes, signature: str, secret: str) -> bool:
        """
        Verify GitLab webhook signature (X-Gitlab-Token header)
        Reference: https://docs.gitlab.com/ee/user/project/integrations/webhooks.html
        """
        try:
            if not signature:
                logger.warning("Missing GitLab signature")
                return False
            
            # GitLab uses simple token comparison
            expected_sig = secret
            
            return hmac.compare_digest(signature, expected_sig)
        except Exception as e:
            logger.error(f"GitLab signature verification error: {e}")
            return False
    
    @staticmethod
    def verify_generic_signature(payload: bytes, signature: str, secret: str, algorithm: str = "sha256") -> bool:
        """
        Generic HMAC signature verification
        """
        try:
            if algorithm not in WebhookSignatureVerifier.SUPPORTED_ALGORITHMS:
                logger.warning(f"Unsupported algorithm: {algorithm}")
                return False
            
            hash_algo = hashlib.sha256 if algorithm == "sha256" else hashlib.sha512
            expected_sig = hmac.new(
                secret.encode(),
                payload,
                hash_algo
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_sig)
        except Exception as e:
            logger.error(f"Generic signature verification error: {e}")
            return False
    
    @staticmethod
    def verify_signature(payload: bytes, signature: str, secret: str, provider: str = "auto") -> bool:
        """
        Auto-detect provider and verify signature
        """
        if not secret:
            logger.warning("No webhook secret configured")
            return False
        
        if provider == "github" or (provider == "auto" and signature.startswith("sha256=")):
            return WebhookSignatureVerifier.verify_github_signature(payload, signature, secret)
        elif provider == "gitlab" or provider == "auto":
            return WebhookSignatureVerifier.verify_gitlab_signature(payload, signature, secret)
        else:
            return WebhookSignatureVerifier.verify_generic_signature(payload, signature, secret)

# ===== INPUT SANITIZATION & VALIDATION =====
class InputSanitizer:
    """Sanitize and validate all inputs to prevent injection attacks"""
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|\#|;)",
        r"(\*|'|\"|\||&|\^)",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"(<script[^>]*>|</script>)",
        r"(on\w+\s*=)",  # Event handlers
        r"(javascript:)",
        r"(<iframe[^>]*>|</iframe>)",
        r"(<object[^>]*>|</object>)",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\.",
        r"%\.\.",
        r"\.\.%",
    ]
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000, allow_html: bool = False) -> str:
        """
        Sanitize string input
        """
        if not isinstance(value, str):
            return ""
        
        # Limit length
        value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # HTML escape if not allowed
        if not allow_html:
            value = html.escape(value)
        
        return value
    
    @staticmethod
    def validate_string(value: str, pattern: str = None, max_length: int = 1000) -> bool:
        """
        Validate string against pattern
        """
        if not isinstance(value, str):
            return False
        
        if len(value) > max_length:
            return False
        
        if pattern:
            if not re.match(pattern, value):
                return False
        
        return True
    
    @staticmethod
    def check_sql_injection(value: str) -> bool:
        """
        Check if string contains SQL injection patterns
        Returns: True if injection detected, False otherwise
        """
        if not isinstance(value, str):
            return False
        
        value_upper = value.upper()
        for pattern in InputSanitizer.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def check_xss_injection(value: str) -> bool:
        """
        Check if string contains XSS patterns
        """
        if not isinstance(value, str):
            return False
        
        for pattern in InputSanitizer.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def check_path_traversal(value: str) -> bool:
        """
        Check if string contains path traversal patterns
        """
        if not isinstance(value, str):
            return False
        
        for pattern in InputSanitizer.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value):
                return True
        
        return False
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url, re.IGNORECASE))
    
    @staticmethod
    def sanitize_payload(payload: Dict[str, Any], max_depth: int = 10) -> Dict[str, Any]:
        """
        Recursively sanitize entire payload
        """
        if not isinstance(payload, dict):
            return payload
        
        if max_depth <= 0:
            logger.warning("Payload sanitization max depth reached")
            return {}
        
        sanitized = {}
        for key, value in payload.items():
            # Sanitize key
            if not InputSanitizer.validate_string(str(key), max_length=256):
                logger.warning(f"Invalid key: {key}")
                continue
            
            key = InputSanitizer.sanitize_string(str(key), max_length=256)
            
            # Sanitize value based on type
            if isinstance(value, dict):
                sanitized[key] = InputSanitizer.sanitize_payload(value, max_depth - 1)
            elif isinstance(value, list):
                sanitized[key] = [
                    InputSanitizer.sanitize_payload(v, max_depth - 1) if isinstance(v, dict) else InputSanitizer.sanitize_string(str(v))
                    for v in value
                ]
            elif isinstance(value, str):
                # Check for injection attempts
                if InputSanitizer.check_sql_injection(value):
                    logger.warning(f"SQL injection detected in field: {key}")
                    continue
                if InputSanitizer.check_xss_injection(value):
                    logger.warning(f"XSS injection detected in field: {key}")
                    continue
                
                sanitized[key] = InputSanitizer.sanitize_string(value)
            elif isinstance(value, (int, float, bool)):
                sanitized[key] = value
            elif value is None:
                sanitized[key] = None
            else:
                sanitized[key] = InputSanitizer.sanitize_string(str(value))
        
        return sanitized

# ===== PARAMETERIZED QUERIES =====
class SQLQueryBuilder:
    """Build safe SQL queries using parameterized statements"""
    
    @staticmethod
    def build_insert(table: str, data: Dict[str, Any]) -> tuple[str, List]:
        """
        Build safe INSERT query
        Returns: (query, params)
        """
        columns = list(data.keys())
        placeholders = ['?' for _ in columns]
        values = list(data.values())
        
        query = f"INSERT INTO {SQLQueryBuilder._validate_identifier(table)} ({', '.join([SQLQueryBuilder._validate_identifier(c) for c in columns])}) VALUES ({', '.join(placeholders)})"
        
        return query, values
    
    @staticmethod
    def build_update(table: str, data: Dict[str, Any], where: Dict[str, Any]) -> tuple[str, List]:
        """
        Build safe UPDATE query
        """
        set_clauses = []
        values = []
        
        for key, val in data.items():
            set_clauses.append(f"{SQLQueryBuilder._validate_identifier(key)} = ?")
            values.append(val)
        
        where_clauses = []
        for key, val in where.items():
            where_clauses.append(f"{SQLQueryBuilder._validate_identifier(key)} = ?")
            values.append(val)
        
        query = f"UPDATE {SQLQueryBuilder._validate_identifier(table)} SET {', '.join(set_clauses)}"
        if where_clauses:
            query += f" WHERE {' AND '.join(where_clauses)}"
        
        return query, values
    
    @staticmethod
    def _validate_identifier(identifier: str) -> str:
        """Validate and quote SQL identifier (table/column name)"""
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
            raise ValueError(f"Invalid SQL identifier: {identifier}")
        return f'"{identifier}"'

# ===== PAYLOAD VALIDATION =====
class PayloadValidator:
    """Validate webhook payloads"""
    
    MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_STRING_LENGTH = 10000
    MAX_ARRAY_LENGTH = 10000
    MAX_NESTING_DEPTH = 10
    
    @staticmethod
    def validate_size(content_length: int) -> bool:
        """Check payload size"""
        if content_length > PayloadValidator.MAX_PAYLOAD_SIZE:
            logger.warning(f"Payload too large: {content_length} bytes")
            return False
        return True
    
    @staticmethod
    def validate_json(payload_str: str) -> Optional[Dict]:
        """Validate JSON payload"""
        try:
            payload = json.loads(payload_str)
            return payload if isinstance(payload, dict) else None
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON payload: {e}")
            return None
    
    @staticmethod
    def validate_structure(payload: Dict, required_fields: List[str] = None) -> bool:
        """Validate payload structure"""
        if required_fields:
            for field in required_fields:
                if field not in payload:
                    logger.warning(f"Missing required field: {field}")
                    return False
        return True

# ===== WEBHOOK RATE LIMITING WITH SIGNATURE TRACKING =====
class WebhookRateLimiter:
    """Advanced webhook rate limiting with signature tracking"""
    
    def __init__(self, requests_per_minute: int = 100):
        self.requests_per_minute = requests_per_minute
        self.webhook_requests = defaultdict(list)
        self.lock = Lock()
        self.blacklist = set()  # Track signatures of malicious requests
        self.whitelist = set()  # Track verified signatures
    
    def is_allowed(self, webhook_source: str, signature: str = None) -> bool:
        """Check if webhook is allowed"""
        current_time = datetime.now(timezone.utc)
        cutoff_time = current_time - timedelta(minutes=1)
        
        # Check blacklist
        if signature and signature in self.blacklist:
            logger.warning(f"Blacklisted webhook signature: {signature}")
            return False
        
        with self.lock:
            # Clean old requests
            self.webhook_requests[webhook_source] = [
                (req_time, sig) for req_time, sig in self.webhook_requests[webhook_source]
                if req_time > cutoff_time
            ]
            
            # Check rate limit
            if len(self.webhook_requests[webhook_source]) >= self.requests_per_minute:
                logger.warning(f"Webhook rate limit exceeded for {webhook_source}")
                return False
            
            # Add current request
            self.webhook_requests[webhook_source].append((current_time, signature))
            return True
    
    def blacklist_signature(self, signature: str):
        """Blacklist a malicious signature"""
        with self.lock:
            self.blacklist.add(signature)
        logger.warning(f"Signature blacklisted: {signature}")
    
    def whitelist_signature(self, signature: str):
        """Whitelist a trusted signature"""
        with self.lock:
            self.whitelist.add(signature)

# ===== GLOBAL INSTANCES =====
webhook_signature_verifier = WebhookSignatureVerifier()
input_sanitizer = InputSanitizer()
payload_validator = PayloadValidator()
webhook_rate_limiter = WebhookRateLimiter()
