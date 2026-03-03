"""
Secrets Management & Rotation
Secure credential storage, automatic secret rotation, and environment management
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from pathlib import Path
import json
from cryptography.fernet import Fernet
from enum import Enum
from src.utils.logger import get_logger

logger = get_logger(__name__)

# ===== SECRET TYPES =====
class SecretType(str, Enum):
    """Types of secrets to manage"""
    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"
    WEBHOOK_SECRET = "webhook_secret"
    JWT_SECRET = "jwt_secret"
    ENCRYPTION_KEY = "encryption_key"
    SERVICE_CREDENTIAL = "service_credential"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"

# ===== SECRET VAULT =====
class SecretVault:
    """Secure storage for secrets with rotation tracking"""
    
    def __init__(self, vault_path: str = ".secrets/vault.json", master_key: str = None):
        self.vault_path = Path(vault_path)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption
        if master_key:
            self.cipher = Fernet(master_key.encode() if isinstance(master_key, str) else master_key)
        else:
            # Generate new master key if not provided
            self.cipher = Fernet(Fernet.generate_key())
        
        self.vault = self._load_vault()
    
    async def initialize(self):
        """Initialize vault (async compatible)"""
        logger.info(f"SecretVault initialized from {self.vault_path}")
        return True
    
    def _load_vault(self) -> Dict[str, Any]:
        """Load vault from file"""
        if self.vault_path.exists():
            try:
                with open(self.vault_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading vault: {e}")
                return {}
        return {}
    
    def _save_vault(self):
        """Save vault to file"""
        try:
            with open(self.vault_path, 'w') as f:
                json.dump(self.vault, f, indent=2)
            # Restrict file permissions to owner only
            os.chmod(self.vault_path, 0o600)
            logger.info("Vault saved securely")
        except Exception as e:
            logger.error(f"Error saving vault: {e}")
    
    def store_secret(self, name: str, value: str, secret_type: SecretType, 
                    rotation_days: int = 90) -> bool:
        """
        Store secret with encryption
        """
        try:
            # Encrypt secret
            encrypted_value = self.cipher.encrypt(value.encode())
            
            self.vault[name] = {
                "type": secret_type.value,
                "value": encrypted_value.decode(),
                "created_at": datetime.utcnow().isoformat(),
                "last_rotated": datetime.utcnow().isoformat(),
                "rotation_interval_days": rotation_days,
                "rotation_due": (datetime.utcnow() + timedelta(days=rotation_days)).isoformat(),
                "version": 1
            }
            
            self._save_vault()
            logger.info(f"Secret stored: {name}")
            return True
        except Exception as e:
            logger.error(f"Error storing secret: {e}")
            return False
    
    def retrieve_secret(self, name: str) -> Optional[str]:
        """
        Retrieve and decrypt secret
        """
        try:
            if name not in self.vault:
                logger.warning(f"Secret not found: {name}")
                return None
            
            encrypted_value = self.vault[name]["value"]
            decrypted_value = self.cipher.decrypt(encrypted_value.encode()).decode()
            return decrypted_value
        except Exception as e:
            logger.error(f"Error retrieving secret: {e}")
            return None
    
    def rotate_secret(self, name: str, new_value: str) -> bool:
        """
        Rotate secret and maintain version history
        """
        try:
            if name not in self.vault:
                logger.warning(f"Secret not found for rotation: {name}")
                return False
            
            # Store old value in history
            old_secret = self.vault[name]
            rotation_history = old_secret.get("rotation_history", [])
            
            rotation_history.append({
                "version": old_secret.get("version", 1),
                "rotated_at": old_secret.get("last_rotated"),
                "expired_at": datetime.utcnow().isoformat()
            })
            
            # Store new secret
            self.vault[name] = {
                **old_secret,
                "value": self.cipher.encrypt(new_value.encode()).decode(),
                "last_rotated": datetime.utcnow().isoformat(),
                "rotation_due": (datetime.utcnow() + timedelta(days=old_secret.get("rotation_interval_days", 90))).isoformat(),
                "version": old_secret.get("version", 1) + 1,
                "rotation_history": rotation_history
            }
            
            self._save_vault()
            logger.info(f"Secret rotated: {name} (v{self.vault[name]['version']})")
            return True
        except Exception as e:
            logger.error(f"Error rotating secret: {e}")
            return False
    
    def get_rotation_due(self) -> Dict[str, datetime]:
        """
        Get secrets due for rotation
        """
        due = {}
        now = datetime.utcnow()
        
        for name, secret in self.vault.items():
            rotation_due = datetime.fromisoformat(secret.get("rotation_due", ""))
            if rotation_due <= now:
                due[name] = rotation_due
        
        return due
    
    def delete_secret(self, name: str) -> bool:
        """
        Securely delete secret
        """
        try:
            if name in self.vault:
                # Overwrite with random data before deleting
                self.vault[name]["value"] = secrets.token_hex(32)
                del self.vault[name]
                self._save_vault()
                logger.info(f"Secret deleted: {name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting secret: {e}")
            return False

# ===== ENVIRONMENT VARIABLE MANAGER =====
class EnvironmentManager:
    """Manage environment variables securely"""
    
    def __init__(self, vault: SecretVault):
        self.vault = vault
    
    def load_from_vault(self, prefix: str = "") -> Dict[str, str]:
        """Load environment variables from vault"""
        env_vars = {}
        for name, secret in self.vault.vault.items():
            if prefix and not name.startswith(prefix):
                continue
            
            value = self.vault.retrieve_secret(name)
            if value:
                env_vars[name] = value
        
        return env_vars
    
    def set_env_from_vault(self, secret_name: str, env_var_name: str):
        """Set environment variable from vault secret"""
        value = self.vault.retrieve_secret(secret_name)
        if value:
            os.environ[env_var_name] = value
            return True
        return False
    
    def validate_required_secrets(self, required_secrets: Dict[str, SecretType]) -> bool:
        """Validate that all required secrets are present"""
        missing = []
        for name, secret_type in required_secrets.items():
            if name not in self.vault.vault:
                missing.append(name)
        
        if missing:
            logger.error(f"Missing required secrets: {missing}")
            return False
        
        return True

# ===== SECRET ROTATION SERVICE =====
class SecretRotationService:
    """Automated secret rotation service"""
    
    def __init__(self, vault: SecretVault):
        self.vault = vault
        self.rotation_handlers = {}
    
    def register_rotation_handler(self, secret_type: SecretType, handler):
        """
        Register handler for secret rotation
        Handler should accept (secret_name, new_value) and update services
        """
        self.rotation_handlers[secret_type] = handler
    
    def rotate_all_due_secrets(self) -> Dict[str, bool]:
        """
        Rotate all secrets that are due for rotation
        """
        results = {}
        due_secrets = self.vault.get_rotation_due()
        
        for secret_name in due_secrets:
            try:
                # Generate new secret value
                new_value = secrets.token_urlsafe(32)
                
                # Rotate in vault
                if self.vault.rotate_secret(secret_name, new_value):
                    # Call rotation handler if registered
                    secret_type = SecretType(self.vault.vault[secret_name]["type"])
                    if secret_type in self.rotation_handlers:
                        handler = self.rotation_handlers[secret_type]
                        handler(secret_name, new_value)
                    
                    results[secret_name] = True
                    logger.info(f"Rotated secret: {secret_name}")
                else:
                    results[secret_name] = False
            except Exception as e:
                logger.error(f"Error rotating secret {secret_name}: {e}")
                results[secret_name] = False
        
        return results

# ===== GLOBAL INSTANCES =====
secret_vault = SecretVault()
environment_manager = EnvironmentManager(secret_vault)
secret_rotation_service = SecretRotationService(secret_vault)
