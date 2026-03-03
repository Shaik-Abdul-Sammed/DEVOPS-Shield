"""
Backup & Recovery System
Automated backups, disaster recovery, data restoration, and backup verification
"""

import os
import shutil
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import sqlite3
try:
    from src.utils.logger import get_logger  # type: ignore[import-untyped]
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)  # type: ignore[assignment]

# ===== BACKUP TYPES =====


class BackupType(str, Enum):
    """Types of backups"""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"

# ===== BACKUP MANIFEST =====


class BackupManifest:
    """Metadata about a backup"""

    def __init__(self, backup_id: str, backup_type: BackupType,
                 source_path: str, backup_path: str):
        self.backup_id = backup_id
        self.backup_type = backup_type
        self.source_path = source_path
        self.backup_path = backup_path
        self.created_at = datetime.utcnow()
        self.size_bytes = 0
        self.file_count = 0
        self.checksum: Optional[str] = None
        self.compressed = False
        self.encrypted = False
        self.retention_days = 30
        self.expiration_date = datetime.utcnow() + timedelta(days=30)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "backup_id": self.backup_id,
            "type": self.backup_type.value,
            "source_path": self.source_path,
            "backup_path": self.backup_path,
            "created_at": self.created_at.isoformat(),
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "checksum": self.checksum,
            "compressed": self.compressed,
            "encrypted": self.encrypted,
            "retention_days": self.retention_days,
            "expiration_date": self.expiration_date.isoformat()
        }

# ===== BACKUP MANAGER =====


class BackupManager:
    """Manage system backups"""

    def __init__(self, backup_dir: str = "backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file = self.backup_dir / "backups.json"
        self.backups: Dict[str, Dict[str, Any]] = self._load_manifests()

    async def initialize(self):
        """Initialize backup manager (async compatible)"""
        logger.info(f"BackupManager initialized with directory: {self.backup_dir}")
        return True

    def _load_manifests(self) -> Dict[str, Dict[str, Any]]:
        """Load backup manifests"""
        if self.manifest_file.exists():
            try:
                with open(self.manifest_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading manifests: {e}")
                return {}
        return {}

    def _save_manifests(self):
        """Save backup manifests"""
        try:
            with open(self.manifest_file, 'w') as f:
                json.dump(self.backups, f, indent=2)
            os.chmod(self.manifest_file, 0o600)
        except Exception as e:
            logger.error(f"Error saving manifests: {e}")

    def create_backup(self, source_path: str, backup_type: BackupType = BackupType.FULL) -> Tuple[bool, str]:
        """
        Create backup of source path
        Returns: (success, backup_id)
        """
        try:
            source = Path(source_path)
            if not source.exists():
                return False, "Source path does not exist"

            # Generate backup ID
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_id = f"backup_{timestamp}"
            backup_path = self.backup_dir / backup_id
            backup_path.mkdir(parents=True, exist_ok=True)

            # Create backup
            if source.is_dir():
                shutil.copytree(source, backup_path / source.name)
            else:
                shutil.copy2(source, backup_path)

            # Create manifest
            manifest = BackupManifest(
                backup_id, backup_type, str(source), str(backup_path))

            # Calculate size and file count
            manifest.size_bytes = sum(
                f.stat().st_size for f in backup_path.rglob('*') if f.is_file())
            manifest.file_count = len(list(backup_path.rglob('*')))

            # Calculate checksum
            manifest.checksum = self._calculate_backup_checksum(backup_path)

            # Store manifest
            self.backups[backup_id] = manifest.to_dict()
            self._save_manifests()

            logger.info(f"Backup created: {
                        backup_id} ({manifest.size_bytes} bytes)")
            return True, backup_id
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return False, str(e)

    def restore_backup(self, backup_id: str, target_path: str) -> Tuple[bool, str]:
        """
        Restore backup to target path
        """
        try:
            if backup_id not in self.backups:
                return False, f"Backup not found: {backup_id}"

            manifest = self.backups[backup_id]
            backup_path = Path(manifest["backup_path"])
            target = Path(target_path)

            if not backup_path.exists():
                return False, "Backup source path does not exist"

            # Verify backup integrity before restoring
            if manifest.get("checksum"):
                calculated = self._calculate_backup_checksum(backup_path)
                if calculated != manifest["checksum"]:
                    return False, "Backup checksum mismatch - possible corruption"

            # Create backup of current state before restore
            if target.exists():
                pre_restore_backup, _ = self.create_backup(str(target))
                if not pre_restore_backup:
                    logger.warning(
                        f"Could not create pre-restore backup of {target_path}")

            # Restore backup
            if backup_path.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(backup_path, target)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_path, target)

            logger.info(f"Backup restored: {backup_id} to {target_path}")
            return True, f"Restored backup {backup_id}"
        except Exception as e:
            logger.error(f"Error restoring backup: {e}")
            return False, str(e)

    def verify_backup(self, backup_id: str) -> Tuple[bool, str]:
        """
        Verify backup integrity
        """
        try:
            if backup_id not in self.backups:
                return False, f"Backup not found: {backup_id}"

            manifest = self.backups[backup_id]
            backup_path = Path(manifest["backup_path"])

            if not backup_path.exists():
                return False, "Backup path does not exist"

            # Verify checksum
            if manifest.get("checksum"):
                calculated = self._calculate_backup_checksum(backup_path)
                if calculated != manifest["checksum"]:
                    return False, "Checksum mismatch - backup may be corrupted"

            # Verify file count
            actual_file_count = len(list(backup_path.rglob('*')))
            if actual_file_count != manifest.get("file_count", 0):
                return False, f"File count mismatch: expected {manifest['file_count']}, got {actual_file_count}"

            logger.info(f"Backup verified: {backup_id}")
            return True, "Backup integrity verified"
        except Exception as e:
            logger.error(f"Error verifying backup: {e}")
            return False, str(e)

    def delete_backup(self, backup_id: str) -> bool:
        """
        Delete backup
        """
        try:
            if backup_id not in self.backups:
                return False

            backup_path = Path(self.backups[backup_id]["backup_path"])
            if backup_path.exists():
                shutil.rmtree(backup_path)

            self.backups.pop(backup_id, None)  # type: ignore[arg-type]
            self._save_manifests()

            logger.info(f"Backup deleted: {backup_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting backup: {e}")
            return False

    def cleanup_expired_backups(self) -> List[str]:
        """
        Delete expired backups based on retention policy
        """
        deleted = []
        now = datetime.utcnow()

        for backup_id, manifest in list(self.backups.items()):
            expiration = datetime.fromisoformat(manifest["expiration_date"])
            if expiration <= now:
                if self.delete_backup(backup_id):
                    deleted.append(backup_id)

        logger.info(f"Cleaned up {len(deleted)} expired backups")
        return deleted

    async def cleanup(self):
        """Async wrapper for cleanup_expired_backups to satisfy main.py call"""
        return self.cleanup_expired_backups()

    def get_backup_info(self, backup_id: str) -> Optional[Dict]:
        """Get backup information"""
        return self.backups.get(backup_id)

    def list_backups(self, limit: int = 50) -> List[Dict]:
        """List all backups"""
        backups = sorted(self.backups.values(),
                         key=lambda x: x["created_at"], reverse=True)
        result = []
        for i, b in enumerate(backups):
            if i >= limit:
                break
            result.append(b)
        return result

    @staticmethod
    def _calculate_backup_checksum(path: Path) -> str:
        """
        Calculate checksum of backup directory
        """
        sha256_hash = hashlib.sha256()

        for file_path in sorted(path.rglob('*')):
            if file_path.is_file():
                with open(file_path, 'rb') as f:
                    sha256_hash.update(f.read())

        return sha256_hash.hexdigest()

# ===== DATABASE BACKUP =====


class DatabaseBackup:
    """Specialized backup for SQLite databases"""

    @staticmethod
    def backup_database(db_path: str, backup_dir: str = "backups") -> Tuple[bool, str]:
        """
        Create backup of SQLite database
        """
        try:
            db_file_path = Path(db_path)
            if not db_file_path.exists():
                return False, "Database file not found"

            backup_dir_path = Path(backup_dir)
            backup_dir_path.mkdir(parents=True, exist_ok=True)

            # Create backup filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_file_path = backup_dir_path / f"db_backup_{timestamp}.db"

            # Use SQLite backup API
            conn = sqlite3.connect(str(db_file_path))
            backup_conn = sqlite3.connect(str(backup_file_path))

            with backup_conn:
                conn.backup(backup_conn)

            conn.close()
            backup_conn.close()

            logger.info(f"Database backup created: {backup_file_path}")
            return True, str(backup_file_path)
        except Exception as e:
            logger.error(f"Error backing up database: {e}")
            return False, str(e)

    @staticmethod
    def restore_database(backup_file: str, target_db_path: str) -> Tuple[bool, str]:
        """
        Restore database from backup
        """
        try:
            backup_file_path = Path(backup_file)
            target_path = Path(target_db_path)

            if not backup_file_path.exists():
                return False, "Backup file not found"

            # Create parent directory if needed
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Restore using SQLite backup API
            backup_conn = sqlite3.connect(str(backup_file_path))
            target_conn = sqlite3.connect(str(target_path))

            with target_conn:
                backup_conn.backup(target_conn)

            backup_conn.close()
            target_conn.close()

            logger.info(f"Database restored from: {backup_file}")
            return True, "Database restored successfully"
        except Exception as e:
            logger.error(f"Error restoring database: {e}")
            return False, str(e)


# ===== GLOBAL INSTANCES =====
backup_manager = BackupManager()
database_backup = DatabaseBackup()
