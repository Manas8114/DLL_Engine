import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger("ManifestManager")

class ManifestManager:
    def __init__(self, backup_dir: str):
        self.manifest_path = os.path.join(backup_dir, "manifest.json")
        self._ensure_manifest()

    def _ensure_manifest(self):
        if not os.path.exists(self.manifest_path):
            with open(self.manifest_path, "w") as f:
                json.dump({"start_date": str(datetime.now()), "records": []}, f, indent=4)

    def add_record(self, original_path: str, backup_path: str, registry_keys: List[str] = None):
        try:
            with open(self.manifest_path, "r") as f:
                data = json.load(f)

            record = {
                "timestamp": str(datetime.now()),
                "operation": "DELETE",
                "original_path": original_path,
                "backup_path": backup_path,
                "registry_backup": registry_keys or [],
                "status": "active"
            }
            
            data["records"].append(record)
            
            with open(self.manifest_path, "w") as f:
                json.dump(data, f, indent=4)
                
            logger.info(f"Manifest updated for {os.path.basename(original_path)}")
            return True
        except Exception as e:
            logger.error(f"Failed to update manifest: {e}")
            return False

    def get_history(self) -> List[Dict]:
        try:
            with open(self.manifest_path, "r") as f:
                data = json.load(f)
            return data.get("records", [])
        except Exception:
            return []
