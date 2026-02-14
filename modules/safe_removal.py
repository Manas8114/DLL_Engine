import shutil
import os
import logging
import time
from typing import Optional, List
from datetime import datetime
from modules.manifest import ManifestManager

# Optional: Import ImpactSimulator for safety checks
try:
    from modules.impact import ImpactSimulator
except ImportError:
    ImpactSimulator = None

# Setup Logging
logger = logging.getLogger("SafeRemoval")

class RegistryBackup:
    """
    Simulates backing up Window Registry keys related to a DLL.
    In a real scenario, this would use `winreg` to export .reg files.
    """
    def __init__(self, backup_dir: str):
        self.backup_dir = backup_dir

    def backup_keys(self, dll_name: str) -> List[str]:
        # MOCK IMPLEMENTATION
        # Simulate finding keys in CLSID, TypeLib, etc.
        logger.info(f"Scanning registry for {dll_name}...")
        dummy_keys = [
            f"HKLM\\SOFTWARE\\Classes\\CLSID\\{{MOCK-GUID-{dll_name}}}",
            f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDlls\\{dll_name}"
        ]
        
        # Simulate export
        reg_file = os.path.join(self.backup_dir, f"{dll_name}_keys.mock.reg")
        with open(reg_file, "w") as f:
            f.write(f"Windows Registry Editor Version 5.00\n; Mock backup for {dll_name}\n")
            for k in dummy_keys:
                f.write(f"[{k}]\n")
        
        logger.info(f"Registry keys backed up to {reg_file}")
        return dummy_keys

class SafeRemovalManager:
    def __init__(self, backup_dir: str = "backups"):
        self.backup_dir = os.path.abspath(backup_dir)
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
            logger.info(f"Created backup directory: {self.backup_dir}")
        
        self.manifest = ManifestManager(self.backup_dir)
        self.reg_backup = RegistryBackup(self.backup_dir)

    def safe_delete(self, file_path: str, impact_engine: Optional['ImpactSimulator'] = None, force: bool = False) -> bool:
        """
        Transactional deletion workflow:
        1. Check Impact (if engine provided)
        2. Backup File
        3. Backup Registry (Mock)
        4. Update Manifest
        5. Delete File
        """
        filename = os.path.basename(file_path)
        
        # 1. Safety Check
        if impact_engine:
            logger.info("Running pre-deletion impact analysis...")
            risk = impact_engine.simulate_removal(filename)
            logger.info(f"Risk Level: {risk['risk_level']} (Score: {risk['risk_score']})")
            
            if risk['risk_level'] in ["HIGH", "CRITICAL"] and not force:
                logger.warning(f"ABORTING: Removal of {filename} is too risky. Use force=True to override.")
                return False

        try:
            # 2. File Backup
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{filename}_{timestamp}.bak"
            backup_path = os.path.join(self.backup_dir, backup_name)
            
            shutil.copy2(file_path, backup_path)
            logger.info(f"File backup created: {backup_path}")

            # 3. Registry Backup
            reg_keys = self.reg_backup.backup_keys(filename)

            # 4. Update Manifest
            self.manifest.add_record(file_path, backup_path, reg_keys)

            # 5. Delete (Simulated for safety default, can be uncommented)
            # os.remove(file_path)
            # logger.info(f"Deleted file: {file_path}")
            
            logger.warning(f"ACTION: [SIMULATED] Deleted {file_path}")
            return True

        except Exception as e:
            logger.error(f"Safe delete transaction failed: {e}")
            # In a real system, we would implement rollback here (delete backup)
            return False

    def restore_latest(self, original_path: str) -> bool:
        """
        Restores the most recent backup for a given file path.
        """
        history = self.manifest.get_history()
        # Filter for this file
        relevant = [h for h in history if h['original_path'] == original_path]
        
        if not relevant:
            logger.error("No backup history found for this file.")
            return False
        
        # Get latest
        latest = relevant[-1]
        backup_path = latest['backup_path']
        
        try:
            if not os.path.exists(backup_path):
                logger.error(f"Backup file missing: {backup_path}")
                return False
                
            shutil.copy2(backup_path, original_path)
            logger.info(f"Restored {original_path} from {backup_path}")
            # Mock registry restore
            logger.info(f"Restored {len(latest.get('registry_backup', []))} registry keys (Mock).")
            return True
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

if __name__ == "__main__":
    # Test Logic
    dummy_dll = "test_lib.dll"
    with open(dummy_dll, "w") as f:
        f.write("DUMMY DATA")
        
    mgr = SafeRemovalManager("backups")
    print("1. Testing Safe Delete...")
    if mgr.safe_delete(dummy_dll):
        print("   Delete sequence successful.")
        
    print("2. Testing Restore...")
    os.remove(dummy_dll) # Actually delete it now to test restore
    if mgr.restore_latest(os.path.abspath(dummy_dll)):
        print("   Restore successful.")
        
    # Cleanup
    if os.path.exists(dummy_dll): os.remove(dummy_dll)
