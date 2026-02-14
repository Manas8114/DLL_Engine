import psutil
import logging
import os
from typing import Dict, List, Set, Tuple
from collections import defaultdict

# Setup Logging
logger = logging.getLogger("RuntimeAnalyzer")

class RuntimeAnalyzer:
    def __init__(self):
        # Map: lowercase_dll_path -> List[pid]
        self.loaded_dlls: Dict[str, List[int]] = defaultdict(list)
        # Map: pid -> process_name
        self.process_map: Dict[int, str] = {}
        
    def scan_running_processes(self):
        """
        Iterates over all running processes and snapshots their loaded DLLs.
        Note: Requires Admin privileges to see details of system/other user processes.
        """
        logger.info("Snapshotting running processes for DLL usage...")
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                self.process_map[proc.info['pid']] = proc.info['name']
                
                # memory_maps() allows us to see loaded files (DLLs)
                # grouped=False gives us flat list of mapped regions
                try:
                    maps = proc.memory_maps(grouped=False)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    # Skip processes we can't access
                    continue

                for m in maps:
                    path = m.path
                    if path and path.lower().endswith('.dll'):
                        # Normalize path
                        clean_path = os.path.normpath(path).lower()
                        self.loaded_dlls[clean_path].append(proc.info['pid'])
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"Error scanning PID {proc.info['pid']}: {e}")

        # Deduplicate PIDs per DLL
        for dll in self.loaded_dlls:
            self.loaded_dlls[dll] = list(set(self.loaded_dlls[dll]))
            
        logger.info(f"Runtime scan complete. Found {len(self.loaded_dlls)} unique DLLs loaded across processes.")

    def get_users_of_dll(self, dll_name: str) -> List[Tuple[int, str]]:
        """
        Returns list of (PID, ProcessName) using the specified DLL.
        dll_name can be full path or just filename.
        """
        dll_name = dll_name.lower()
        users = []
        
        for path, pids in self.loaded_dlls.items():
            # Check if the filename matches exactly
            if os.path.basename(path).lower() == dll_name:
                for pid in pids:
                    name = self.process_map.get(pid, "Unknown")
                    users.append((pid, name))
        
        return list(set(users)) # Dedupe in case multiple paths matched

    def get_unused_dlls(self, scanned_dlls: List[str]) -> List[str]:
        """
        Compare a list of scanned DLL paths (on disk) against currently loaded DLLs.
        Returns paths of DLLs that are NOT currently loaded.
        """
        loaded_set = set(self.loaded_dlls.keys())
        unused = []
        
        for dll_path in scanned_dlls:
            norm_path = os.path.normpath(dll_path).lower()
            if norm_path not in loaded_set:
                unused.append(dll_path)
                
        return unused

if __name__ == "__main__":
    analyzer = RuntimeAnalyzer()
    analyzer.scan_running_processes()
    
    # Example: Check usage of a common DLL
    target = "kernel32.dll"
    users = analyzer.get_users_of_dll(target)
    print(f"Users of {target}: {len(users)} processes.")
    for pid, name in users[:5]:
        print(f"  - [{pid}] {name}")
        
    print(f"Total Unique Loaded DLLs: {len(analyzer.loaded_dlls)}")
