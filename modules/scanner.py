import os
import hashlib
import math
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import pefile

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DLLScanner")

@dataclass
class DLLMetadata:
    path: str
    filename: str
    size_bytes: int
    md5: str
    sha256: str
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    is_signed: bool = False
    entropy: float = 0.0
    machine_type: str = "UNKNOWN"
    compile_time: Optional[datetime] = None

class DLLScanner:
    def __init__(self):
        self.results: Dict[str, DLLMetadata] = {}

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon Entropy to detect packing/encryption."""
        if not data:
            return 0.0
        entropy = 0
        if len(data) == 0:
            return 0.0
            
        # Count byte occurrences
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
            
        for count in counts:
            if count > 0:
                p_x = float(count) / len(data)
                entropy -= p_x * math.log(p_x, 2)
        return entropy

    def get_hashes(self, data: bytes):
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return md5, sha256

    def scan_file(self, file_path: str) -> Optional[DLLMetadata]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            md5, sha256 = self.get_hashes(data)
            entropy = self.calculate_entropy(data)
            
            meta = None
            try:
                pe = pefile.PE(data=data, fast_load=True)
                
                # Parse directories for imports/exports
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
                ])
                
                imports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        if entry.dll:
                            imports.append(entry.dll.decode('utf-8', errors='ignore').lower())

                exports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            exports.append(exp.name.decode('utf-8', errors='ignore'))
                
                # Check for security directory (authenticode signature existence)
                is_signed = False
                if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
                    # Index 4 is usually the Security Directory
                    sec_dir_idx = 4 
                    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
                         security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
                         if security_dir.VirtualAddress != 0 and security_dir.Size > 0:
                             is_signed = True

                try:
                    # Machine Type Mapping
                    machine_map = {
                        0x14c: "x86",
                        0x8664: "x64",
                        0x1c0: "ARM",
                        0xaa64: "ARM64"
                    }
                    machine_val = pe.FILE_HEADER.Machine
                    machine = machine_map.get(machine_val, hex(machine_val))
                except:
                    machine = "UNKNOWN"

                timestamp = pe.FILE_HEADER.TimeDateStamp
                try:
                    compile_time = datetime.fromtimestamp(timestamp)
                except:
                    compile_time = None

                pe.close()

                meta = DLLMetadata(
                    path=file_path,
                    filename=os.path.basename(file_path),
                    size_bytes=len(data),
                    md5=md5,
                    sha256=sha256,
                    imports=imports,
                    exports=exports,
                    is_signed=is_signed,
                    entropy=entropy,
                    machine_type=machine,
                    compile_time=compile_time
                )

            except Exception as e:
                # Fallback for non-PE files or parsing errors
                # logger.debug(f"PE parsing failed for {file_path}: {e}")
                pass

            return meta

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            return None

    def scan_directory(self, directory: str, recursive: bool = True) -> Dict[str, DLLMetadata]:
        logger.info(f"Scanning directory: {directory}")
        files_to_scan = []
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(('.dll', '.exe', '.sys')):
                    files_to_scan.append(os.path.join(root, file))
            if not recursive:
                break
        
        logger.info(f"Found {len(files_to_scan)} binaries")
        
        results = {}
        with ThreadPoolExecutor() as executor:
            # Map returns iterator, convert to list to force execution
            scan_results = list(executor.map(self.scan_file, files_to_scan))
            
        for res in scan_results:
            if res:
                results[res.filename.lower()] = res
        
        self.results.update(results)
        return results

if __name__ == "__main__":
    scanner = DLLScanner()
    # Test on system32 might be too slow/permission heavy for quick test, act on current dir
    scanner.scan_directory(".") 
    print(f"Scanned {len(scanner.results)} files.")
