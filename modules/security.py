import logging
from collections import defaultdict
from typing import Dict, List, Tuple
from modules.scanner import DLLMetadata

# Setup Logging
logger = logging.getLogger("SecurityModule")

class SecurityAnalyzer:
    def __init__(self, metadata_store: Dict[str, DLLMetadata]):
        self.metadata = metadata_store
        
        # Determine duplicated hashes
        self.hash_map = defaultdict(list)
        for name, meta in self.metadata.items():
            self.hash_map[meta.sha256].append(meta)

    def find_high_entropy_files(self, threshold: float = 7.2) -> List[Tuple[str, float]]:
        """
        Identify files with high entropy, suggesting packing or encryption.
        Standard text/code is usually < 6.5. Compressed/Encrypted is > 7.0.
        """
        suspicious = []
        for name, meta in self.metadata.items():
            if meta.entropy > threshold:
                suspicious.append((name, meta.entropy))
        
        return sorted(suspicious, key=lambda x: x[1], reverse=True)

    def find_unsigned_dlls(self) -> List[str]:
        """
        Identify DLLs that are NOT digitally signed.
        """
        unsigned = []
        for name, meta in self.metadata.items():
            if not meta.is_signed:
                unsigned.append(name)
        return unsigned

    def find_duplicates(self) -> Dict[str, List[str]]:
        """
        Finds identical files (same SHA256) at different locations/names.
        Returns: {sha256: [filename1, filename2, ...]}
        """
        duplicates = {}
        for hash_val, meta_list in self.hash_map.items():
            if len(meta_list) > 1:
                duplicates[hash_val] = [m.path for m in meta_list]
        return duplicates

    def check_known_threats(self, known_bad_hashes: List[str]) -> List[str]:
        """
        Compares scanned hashes against a provided list of malicious hashes.
        """
        found_threats = []
        bad_set = set(known_bad_hashes)
        for hash_val in self.hash_map:
            if hash_val in bad_set:
                files = [m.path for m in self.hash_map[hash_val]]
                found_threats.extend(files)
        return found_threats

# Example known bad hash (Empty placeholder for now)
KNOWN_BAD_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e", # MD5 of empty string (just for test)
]

if __name__ == "__main__":
    # Integration test logic would go here
    pass
