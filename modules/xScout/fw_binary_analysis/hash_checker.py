import hashlib
from typing import Dict

class HashChecker:
    """Module for file integrity hashing"""
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate MD5, SHA1, SHA256, and SHA512 hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            hashes['md5'] = hashlib.md5(file_data).hexdigest()
            hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
            hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
            hashes['sha512'] = hashlib.sha512(file_data).hexdigest()
            hashes['size'] = len(file_data)
            
        except Exception as e:
            hashes['error'] = f"Hash calculation failed: {e}"
        
        return hashes