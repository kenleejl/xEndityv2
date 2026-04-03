import os
from typing import Dict, Any

class MetadataAnalyzer:
    """Module for file metadata analysis"""
    
    def analyze_metadata(self, file_path: str) -> Dict[str, Any]:
        """Analyze file metadata (equivalent to ls -lh)"""
        metadata = {}
        
        try:
            file_stat = os.stat(file_path)
            
            metadata.update({
                'file_size': file_stat.st_size,
                'file_size_human': self._human_readable_size(file_stat.st_size),
                'permissions': oct(file_stat.st_mode)[-3:],
                'owner_uid': file_stat.st_uid,
                'group_gid': file_stat.st_gid,
                'modification_time': file_stat.st_mtime,
                'access_time': file_stat.st_atime,
                'creation_time': file_stat.st_ctime,
                'is_readable': os.access(file_path, os.R_OK),
                'is_writable': os.access(file_path, os.W_OK),
                'is_executable': os.access(file_path, os.X_OK)
            })
            
        except Exception as e:
            metadata['error'] = f"Metadata analysis failed: {e}"
        
        return metadata
    
    def _human_readable_size(self, size: int) -> str:
        """Convert size to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"