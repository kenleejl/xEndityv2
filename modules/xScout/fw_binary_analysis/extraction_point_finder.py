import os
import re
import subprocess
from typing import Dict, Any, List

class ExtractionPointFinder:
    """Module for finding extraction points using binwalk"""
    
    def find_extraction_points(self, file_path: str) -> Dict[str, Any]:
        """Find potential extraction points using binwalk"""
        # Get output directory
        firmware_name = os.path.splitext(os.path.basename(file_path))[0]
        output_dir = os.path.join(os.path.dirname(file_path), f"{firmware_name}_analysis")
        
        extraction_info = {
            'signatures_found': [],
            'filesystems_detected': [],
            'compressed_sections': [],
            'extraction_offsets': []
        }
        
        try:
            # Run binwalk signature scan
            result = subprocess.run(['binwalk', file_path], 
                                  capture_output=True, text=True, check=True)
            binwalk_output = result.stdout
            
            # Parse binwalk output
            lines = binwalk_output.split('\n')
            for line in lines:
                if line.strip() and not line.startswith('DECIMAL'):
                    match = re.match(r'(\d+)\s+0x[A-Fa-f0-9]+\s+(.+)', line.strip())
                    if match:
                        offset = int(match.group(1))
                        description = match.group(2)
                        
                        extraction_info['extraction_offsets'].append({
                            'offset': offset,
                            'description': description
                        })
                        
                        # Categorize findings
                        desc_lower = description.lower()
                        if any(fs in desc_lower for fs in ['filesystem', 'squashfs', 'cramfs', 'jffs2']):
                            extraction_info['filesystems_detected'].append(description)
                        elif any(comp in desc_lower for comp in ['gzip', 'lzma', 'bzip2', 'compressed']):
                            extraction_info['compressed_sections'].append(description)
                        else:
                            extraction_info['signatures_found'].append(description)
            
            # Save binwalk output
            binwalk_file = os.path.join(output_dir, "binwalk_analysis.txt")
            with open(binwalk_file, 'w') as f:
                f.write(binwalk_output)
            
            extraction_info['binwalk_file'] = binwalk_file
            extraction_info['extraction_recommended'] = len(extraction_info['extraction_offsets']) > 0
            
        except Exception as e:
            extraction_info['error'] = f"Binwalk analysis failed: {e}"
        
        return extraction_info