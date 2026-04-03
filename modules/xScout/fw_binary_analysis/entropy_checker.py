import os
import re
import subprocess
import math
from typing import Dict, Any, Optional

class EntropyChecker:
    """Module for entropy analysis"""
    
    def analyze_entropy(self, file_path: str) -> Dict[str, Any]:
        """Analyze file entropy using ent command and custom calculation"""
        # Get output directory
        firmware_name = os.path.splitext(os.path.basename(file_path))[0]
        output_dir = os.path.join(os.path.dirname(file_path), f"{firmware_name}_analysis")
        
        entropy_info = {}
        
        # Use ent command if available
        try:
            result = subprocess.run(['ent', file_path], 
                                  capture_output=True, text=True, check=True)
            entropy_output = result.stdout
            
            # Parse ent output
            entropy_info['ent_output'] = entropy_output
            entropy_info['entropy_value'] = self._parse_ent_entropy(entropy_output)
            entropy_info['classification'] = self._classify_entropy(entropy_info['entropy_value'])
            
            # Save ent output
            ent_file = os.path.join(output_dir, "entropy_analysis.txt")
            with open(ent_file, 'w') as f:
                f.write(entropy_output)
            entropy_info['ent_file'] = ent_file
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to custom entropy calculation
            entropy_info['entropy_value'] = self._calculate_entropy_custom(file_path)
            entropy_info['classification'] = self._classify_entropy(entropy_info['entropy_value'])
            entropy_info['method'] = 'custom_calculation'
        
        # Generate entropy graph with binwalk if available
        entropy_info['graph_available'] = self._generate_entropy_graph(file_path, output_dir)
        
        return entropy_info
    
    def _parse_ent_entropy(self, ent_output: str) -> Optional[float]:
        """Parse entropy value from ent command output"""
        match = re.search(r'Entropy = ([\d.]+) bits per byte', ent_output)
        return float(match.group(1)) if match else None
    
    def _calculate_entropy_custom(self, file_path: str) -> Optional[float]:
        """Calculate entropy using custom implementation"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Read first 1MB for speed
            
            if not data:
                return None
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            length = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / length
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception:
            return None
    
    def _classify_entropy(self, entropy: Optional[float]) -> str:
        """Classify entropy level for decision making"""
        if entropy is None:
            return 'unknown'
        elif entropy < 3.0:
            return 'low_likely_uncompressed'
        elif entropy < 6.0:
            return 'medium_likely_compressed'
        elif entropy < 7.5:
            return 'high_likely_encrypted'
        else:
            return 'very_high_definitely_encrypted'
    
    def _generate_entropy_graph(self, file_path: str, output_dir: str) -> bool:
        """Generate entropy graph using binwalk if available"""
        try:
            output_path = os.path.join(output_dir, "entropy_graph.png")
            subprocess.run(['binwalk', '-E', '-p', output_path, file_path], 
                          capture_output=True, check=True)
            return os.path.exists(output_path)
        except:
            return False