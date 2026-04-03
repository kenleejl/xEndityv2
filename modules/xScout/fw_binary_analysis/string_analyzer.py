import os
import re
import subprocess
from typing import Dict, Any, List

class StringAnalyzer:
    """Module for printable string analysis"""
    
    def __init__(self):
        # Define which patterns should be case sensitive
        self.case_sensitive_categories = {'dji_patterns'}
        
        self.vendor_patterns = {
            'avm': [r'AVM GmbH.*All rights reserved', r'\(C\) Copyright.*AVM'],
            'supermicro_bmc': [r'libipmi\.so'],
            'dji_patterns': [r'^PRAK$', r'^RREK$', r'^IAEK$', r'^PUEK$'],  # Exact matches only
            'uefi_bios': [r'UEFI\b', r'\bBIOS\b'],  # Word boundaries
            'linux_indicators': [r'/bin/', r'/sbin/', r'/etc/', r'/usr/', r'busybox'],
            'init_patterns': [r'init=/[/\w]+']
        }
    
    def analyze_strings(self, file_path: str) -> Dict[str, Any]:
        """Extract and analyze printable strings"""
        # Create output directory based on firmware name
        firmware_name = os.path.splitext(os.path.basename(file_path))[0]
        output_dir = os.path.join(os.path.dirname(file_path), f"{firmware_name}_analysis")
        os.makedirs(output_dir, exist_ok=True)
        
        analysis = {
            'vendor_detected': [],
            'architecture_hints': [],
            'filesystem_indicators': [],
            'total_strings': 0,
            'notable_strings': [],
            'output_dir': output_dir
        }
        
        try:
            # Extract strings
            result = subprocess.run(['strings', file_path], 
                                  capture_output=True, text=True, check=True)
            strings_output = result.stdout
            strings_list = strings_output.split('\n')
            
            analysis['total_strings'] = len([s for s in strings_list if s.strip()])
            
            # Analyze patterns
            for category, patterns in self.vendor_patterns.items():
                matches = []
                for pattern in patterns:
                    for string in strings_list:
                        string = string.strip()
                        if not string:
                            continue
                            
                        # Use case-sensitive matching for specific categories
                        flags = 0 if category in self.case_sensitive_categories else re.IGNORECASE
                        if re.search(pattern, string, flags):
                            matches.append(string)
                
                if matches:
                    analysis['vendor_detected'].append({
                        'category': category,
                        'matches': list(set(matches))[:5]  # Limit to 5 matches
                    })
            
            # Look for architecture indicators
            arch_patterns = {
                'arm': [r'\barm\b', r'\bARM\b'],  # Word boundaries
                'mips': [r'\bmips\b', r'\bMIPS\b'],
                'x86': [r'\bi386\b', r'\bx86\b'],
                'powerpc': [r'\bppc\b', r'\bPowerPC\b']
            }
            
            for arch, patterns in arch_patterns.items():
                for pattern in patterns:
                    if any(re.search(pattern, s) for s in strings_list[:1000]):
                        analysis['architecture_hints'].append(arch)
                        break
            
            # Save strings to file in output directory
            strings_file = os.path.join(output_dir, "strings.txt")
            with open(strings_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(strings_output)
            
            analysis['strings_file'] = strings_file
            
        except Exception as e:
            analysis['error'] = f"String analysis failed: {e}"
        
        return analysis