import re
import subprocess
import math
from typing import Dict, List, Any, Optional, Tuple

class EncryptionDetector:
    """Module for vendor-specific encryption detection with multi-factor analysis"""
    
    def __init__(self):
        # Vendor specific patterns from file headers
        self.vendor_patterns = {
            'dlink_shrs': b'SHRS',
            'dlink_encrypted_img': b'encrpted_img',
            'engenius_pattern1': re.compile(rb'\x00\x00\x00\x00\x00\x00..\x00\x00..\x31\x32\x33\x00'),
            'engenius_pattern2': re.compile(rb'\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00..\x33\x2e(\x38|\x39)\x2e'),
            'buffalo_pattern': re.compile(rb'\x62\x67\x6e\x00\x00\x00\x00\x00\x00\x00\x00'),
            'android_ota': b'CrAU',
            'gpg_pattern': re.compile(rb'\xa3\x01'),
            'dji_xv4': b'\x78\x56\x34',
            'openssl_salted': b'Salted__'
        }
        
        # Known encryption signatures
        self.encryption_magic_bytes = {
            'openssl_enc': [b'Salted__'],
            'pgp_encrypted': [b'\x85\x01', b'\x84\x00'],
            'aes_gcm': [b'\x00\x00\x00\x10GCM'],
            'luks_header': [b'LUKS\xba\xbe'],
            'truecrypt': [b'TRUE', b'TCRYPT']
        }
    
    def detect_encryption(self, file_path: str) -> Dict[str, Any]:
        """Detect encryption using multi-factor analysis"""
        detection_results = {
            'vendor_encryption': [],
            'hex_patterns': {},
            'gpg_detected': False,
            'encryption_indicators': [],
            'encryption_probability': 'unknown',
            'encryption_confidence': 0.0,
            'encryption_factors': {},
            'file_magic_analysis': {}
        }
        
        # Multi-factor analysis components
        factors = {
            'entropy_factor': 0.0,
            'magic_bytes_factor': 0.0,
            'vendor_pattern_factor': 0.0,
            'file_command_factor': 0.0,
            'binwalk_signature_factor': 0.0,
            'string_density_factor': 0.0
        }
        
        try:
            # Factor 1: Analyze file header and magic bytes
            factors['magic_bytes_factor'] = self._analyze_magic_bytes(file_path, detection_results)
            
            # Factor 2: Vendor-specific pattern detection
            factors['vendor_pattern_factor'] = self._detect_vendor_patterns(file_path, detection_results)
            
            # Factor 3: File command analysis
            factors['file_command_factor'] = self._analyze_file_command(file_path, detection_results)
            
            # Factor 4: Binwalk signature analysis for encryption indicators
            factors['binwalk_signature_factor'] = self._analyze_binwalk_signatures(file_path, detection_results)
            
            # Factor 5: String density analysis (encrypted files have fewer readable strings)
            factors['string_density_factor'] = self._analyze_string_density(file_path, detection_results)
            
            # Factor 6: Entropy analysis enhancement
            factors['entropy_factor'] = self._enhanced_entropy_analysis(file_path, detection_results)
            
            # Calculate overall encryption probability using weighted factors
            detection_results['encryption_factors'] = factors
            encryption_score = self._calculate_encryption_score(factors)
            detection_results['encryption_confidence'] = encryption_score
            detection_results['encryption_probability'] = self._classify_encryption_probability(encryption_score)
            
            # GPG specific check
            detection_results['gpg_detected'] = self._check_gpg_encryption(file_path)
            if detection_results['gpg_detected']:
                detection_results['encryption_probability'] = 'high_gpg_detected'
                
        except Exception as e:
            detection_results['error'] = f"Encryption analysis failed: {e}"
        
        return detection_results
    
    def _analyze_magic_bytes(self, file_path: str, results: Dict) -> float:
        """Analyze file magic bytes for encryption signatures"""
        magic_score = 0.0
        
        try:
            with open(file_path, 'rb') as f:
                header_data = f.read(1024)
            
            results['hex_patterns']['first_16_bytes'] = header_data[:16].hex()
            results['hex_patterns']['first_64_bytes'] = header_data[:64].hex()
            
            # Check known encryption magic bytes
            encryption_detected = []
            for enc_type, magic_list in self.encryption_magic_bytes.items():
                for magic in magic_list:
                    if magic in header_data:
                        encryption_detected.append(enc_type)
                        magic_score += 0.8  # High confidence for known encryption magic
            
            results['file_magic_analysis']['encryption_signatures'] = encryption_detected
            
            # Additional checks
            first_16 = header_data[:16]
            
            # Check for high randomness in first bytes (encryption indicator)
            if len(set(first_16)) > 12:  # High byte diversity
                magic_score += 0.3
                results['encryption_indicators'].append('high_byte_diversity_in_header')
            
            # Check for specific problematic patterns that indicate encryption
            if b'\x00' * 8 not in header_data[:64]:  # No long null sequences
                magic_score += 0.2
                results['encryption_indicators'].append('no_null_sequences_in_header')
            
        except Exception as e:
            results['file_magic_analysis']['error'] = str(e)
        
        return min(magic_score, 1.0)
    
    def _detect_vendor_patterns(self, file_path: str, results: Dict) -> float:
        """Detect vendor-specific encryption patterns"""
        vendor_score = 0.0
        
        try:
            with open(file_path, 'rb') as f:
                header_data = f.read(2048)  # Read more data for vendor patterns
            
            # Check vendor patterns with D-Link type differentiation
            for pattern_name, pattern in self.vendor_patterns.items():
                if isinstance(pattern, bytes):
                    # Special handling for DJI XV4 - only check at offset 0
                    if pattern_name == 'dji_xv4':
                        if header_data.startswith(pattern):
                            results['vendor_encryption'].append(pattern_name)
                            vendor_score += 0.9  # Very high confidence for vendor patterns
                    # Special handling for D-Link encryption types
                    elif pattern_name == 'dlink_shrs':
                        if pattern in header_data:
                            results['vendor_encryption'].append('dlink_shrs_type1')
                            results['dlink_encryption_type'] = 1  # EMBA style type 1
                            vendor_score += 0.9
                    elif pattern_name == 'dlink_encrypted_img':
                        if pattern in header_data:
                            results['vendor_encryption'].append('dlink_encrypted_img_type2')
                            results['dlink_encryption_type'] = 2  # EMBA style type 2
                            vendor_score += 0.9
                    # For all other byte patterns, check anywhere in header
                    else:
                        if pattern in header_data:
                            results['vendor_encryption'].append(pattern_name)
                            vendor_score += 0.9  # Very high confidence for vendor patterns
                elif hasattr(pattern, 'search'):  # regex pattern
                    if pattern.search(header_data):
                        results['vendor_encryption'].append(pattern_name)
                        vendor_score += 0.9
            
            # Ensure we have the dlink_encryption_type field for consistency
            if 'dlink_encryption_type' not in results:
                results['dlink_encryption_type'] = 0  # No D-Link encryption detected
                        
        except Exception as e:
            results['vendor_encryption'] = [f"Error: {e}"]
            results['dlink_encryption_type'] = 0
        
        return min(vendor_score, 1.0)
    
    def _analyze_file_command(self, file_path: str, results: Dict) -> float:
        """Analyze file command output for encryption indicators"""
        file_score = 0.0
        
        try:
            result = subprocess.run(['file', '-b', file_path], 
                                  capture_output=True, text=True, check=True)
            file_output = result.stdout.strip().lower()
            results['file_magic_analysis']['file_command_output'] = file_output
            
            # File command analysis
            encryption_indicators = [
                'encrypted', 'openssl enc', 'gpg encrypted', 'password protected',
                'salted', 'cipher', 'aes', 'des', 'rsa encrypted'
            ]
            
            for indicator in encryption_indicators:
                if indicator in file_output:
                    results['encryption_indicators'].append(f'file_command_{indicator}')
                    file_score += 0.7
            
            # Check for "data" classification which could indicate encryption
            if file_output == 'data' or 'data' == file_output.split(',')[0].strip():
                file_score += 0.3  # Medium confidence - could be encrypted or just binary
                results['encryption_indicators'].append('file_command_reports_generic_data')
            
        except Exception as e:
            results['file_magic_analysis']['file_command_error'] = str(e)
        
        return min(file_score, 1.0)
    
    def _analyze_binwalk_signatures(self, file_path: str, results: Dict) -> float:
        """Analyze binwalk signatures for encryption indicators"""
        binwalk_score = 0.0
        
        try:
            result = subprocess.run(['binwalk', '-y', 'encrypt', file_path], 
                                  capture_output=True, text=True, check=True)
            binwalk_output = result.stdout.lower()
            
            # Look for encryption-related signatures
            encryption_sigs = ['encrypt', 'cipher', 'aes', 'des', 'rsa', 'ssl', 'tls']
            detected_sigs = []
            
            for sig in encryption_sigs:
                if sig in binwalk_output:
                    detected_sigs.append(sig)
                    binwalk_score += 0.4
            
            results['file_magic_analysis']['binwalk_encryption_signatures'] = detected_sigs
            
            # Check for QNAP encryption
            qnap_result = subprocess.run(['binwalk', '-y', 'qnap encrypted', file_path], 
                                       capture_output=True, text=True, check=True)
            if 'qnap encrypted firmware footer' in qnap_result.stdout.lower():
                results['vendor_encryption'].append('qnap_encrypted')
                binwalk_score += 0.9  # High confidence for vendor encryption
            
            # Store full binwalk output for AMI and other detection
            full_binwalk_result = subprocess.run(['binwalk', file_path], 
                                                capture_output=True, text=True, check=True)
            results['file_magic_analysis']['full_binwalk_output'] = full_binwalk_result.stdout
            
            # Check for AMI EFI capsule detection
            if 'ami' in full_binwalk_result.stdout.lower() and 'efi' in full_binwalk_result.stdout.lower() and 'capsule' in full_binwalk_result.stdout.lower():
                results['vendor_encryption'].append('uefi_ami_capsule')
                results['file_magic_analysis']['ami_capsule_detected'] = True
                binwalk_score += 0.8  # High confidence for AMI capsule
            else:
                results['file_magic_analysis']['ami_capsule_detected'] = False
            
            # Also check for compression vs encryption signatures ratio
            comp_result = subprocess.run(['binwalk', '-y', 'compress', file_path], 
                                       capture_output=True, text=True, check=True)
            compress_count = len(comp_result.stdout.split('\n')) - 1
            encrypt_count = len(detected_sigs)
            
            if encrypt_count > compress_count and encrypt_count > 2:
                binwalk_score += 0.3
                results['encryption_indicators'].append('more_encryption_than_compression_signatures')
                
        except Exception:
            # Binwalk failed, try general signature scan
            try:
                result = subprocess.run(['binwalk', file_path], 
                                      capture_output=True, text=True, check=True)
                output_lines = result.stdout.split('\n')
                results['file_magic_analysis']['full_binwalk_output'] = result.stdout
                
                # Check for QNAP in general binwalk output
                for line in output_lines:
                    if 'qnap encrypted' in line.lower():
                        results['vendor_encryption'].append('qnap_encrypted')
                        binwalk_score += 0.9
                        break
                
                # Check for AMI EFI capsule in general output
                full_output_lower = result.stdout.lower()
                if 'ami' in full_output_lower and 'efi' in full_output_lower and 'capsule' in full_output_lower:
                    results['vendor_encryption'].append('uefi_ami_capsule')
                    results['file_magic_analysis']['ami_capsule_detected'] = True
                    binwalk_score += 0.8
                else:
                    results['file_magic_analysis']['ami_capsule_detected'] = False
                
                # Look for very few signatures (possible encryption indicator)
                significant_sigs = [line for line in output_lines if line.strip() and not line.startswith('DECIMAL')]
                if len(significant_sigs) < 3:
                    binwalk_score += 0.4
                    results['encryption_indicators'].append('very_few_binwalk_signatures')
                    
            except Exception as e:
                results['file_magic_analysis']['binwalk_error'] = str(e)
                results['file_magic_analysis']['ami_capsule_detected'] = False
        
        return min(binwalk_score, 1.0)
    
    def _analyze_string_density(self, file_path: str, results: Dict) -> float:
        """Analyze string density - encrypted files have fewer readable strings"""
        string_score = 0.0
        
        try:
            # Get strings from file
            strings_result = subprocess.run(['strings', file_path], 
                                          capture_output=True, text=True, check=True)
            strings_list = [s.strip() for s in strings_result.stdout.split('\n') if s.strip()]
            
            # Calculate string density
            file_size = os.path.getsize(file_path)
            string_bytes = sum(len(s) for s in strings_list)
            string_density = string_bytes / file_size if file_size > 0 else 0
            
            results['file_magic_analysis']['string_density'] = string_density
            results['file_magic_analysis']['total_strings'] = len(strings_list)
            
            # String density analysis
            if string_density < 0.01:  # Less than 1% readable strings
                string_score += 0.6
                results['encryption_indicators'].append('very_low_string_density')
            elif string_density < 0.05:  # Less than 5% readable strings  
                string_score += 0.3
                results['encryption_indicators'].append('low_string_density')
            
            # Check for meaningful strings vs random-looking strings
            meaningful_strings = 0
            for s in strings_list[:100]:  # Check first 100 strings
                if len(s) > 4 and any(word in s.lower() for word in ['linux', 'root', 'bin', 'etc', 'usr', 'var']):
                    meaningful_strings += 1
            
            meaningful_ratio = meaningful_strings / min(len(strings_list), 100)
            if meaningful_ratio < 0.1:  # Less than 10% meaningful strings
                string_score += 0.4
                results['encryption_indicators'].append('low_meaningful_string_ratio')
                
        except Exception as e:
            results['file_magic_analysis']['string_analysis_error'] = str(e)
        
        return min(string_score, 1.0)
    
    def _enhanced_entropy_analysis(self, file_path: str, results: Dict) -> float:
        """Enhanced entropy analysis with sectional analysis"""
        entropy_score = 0.0
        
        try:
            # Get overall entropy first
            ent_result = subprocess.run(['ent', file_path], 
                                      capture_output=True, text=True, check=True)
            ent_output = ent_result.stdout
            
            # Parse entropy value
            entropy_match = re.search(r'Entropy = ([\d.]+) bits per byte', ent_output)
            if entropy_match:
                entropy_value = float(entropy_match.group(1))
                results['file_magic_analysis']['overall_entropy'] = entropy_value
                
                # Entropy classification
                if entropy_value > 7.9:
                    entropy_score += 0.9  # Very likely encrypted
                    results['encryption_indicators'].append('very_high_entropy_likely_encrypted')
                elif entropy_value > 7.5:
                    entropy_score += 0.6  # Possibly encrypted or highly compressed
                    results['encryption_indicators'].append('high_entropy_possibly_encrypted')
                elif entropy_value > 6.5:
                    entropy_score += 0.3  # Likely compressed
                    results['encryption_indicators'].append('medium_entropy_likely_compressed')
            
            # Sectional entropy analysis
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # Only for files > 1MB
                sections_entropy = self._analyze_sectional_entropy(file_path)
                results['file_magic_analysis']['sectional_entropy'] = sections_entropy
                
                # Check entropy variance across sections
                if sections_entropy:
                    entropies = [s['entropy'] for s in sections_entropy if s.get('entropy')]
                    if entropies:
                        entropy_variance = max(entropies) - min(entropies)
                        if entropy_variance < 0.5:  # Very consistent high entropy
                            entropy_score += 0.4
                            results['encryption_indicators'].append('consistent_high_entropy_across_sections')
            
        except Exception as e:
            results['file_magic_analysis']['entropy_error'] = str(e)
        
        return min(entropy_score, 1.0)
    
    def _analyze_sectional_entropy(self, file_path: str) -> List[Dict]:
        """Analyze entropy in different sections of the file"""
        sections = []
        try:
            file_size = os.path.getsize(file_path)
            section_size = min(1024 * 1024, file_size // 5)  # 5 sections or 1MB max
            
            with open(file_path, 'rb') as f:
                for i in range(5):
                    offset = i * section_size
                    f.seek(offset)
                    data = f.read(section_size)
                    
                    if data:
                        # Calculate entropy for this section
                        byte_counts = [0] * 256
                        for byte in data:
                            byte_counts[byte] += 1
                        
                        entropy = 0.0
                        length = len(data)
                        for count in byte_counts:
                            if count > 0:
                                probability = count / length
                                entropy -= probability * math.log2(probability)
                        
                        sections.append({
                            'offset': offset,
                            'size': len(data),
                            'entropy': entropy
                        })
        except Exception:
            pass
        
        return sections
    
    def _calculate_encryption_score(self, factors: Dict[str, float]) -> float:
        """Calculate weighted encryption score using factor weighting"""
        # Weighting based on reliability of each factor
        weights = {
            'vendor_pattern_factor': 0.25,      # Highest weight - very reliable
            'magic_bytes_factor': 0.20,        # High weight - reliable signatures
            'file_command_factor': 0.15,       # Medium-high weight
            'binwalk_signature_factor': 0.15,  # Medium-high weight  
            'entropy_factor': 0.15,            # Medium weight - can be misleading
            'string_density_factor': 0.10      # Lower weight - supporting evidence
        }
        
        weighted_score = sum(factors[factor] * weights[factor] for factor in weights)
        return min(weighted_score, 1.0)
    
    def _classify_encryption_probability(self, score: float) -> str:
        """Classify encryption probability based on thresholds"""
        if score >= 0.8:
            return 'very_high_definitely_encrypted'
        elif score >= 0.6:
            return 'high_likely_encrypted'
        elif score >= 0.4:
            return 'medium_possibly_encrypted'
        elif score >= 0.2:
            return 'low_probably_compressed_or_binary'
        else:
            return 'very_low_likely_unencrypted'
    
    def _check_gpg_encryption(self, file_path: str) -> bool:
        """Check for GPG encryption using gpg --list-packets"""
        try:
            result = subprocess.run(['gpg', '--list-packets', file_path], 
                                  capture_output=True, text=True, check=True)
            return 'compressed packet:' in result.stdout
        except:
            return False