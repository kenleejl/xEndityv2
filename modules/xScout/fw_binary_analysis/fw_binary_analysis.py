# This script does checking of the given firmware file before extraction
# It gathers information crucial towards defining the extraction strategy
# 1. Check file format (data, vmdk, ubi, ...)
# 2. Check hashing - verify integrity, check dupes, db correlation
# 3. Check encryption - entropy check (), gpg check 
# 	|
# 	|
# 	------- Check vendor specific encryption - hex signature inspection

# 5. Check printable strings - identify firmware type, archi, vendor name, libs etc
# 6. find extraction points within firmware binary
# 8. file metadata - space, protections, dates
# 9. byte pattern visualization - help detech headers, patterns, anomalies


#!/usr/bin/env python3
"""
Firmware Binary Analyzer
"""

import os
import sys
import hashlib
import subprocess
import re
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import argparse
import glob
from byte_pattern_visualizer import BytePatternVisualizer
from encryption_detection import EncryptionDetector
from entropy_checker import EntropyChecker
from extraction_point_finder import ExtractionPointFinder
from file_format_checker import FileFormatChecker
from hash_checker import HashChecker
from metadata_analyzer import MetadataAnalyzer
from string_analyzer import StringAnalyzer


@dataclass
class AnalysisResult:
    """Data class to store analysis results"""
    file_path: str
    file_format: Dict[str, Any]
    hashes: Dict[str, str]
    entropy: Dict[str, Any]
    encryption: Dict[str, Any]
    strings_analysis: Dict[str, Any]
    extraction_points: Dict[str, Any]
    metadata: Dict[str, Any]
    visualization: Dict[str, Any]

class FirmwareBinaryAnalyzer:
    """Main analyzer class that orchestrates all checks"""
    
    def __init__(self):
        self.format_checker = FileFormatChecker()
        self.hash_checker = HashChecker()
        self.entropy_checker = EntropyChecker()
        self.encryption_detector = EncryptionDetector()
        self.string_analyzer = StringAnalyzer()
        self.extraction_finder = ExtractionPointFinder()
        self.metadata_analyzer = MetadataAnalyzer()
        self.pattern_visualizer = BytePatternVisualizer()
    
    def analyze_firmware(self, file_path: str) -> AnalysisResult:
        """Perform complete fw_binary_analysis"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Create output directory based on firmware name
        firmware_name = os.path.splitext(os.path.basename(file_path))[0]
        output_dir = os.path.join(os.path.dirname(file_path), f"{firmware_name}_analysis")
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"[*] Starting fw_binary_analysis of: {file_path}")
        print(f"[*] Output directory: {output_dir}")
        
        # Clean up any old format files
        old_files = glob.glob(os.path.join(output_dir, f"{firmware_name}.bin_*"))
        for old_file in old_files:
            try:
                os.remove(old_file)
            except:
                pass
        
        # Perform all checks
        print("[*] Checking file format...")
        file_format = self.format_checker.check_format(file_path)
        
        print("[*] Calculating hashes...")
        hashes = self.hash_checker.calculate_hashes(file_path)
        
        print("[*] Analyzing entropy...")
        entropy = self.entropy_checker.analyze_entropy(file_path)
        
        print("[*] Detecting encryption...")
        encryption = self.encryption_detector.detect_encryption(file_path)
        
        print("[*] Analyzing strings...")
        strings_analysis = self.string_analyzer.analyze_strings(file_path)
        
        print("[*] Finding extraction points...")
        extraction_points = self.extraction_finder.find_extraction_points(file_path)
        
        print("[*] Analyzing metadata...")
        metadata = self.metadata_analyzer.analyze_metadata(file_path)
        
        print("[*] Generating byte pattern visualization...")
        visualization = self.pattern_visualizer.visualize_patterns(file_path)
        
        # Create analysis result
        result = AnalysisResult(
            file_path=file_path,
            file_format=file_format,
            hashes=hashes,
            entropy=entropy,
            encryption=encryption,
            strings_analysis=strings_analysis,
            extraction_points=extraction_points,
            metadata=metadata,
            visualization=visualization
        )
        
        # Generate extraction strategy
        strategy = self.generate_extraction_strategy(result)
        
        # Save results to output directory
        output_json = os.path.join(output_dir, "analysis_results.json")
        self.save_results(result, output_json)
        
        # Generate and save summary
        summary = self.generate_summary(result, strategy)
        summary_file = os.path.join(output_dir, "analysis_summary.txt")
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        print("[+] Analysis completed!")
        return result
    
    def generate_summary(self, result: AnalysisResult, strategy: Dict[str, Any]) -> str:
        """Generate a comprehensive summary of the analysis results"""
        summary = []
        
        # Add header
        summary.append("=" * 80)
        summary.append(f"FIRMWARE BINARY ANALYSIS SUMMARY")
        summary.append("=" * 80)
        
        # Basic info
        summary.append(f"\nFILE INFORMATION:")
        summary.append(f"Filename: {os.path.basename(result.file_path)}")
        summary.append(f"Path: {result.file_path}")
        summary.append(f"Size: {result.metadata.get('file_size_human', 'Unknown')}")
        summary.append(f"Permissions: {result.metadata.get('permissions', 'Unknown')}")
        modification_time = result.metadata.get('modification_time')
        if modification_time:
            import datetime
            mod_time = datetime.datetime.fromtimestamp(modification_time).strftime('%Y-%m-%d %H:%M:%S')
            summary.append(f"Last Modified: {mod_time}")
        
        # File format
        summary.append(f"\nFILE FORMAT:")
        summary.append(f"Type: {result.file_format.get('raw_output', 'Unknown')}")
        summary.append(f"MIME: {result.file_format.get('mime_type', 'Unknown')}")
        if result.file_format.get('architecture'):
            summary.append(f"Architecture: {result.file_format.get('architecture')}")
        
        # Hashes
        summary.append(f"\nHASHES:")
        summary.append(f"MD5: {result.hashes.get('md5', 'Not calculated')}")
        summary.append(f"SHA1: {result.hashes.get('sha1', 'Not calculated')}")
        summary.append(f"SHA256: {result.hashes.get('sha256', 'Not calculated')}")
        
        # Entropy analysis - simplified
        summary.append(f"\nENTROPY ANALYSIS:")
        summary.append(f"Value: {result.entropy.get('entropy_value', 'Unknown')} bits per byte")
        
        # Encryption detection - streamlined
        summary.append(f"\nENCRYPTION ANALYSIS:")
        enc_prob = result.encryption.get('encryption_probability', 'unknown')
        enc_conf = result.encryption.get('encryption_confidence', 0.0)
        summary.append(f"Probability: {enc_prob} (confidence: {enc_conf:.2f})")
        
        # Show all factors with their weights for transparency
        enc_factors = result.encryption.get('encryption_factors', {})
        if enc_factors:
            summary.append(f"Factor analysis:")
            
            # Define reasoning for each factor
            factor_reasoning = {
                'entropy_factor': 'high entropy could indicate encryption or compression',
                'magic_bytes_factor': 'encryption signatures found in file header',
                'vendor_pattern_factor': 'vendor-specific encryption patterns detected',
                'file_command_factor': 'file command reports encryption indicators',
                'binwalk_signature_factor': 'extractable content found (suggests compression over encryption)',
                'string_density_factor': 'low readable strings could indicate encryption'
            }
            
            # Show each factor with score and reasoning
            for factor, score in enc_factors.items():
                factor_name = factor.replace('_factor', '').replace('_', ' ').title()
                reasoning = factor_reasoning.get(factor, 'analysis factor')
                
                # Adjust reasoning based on score level
                if factor == 'binwalk_signature_factor' and score > 0.5:
                    reasoning = 'many extractable components found (indicates compression, not encryption)'
                elif factor == 'entropy_factor':
                    if score > 0.8:
                        reasoning = 'very high entropy (likely encrypted or highly compressed)'
                    elif score > 0.5:
                        reasoning = 'high entropy (could indicate encryption or compression)'
                    else:
                        reasoning = 'moderate entropy (likely uncompressed or lightly compressed)'
                elif factor == 'string_density_factor':
                    if score > 0.5:
                        reasoning = 'very few readable strings (encryption indicator)'
                    elif score > 0.3:
                        reasoning = 'low readable strings (possible encryption)'
                    else:
                        reasoning = 'normal amount of readable strings'
                elif factor == 'vendor_pattern_factor' and score == 0:
                    reasoning = 'no vendor-specific encryption patterns detected'
                elif factor == 'magic_bytes_factor' and score == 0:
                    reasoning = 'no encryption signatures in file header'
                elif factor == 'file_command_factor' and score == 0:
                    reasoning = 'file command shows no encryption indicators'
                
                summary.append(f"  {factor_name}: {score:.2f}/1.0 ({reasoning})")
        
        # Vendor-specific patterns - only if detected
        if result.encryption.get('vendor_encryption'):
            summary.append(f"Vendor encryption: {', '.join(result.encryption.get('vendor_encryption'))}")
            
            # Show D-Link encryption type if detected
            dlink_type = result.encryption.get('dlink_encryption_type', 0)
            if dlink_type > 0:
                dlink_type_desc = {1: "SHRS", 2: "encrpted_img"}
                summary.append(f"D-Link type: {dlink_type} ({dlink_type_desc.get(dlink_type, 'unknown')})")
            
            # Show AMI capsule detection if found
            if result.encryption.get('file_magic_analysis', {}).get('ami_capsule_detected'):
                summary.append(f"AMI capsule: Detected (specialized UEFI firmware)")
        
        # Magic bytes analysis - only if significant
        magic_analysis = result.encryption.get('file_magic_analysis', {})
        if magic_analysis.get('encryption_signatures'):
            summary.append(f"Encryption signatures: {', '.join(magic_analysis['encryption_signatures'])}")
        
        # Vendor Pattern Detection Summary
        summary.append(f"\nVENDOR PATTERN DETECTION:")
        
        # Compile all vendor detection results
        vendor_results = {}
        
        # From encryption detection
        detected_vendors = result.encryption.get('vendor_encryption', [])
        vendor_results['AVM'] = False  # Initialize as false, will be updated from string analysis
        vendor_results['Android APK'] = False  # Initialize as false
        vendor_results['Android OTA'] = any('android_ota' in v.lower() for v in detected_vendors)
        vendor_results['Buffalo'] = any('buffalo' in v.lower() for v in detected_vendors)
        vendor_results['D-Link SHRS'] = any('dlink_shrs_type1' in v.lower() for v in detected_vendors)
        vendor_results['D-Link EncImg'] = any('dlink_encrypted_img_type2' in v.lower() for v in detected_vendors)
        vendor_results['D-Link Generic'] = any('dlink' in v.lower() and 'type' not in v.lower() for v in detected_vendors)
        vendor_results['DJI'] = any('dji' in v.lower() for v in detected_vendors)
        vendor_results['EnGenius'] = any('engenius' in v.lower() for v in detected_vendors)
        vendor_results['GPG'] = result.encryption.get('gpg_detected', False)
        vendor_results['OpenSSL'] = any('openssl' in v.lower() for v in detected_vendors)
        vendor_results['QNAP'] = any('qnap' in v.lower() for v in detected_vendors)
        vendor_results['Supermicro BMC'] = False  # Initialize as false
        vendor_results['UEFI/BIOS'] = False  # Initialize as false
        vendor_results['UEFI AMI Capsule'] = any('uefi_ami_capsule' in v.lower() for v in detected_vendors)
        vendor_results['Windows PE'] = False  # Initialize as false
        
        # From string analysis
        string_vendors = result.strings_analysis.get('vendor_detected', [])
        for vendor_info in string_vendors:
            category = vendor_info.get('category', '')
            if 'avm' in category:
                vendor_results['AVM'] = True
            elif 'supermicro_bmc' in category or 'bmc' in category:
                vendor_results['Supermicro BMC'] = True
            elif 'uefi_bios' in category:
                vendor_results['UEFI/BIOS'] = True
        
        # From file format detection
        detected_formats = result.file_format.get('detected_formats', [])
        if 'OpenSSL_encrypted' in detected_formats:
            vendor_results['OpenSSL'] = True
        if 'Windows_PE' in detected_formats:
            vendor_results['Windows PE'] = True
        if 'APK' in detected_formats:
            vendor_results['Android APK'] = True
        
        # Display results in checklist format
        for vendor, detected in sorted(vendor_results.items()):
            status = "✓" if detected else "✗"
            summary.append(f"  {vendor}: {status}")
        
        # Add any others that weren't explicitly checked
        additional_vendors = []
        for vendor in detected_vendors:
            vendor_clean = vendor.replace('_', ' ').title()
            if not any(vendor_clean.lower() in existing.lower() for existing in vendor_results.keys()):
                additional_vendors.append(vendor_clean)
        
        if additional_vendors:
            summary.append(f"  Additional patterns: {', '.join(additional_vendors)}")
        
        # String analysis - simplified
        summary.append(f"\nSTRING ANALYSIS:")
        summary.append(f"Total strings: {result.strings_analysis.get('total_strings', 0)}")
        
        if result.strings_analysis.get('vendor_detected'):
            summary.append(f"Detected patterns:")
            for vendor in result.strings_analysis.get('vendor_detected', []):
                category = vendor.get('category', '')
                matches = vendor.get('matches', [])
                if matches:
                    summary.append(f"  - {category}: {len(matches)} matches")
        
        if result.strings_analysis.get('architecture_hints'):
            summary.append(f"Architecture hints: {', '.join(result.strings_analysis.get('architecture_hints'))}")
        
        # Extraction points - streamlined
        summary.append(f"\nEXTRACTION ANALYSIS:")
        if result.extraction_points.get('filesystems_detected'):
            summary.append(f"Filesystems:")
            for fs in result.extraction_points.get('filesystems_detected'):
                summary.append(f"  - {fs}")
        
        if result.extraction_points.get('compressed_sections'):
            summary.append(f"Compressed sections: {len(result.extraction_points.get('compressed_sections', []))}")
        
        # Show only first 5 important offsets, not all
        extraction_offsets = result.extraction_points.get('extraction_offsets', [])
        if extraction_offsets:
            # Prioritize signatures based on full system emulation requirements
            def get_signature_priority(description):
                desc_lower = description.lower()
                
                # Priority 1: Root Filesystem ⭐⭐⭐⭐⭐ (Critical - IS the operating system)
                priority_1_rootfs = [
                    'squashfs filesystem', 'jffs2 filesystem', 'ubifs', 'yaffs',
                    'ext2 filesystem', 'ext3 filesystem', 'ext4 filesystem',
                    'cramfs filesystem', 'romfs filesystem', 'minix filesystem'
                ]
                
                # Priority 2: Linux Kernel ⭐⭐⭐⭐ (Critical - needed to boot rootfs)
                priority_2_kernel = [
                    'vmlinux', 'zimage', 'bzimage', 'uimage', 'kernel',
                    'linux kernel', 'compressed kernel','kernel binary'
                ]
                
                # Priority 3: U-Boot Bootloader ⭐⭐⭐ (Important - boot params & hw init)
                priority_3_bootloader = [
                    'u-boot', 'bootloader', 'trx firmware header', 'firmware header',
                    'uboot', 'boot', 'loader'
                ]
                
                # Priority 4: Device Tree/Hardware Config ⭐⭐⭐ (Important - hw description)
                priority_4_hardware = [
                    'flattened device tree', 'device tree', 'fdt', 'dtb',
                    'hardware config', 'board config'
                ]
                
                # Priority 5: Network/Init Configuration ⭐⭐ (Useful for emulation setup)
                priority_5_config = [
                    'certificate', 'public key', 'private key', 'config',
                    'network config', 'init', 'startup'
                ]
                
                # Priority 6: Compressed Data ⭐⭐ (May contain above components)
                priority_6_compressed = [
                    'lzma compressed', 'gzip compressed', 'bzip2 compressed',
                    'xz compressed', 'zip archive', 'tar archive', 'compressed data'
                ]
                
                # Priority 7: Additional Filesystems ⭐ (May contain additional components)
                priority_7_additional = [
                    'filesystem', 'partition', 'disk image', 'archive'
                ]
                
                # Check priorities (higher number = higher priority)
                if any(pattern in desc_lower for pattern in priority_1_rootfs):
                    return 7  # Highest priority
                elif any(pattern in desc_lower for pattern in priority_2_kernel):
                    return 6
                elif any(pattern in desc_lower for pattern in priority_3_bootloader):
                    return 5
                elif any(pattern in desc_lower for pattern in priority_4_hardware):
                    return 4
                elif any(pattern in desc_lower for pattern in priority_5_config):
                    return 3
                elif any(pattern in desc_lower for pattern in priority_6_compressed):
                    return 2
                elif any(pattern in desc_lower for pattern in priority_7_additional):
                    return 1
                else:
                    return 0  # Not important for emulation
            
            # Separate signatures by priority and sort
            prioritized_offsets = []
            for offset in extraction_offsets:
                priority = get_signature_priority(offset['description'])
                if priority > 0:  # Only include emulation-relevant signatures
                    prioritized_offsets.append((priority, offset))
            
            # Sort by priority (highest first), then by offset position
            prioritized_offsets.sort(key=lambda x: (-x[0], x[1]['offset']))
            
            # Count by priority levels for display
            priority_counts = {}
            for priority, _ in prioritized_offsets:
                priority_counts[priority] = priority_counts.get(priority, 0) + 1
            
            # Take top 5 signatures for display
            top_signatures = prioritized_offsets[:5]
            
            # Create priority labels
            priority_labels = {
                7: "Priority 1 - Root Filesystem",
                6: "Priority 2 - Linux Kernel", 
                5: "Priority 3 - Bootloader",
                4: "Priority 4 - Hardware Config",
                3: "Priority 5 - Network/Config",
                2: "Priority 6 - Compressed Data",
                1: "Priority 7 - Additional FS"
            }
            
            if top_signatures:
                emulation_ready = len([p for p, _ in prioritized_offsets if p >= 6])  # P1 + P2
                summary.append(f"\nEMULATION-READY SIGNATURES ({len(extraction_offsets)} total, {len(prioritized_offsets)} emulation-relevant, {emulation_ready} critical):")
                
                for priority, offset in top_signatures:
                    priority_symbol = "🔴" if priority >= 6 else "🟡" if priority >= 4 else "🟢"
                    summary.append(f"  {priority_symbol} {offset['offset']} (0x{offset['offset']:X}): {offset['description']}")
                
                if len(prioritized_offsets) > 5:
                    summary.append(f"  ... and {len(prioritized_offsets) - 5} more emulation-relevant signatures")
                
                # Show priority breakdown
                if priority_counts:
                    summary.append(f"\nEmulation Priority Breakdown:")
                    for priority in sorted(priority_counts.keys(), reverse=True):
                        count = priority_counts[priority]
                        label = priority_labels.get(priority, f"Priority {priority}")
                        symbol = "🔴" if priority >= 6 else "🟡" if priority >= 4 else "🟢"
                        summary.append(f"  {symbol} {label}: {count} found")
            else:
                summary.append(f"\nEMULATION-READY SIGNATURES: None found (may require manual extraction)")
                summary.append(f"Total signatures: {len(extraction_offsets)} (check manually for emulation components)")
        
        # Extraction strategy
        summary.append(f"\nEXTRACTION STRATEGY:")
        summary.append(f"Confidence: {strategy.get('confidence', 'unknown')}")
        
        # Show deep analysis optimization status
        if strategy.get('disable_deep_analysis'):
            summary.append(f"Deep Analysis: DISABLED (optimization for {strategy.get('format_flags', {}).get('DISABLE_DEEP_ANALYSIS', 'file type')})")
        else:
            summary.append(f"Deep Analysis: ENABLED (full extraction pipeline)")
        
        if strategy.get('recommended_extractors'):
            summary.append(f"Recommended tools: {', '.join(strategy.get('recommended_extractors'))}")
        
        if strategy.get('format_flags'):
            flags = [flag for flag, value in strategy.get('format_flags').items() if value == 1 and flag not in ['DISABLE_DEEP_ANALYSIS']]
            if flags:
                summary.append(f"Detected formats: {', '.join(flags)}")
        
        # Next steps - fix contradictory logic
        summary.append(f"\nRECOMMENDED NEXT STEPS:")
        encryption_prob = result.encryption.get('encryption_probability', 'unknown')
        
        # Handle deep analysis disabled cases first
        if strategy.get('disable_deep_analysis'):
            disable_reason = None
            for handling in strategy.get('special_handling', []):
                if 'disable_deep_analysis_due_to_' in handling:
                    disable_reason = handling.replace('disable_deep_analysis_due_to_', '').replace('_', ' ')
                    break
            
            summary.append(f"1. Use specialized analyzer for {disable_reason or 'this file type'}")
            summary.append(f"2. Skip expensive extraction operations (optimization)")
            if 'script_analyzer' in strategy.get('recommended_extractors', []):
                summary.append(f"3. Perform static code analysis")
            elif 'windows_exe_extractor' in strategy.get('recommended_extractors', []):
                summary.append(f"3. Use PE analysis tools")
            elif 'apk_analyzer' in strategy.get('recommended_extractors', []):
                summary.append(f"3. Use APK analysis tools")
        elif 'very_high_definitely_encrypted' in encryption_prob or 'high_likely_encrypted' in encryption_prob:
            summary.append(f"1. Attempt decryption before extraction")
            if strategy.get('recommended_extractors'):
                main_extractor = strategy['recommended_extractors'][0]
                summary.append(f"2. Use {main_extractor} for specialized extraction")
        elif 'DEFAULT_EXTRACTION' in strategy.get('format_flags', {}):
            summary.append(f"1. Use standard extraction tools (binwalk, unblob)")
            summary.append(f"2. Analyze extracted filesystems and components")
        else:
            if strategy.get('recommended_extractors'):
                main_extractor = strategy['recommended_extractors'][0]
                summary.append(f"1. Use {main_extractor} for specialized extraction")
            summary.append(f"2. Analyze extracted contents for hidden components")
        
        return "\n".join(summary)
        
    def generate_extraction_strategy(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate extraction strategy based on analysis results"""
        strategy = {
            'recommended_extractors': [],
            'extraction_order': [],
            'special_handling': [],
            'format_flags': {},
            'confidence': 'unknown',
            'disable_deep_analysis': False  # New optimization flag
        }
        
        # Get analysis components
        file_format = result.file_format
        encryption = result.encryption
        raw_output = file_format.get('raw_output', '').lower()
        
        # Deep Analysis Optimization - Skip expensive operations for certain file types
        disable_deep_triggers = []
        
        # Check file formats that don't benefit from deep extraction
        detected_formats = file_format.get('detected_formats', [])
        if 'Windows_PE' in detected_formats:
            disable_deep_triggers.append('windows_executable')
            strategy['disable_deep_analysis'] = True
        if 'APK' in detected_formats:
            disable_deep_triggers.append('android_apk')
            strategy['disable_deep_analysis'] = True
        
        # Check for script files
        script_formats = ['Script_Perl', 'Script_PHP', 'Script_Python', 'Script_Shell']
        detected_scripts = [fmt for fmt in script_formats if fmt in detected_formats]
        if detected_scripts:
            disable_deep_triggers.append(f'script_file_{detected_scripts[0]}')
            strategy['disable_deep_analysis'] = True
        
        # Additional file types that should disable deep analysis
        # Single ELF files (not firmware images) - check if file is just an ELF with no other signatures
        if 'ELF' in detected_formats and len(detected_formats) == 1:
            # Check if this is a standalone ELF binary vs firmware containing ELF
            file_size = result.metadata.get('file_size', 0)
            if file_size < 50 * 1024 * 1024:  # Less than 50MB, likely standalone binary
                disable_deep_triggers.append('standalone_elf_binary')
                strategy['disable_deep_analysis'] = True
        
        # Very small files that are unlikely to be firmware
        file_size = result.metadata.get('file_size', 0)
        if file_size < 1024:  # Less than 1KB
            disable_deep_triggers.append('very_small_file')
            strategy['disable_deep_analysis'] = True
        
        # Log why deep analysis is disabled
        if strategy['disable_deep_analysis']:
            strategy['special_handling'].append(f'disable_deep_analysis_due_to_{disable_deep_triggers[0]}')
            strategy['format_flags']['DISABLE_DEEP_ANALYSIS'] = 1
            # Store the specific reason for debugging
            strategy['deep_analysis_disabled_reason'] = disable_deep_triggers[0]
        
        # Encrypted/Vendor-Specific Format Detection
        if encryption.get('vendor_encryption'):
            for vendor in encryption['vendor_encryption']:
                if 'dlink_shrs_type1' in vendor:
                    strategy['format_flags']['DLINK_ENC_DETECTED'] = 1  # Type 1: SHRS
                    strategy['recommended_extractors'].append('dlink_decryptor')
                    strategy['special_handling'].append('dlink_shrs_encryption')
                elif 'dlink_encrypted_img_type2' in vendor:
                    strategy['format_flags']['DLINK_ENC_DETECTED'] = 2  # Type 2: encrpted_img  
                    strategy['recommended_extractors'].append('dlink_decryptor')
                    strategy['special_handling'].append('dlink_encrypted_img_encryption')
                elif 'dlink' in vendor:  # Fallback for generic D-Link detection
                    strategy['format_flags']['DLINK_ENC_DETECTED'] = 1
                    strategy['recommended_extractors'].append('dlink_decryptor')
                elif 'buffalo' in vendor:
                    strategy['format_flags']['BUFFALO_ENC_DETECTED'] = 1
                    strategy['recommended_extractors'].append('buffalo_decryptor')
                elif 'engenius' in vendor:
                    strategy['format_flags']['ENGENIUS_ENC_DETECTED'] = 1
                    strategy['recommended_extractors'].append('engenius_decryptor')
                elif 'android_ota' in vendor:
                    strategy['format_flags']['ANDROID_OTA'] = 1
                    strategy['recommended_extractors'].append('android_ota_extractor')
                elif 'dji' in vendor:
                    strategy['format_flags']['DJI_PRAK_DETECTED'] = 1
                    strategy['recommended_extractors'].append('dji_extractor')
                elif 'qnap' in vendor:
                    strategy['format_flags']['QNAP_ENC_DETECTED'] = 1
                    strategy['recommended_extractors'].append('qnap_decryptor')
                elif 'uefi_ami_capsule' in vendor:
                    strategy['format_flags']['UEFI_AMI_CAPSULE'] = 1
                    strategy['recommended_extractors'].append('uefi_ami_capsule_extractor')
                    strategy['special_handling'].append('ami_capsule_specific_extraction')
        
        # GPG Compression Detection
        if encryption.get('gpg_detected'):
            strategy['format_flags']['GPG_COMPRESS'] = 1
            strategy['recommended_extractors'].append('gpg_decompressor')
        
        # File Format Based Detection
        
        # OpenSSL encryption detection
        if 'OpenSSL_encrypted' in detected_formats:
            strategy['format_flags']['OPENSSL_ENC_DETECTED'] = 1
            strategy['recommended_extractors'].append('openssl_decryptor')
            strategy['special_handling'].append('foscam_firmware_encryption')
        
        # Windows executable detection
        if 'Windows_PE' in detected_formats:
            strategy['format_flags']['WINDOWS_EXE'] = 1
            strategy['recommended_extractors'].append('windows_exe_extractor')
        
        # Script file detection
        if detected_scripts:
            strategy['recommended_extractors'].append('script_analyzer')
        
        # APK detection
        if 'APK' in detected_formats:
            strategy['format_flags']['ANDROID_APK'] = 1
            strategy['recommended_extractors'].append('apk_analyzer')
        
        if 'vmware4 disk image' in raw_output or 'vmdk' in raw_output:
            strategy['format_flags']['VMDK_DETECTED'] = 1
            strategy['recommended_extractors'].append('vmdk_extractor')
        elif 'qemu qcow' in raw_output or 'qcow' in raw_output:
            strategy['format_flags']['QCOW_DETECTED'] = 1
            strategy['recommended_extractors'].append('qcow_mounter')
        elif 'u-boot legacy uimage' in raw_output or 'u-boot' in raw_output:
            # U-Boot images need special handling - not just default extraction
            strategy['format_flags']['UBOOT_IMAGE'] = 1
            strategy['recommended_extractors'].append('uboot_extractor')
            strategy['special_handling'].append('uboot_kernel_extraction')
        elif 'ubi image' in raw_output or 'ubifs' in raw_output:
            strategy['format_flags']['UBI_IMAGE'] = 1
            strategy['recommended_extractors'].append('ubi_extractor')
        elif 'jffs2 filesystem' in raw_output:
            strategy['format_flags']['JFFS2_DETECTED'] = 1
            strategy['recommended_extractors'].append('filesystem_mounter')
            strategy['special_handling'].append('filesystem_mount_instead_of_extract')
        elif 'ext2' in raw_output or 'ext3' in raw_output or 'ext4' in raw_output:
            strategy['format_flags']['EXT_IMAGE'] = 1
            strategy['recommended_extractors'].append('ext_mounter')
        elif 'bsd' in raw_output and 'ufs' in raw_output:
            strategy['format_flags']['BSD_UFS'] = 1
            strategy['recommended_extractors'].append('bsd_ufs_mounter')
        elif 'uefi' in raw_output or 'efi' in raw_output:
            # Check if it's specifically an AMI capsule first
            if encryption.get('file_magic_analysis', {}).get('ami_capsule_detected'):
                strategy['format_flags']['UEFI_AMI_CAPSULE'] = 1
                strategy['recommended_extractors'].append('uefi_ami_capsule_extractor')
                strategy['special_handling'].append('ami_capsule_specific_extraction')
            else:
                strategy['format_flags']['UEFI_DETECTED'] = 1
                strategy['recommended_extractors'].append('uefi_extractor')
        
        # Special ZIP handling
        if 'zip archive' in raw_output:
            # Check if it's encrypted Zyxel ZIP
            zip_entries = result.extraction_points.get('extraction_offsets', [])
            if any('zyxel' in str(entry).lower() for entry in zip_entries):
                strategy['format_flags']['ZYXEL_ZIP'] = 1
                strategy['recommended_extractors'].append('zyxel_zip_decryptor')
            else:
                strategy['recommended_extractors'].append('standard_archive_extractor')
        
        # String Analysis Based Detection
        vendor_detected = result.strings_analysis.get('vendor_detected', [])
        for vendor_info in vendor_detected:
            category = vendor_info.get('category', '')
            if 'uefi_bios' in category:
                strategy['format_flags']['UEFI_DETECTED'] = 1
                if 'uefi_extractor' not in strategy['recommended_extractors']:
                    strategy['recommended_extractors'].append('uefi_extractor')
            elif 'dji_patterns' in category:
                strategy['format_flags']['DJI_PRAK_DETECTED'] = 1
                if 'dji_extractor' not in strategy['recommended_extractors']:
                    strategy['recommended_extractors'].append('dji_extractor')
            elif 'avm' in category:
                strategy['format_flags']['AVM_DETECTED'] = 1
                strategy['special_handling'].append('avm_firmware_handling')
            elif 'supermicro_bmc' in category:
                strategy['format_flags']['BMC_ENC_DETECTED'] = 1
                if 'bmc_decryptor' not in strategy['recommended_extractors']:
                    strategy['recommended_extractors'].append('bmc_decryptor')
        
        # Check encryption probability for strategy decisions
        encryption_prob = result.encryption.get('encryption_probability', 'unknown')
        if 'very_high_definitely_encrypted' in encryption_prob or 'high_likely_encrypted' in encryption_prob:
            # Only suggest decryption if it's not a file type that skips deep analysis
            if not strategy['disable_deep_analysis']:
                strategy['special_handling'].append('likely_encrypted_needs_decryption')
        elif 'medium_possibly_encrypted' in encryption_prob:
            if not strategy['disable_deep_analysis']:
                strategy['special_handling'].append('possibly_encrypted_check_vendor_tools')
        
        # Check filesystems detected by binwalk
        filesystems = result.extraction_points.get('filesystems_detected', [])
        for fs in filesystems:
            fs_lower = fs.lower()
            if 'squashfs' in fs_lower:
                strategy['format_flags']['SQUASHFS_DETECTED'] = 1
            elif 'jffs2' in fs_lower:
                strategy['format_flags']['JFFS2_DETECTED'] = 1
                strategy['special_handling'].append('filesystem_mount_instead_of_extract')
                if 'filesystem_mounter' not in strategy['recommended_extractors']:
                    strategy['recommended_extractors'].append('filesystem_mounter')
            elif 'cramfs' in fs_lower:
                strategy['format_flags']['CRAMFS_DETECTED'] = 1
            elif 'romfs' in fs_lower:
                strategy['format_flags']['ROMFS_DETECTED'] = 1
        
        # Default extractors when NO specialized format detected
        if not strategy['recommended_extractors']:
            # Even for default extraction, respect the deep analysis flag
            if strategy['disable_deep_analysis']:
                strategy['recommended_extractors'] = ['basic_file_analyzer']
            else:
                strategy['recommended_extractors'] = ['unblob', 'binwalk']
            strategy['format_flags']['DEFAULT_EXTRACTION'] = 1
        
        # Set confidence based on detection results
        if strategy['format_flags']:
            specialized_flags = [k for k in strategy['format_flags'].keys() if k not in ['DEFAULT_EXTRACTION', 'DISABLE_DEEP_ANALYSIS']]
            if specialized_flags:
                strategy['confidence'] = 'high_specialized_format_detected'
            else:
                strategy['confidence'] = 'medium_default_extraction'
        else:
            strategy['confidence'] = 'low_no_format_detected'
        
        return strategy
    
    def save_results(self, result: AnalysisResult, output_file: str):
        """Save analysis results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(asdict(result), f, indent=2, default=str)
            print(f"[+] Results saved to: {output_file}")
        except Exception as e:
            print(f"[-] Failed to save results: {e}")


def main():
    parser = argparse.ArgumentParser(description='Firmware Binary Analyzer')
    parser.add_argument('firmware_file', help='Path to firmware file to analyze')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    parser.add_argument('-s', '--strategy', action='store_true', 
                       help='Generate extraction strategy')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.firmware_file):
        print(f"[-] Error: File not found: {args.firmware_file}")
        sys.exit(1)
    
    try:
        # Initialize analyzer
        analyzer = FirmwareBinaryAnalyzer()
        
        # Perform analysis
        result = analyzer.analyze_firmware(args.firmware_file)
        
        # Generate extraction strategy
        strategy = analyzer.generate_extraction_strategy(result)
        
        # Get firmware base name and output directory
        firmware_name = os.path.splitext(os.path.basename(args.firmware_file))[0]
        output_dir = os.path.join(os.path.dirname(args.firmware_file), f"{firmware_name}_analysis")
        
        # Print summary
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        print(f"File: {result.file_path}")
        print(f"Size: {result.metadata.get('file_size_human', 'Unknown')}")
        print(f"Format: {result.file_format.get('raw_output', 'Unknown')}")
        print(f"SHA256: {result.hashes.get('sha256', 'Not calculated')}")
        print(f"Entropy: {result.entropy.get('entropy_value', 'Unknown')} ({result.entropy.get('classification', 'Unknown')})")
        
        # Enhanced encryption analysis display
        enc_prob = result.encryption.get('encryption_probability', 'unknown')
        enc_conf = result.encryption.get('encryption_confidence', 0.0)
        print(f"\nENCRYPTION ANALYSIS (Multi-factor Analysis):")
        print(f"  Probability: {enc_prob}")
        print(f"  Confidence: {enc_conf:.3f}/1.0")
        
        # Show key factors that contributed to the score
        enc_factors = result.encryption.get('encryption_factors', {})
        if enc_factors:
            high_factors = [(k, v) for k, v in enc_factors.items() if v > 0.3]
            if high_factors:
                print(f"  Key factors:")
                for factor, score in sorted(high_factors, key=lambda x: x[1], reverse=True):
                    factor_name = factor.replace('_factor', '').replace('_', ' ').title()
                    print(f"    {factor_name}: {score:.2f}")
        
        # Show encryption indicators if any
        enc_indicators = result.encryption.get('encryption_indicators', [])
        if enc_indicators:
            print(f"  Indicators: {', '.join(enc_indicators[:3])}")
            if len(enc_indicators) > 3:
                print(f"    (+{len(enc_indicators) - 3} more)")
        
        if result.encryption.get('vendor_encryption'):
            print(f"  Vendor patterns: {', '.join(result.encryption['vendor_encryption'])}")
        
        # String density info
        magic_analysis = result.encryption.get('file_magic_analysis', {})
        if magic_analysis.get('string_density') is not None:
            density = magic_analysis['string_density']
            print(f"  String density: {density:.3f} ({density*100:.1f}% readable)")
        
        if result.extraction_points.get('extraction_offsets'):
            print(f"\nExtraction Points: {len(result.extraction_points['extraction_offsets'])} found")
        
        # Show filesystems if any detected
        if result.extraction_points.get('filesystems_detected'):
            print("\nFilesystems Detected:")
            for fs in result.extraction_points['filesystems_detected']:
                print(f"  - {fs}")
        
        # Display extraction strategy if requested
        if args.strategy:
            print("\nEXTRACTION STRATEGY:")
            print(f"Recommended extractors: {', '.join(strategy['recommended_extractors'])}")
            print(f"Confidence: {strategy['confidence']}")
            
            # Show format flags if any detected
            if strategy.get('format_flags'):
                print("\nFORMAT FLAGS:")
                for flag, value in strategy['format_flags'].items():
                    if value == 1:
                        print(f"  {flag}=1")
            
            # Show special handling if any
            if strategy.get('special_handling'):
                print("\nSPECIAL HANDLING:")
                for handling in strategy['special_handling']:
                    print(f"  - {handling}")
            
            # Show if default extraction or specialized
            if 'DEFAULT_EXTRACTION' in strategy.get('format_flags', {}):
                print("\n[!] No specialized format detected - using default extraction hierarchy")
            else:
                print("\n[+] Specialized format detected - bypassing default extraction")
        
        # Print location of detailed summary
        summary_file = os.path.join(output_dir, "analysis_summary.txt")
        print(f"\n[+] Detailed analysis summary saved to: {summary_file}")
        
        # Save results if output file specified
        if args.output:
            analyzer.save_results(result, args.output)
    
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 