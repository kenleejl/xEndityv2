"""
Kernel Version Detection Service for xFormation

Determines the appropriate kernel version to use based on firmware analysis
"""

import logging
import re
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class KernelVersionService:
    """Service for determining appropriate kernel version for emulation"""
    
    # Supported kernel versions in penguin
    KERNEL_4_1 = "4.1"
    KERNEL_6_13 = "6.13"

    # Default kernel version when detection fails
    DEFAULT_KERNEL = KERNEL_4_1
    
    @staticmethod
    def determine_kernel_version(analysis_results: Optional[Dict] = None) -> Tuple[str, str]:
        """
        Determine the appropriate kernel version based on firmware analysis.
        
        Logic:
        - If detected kernel version <= 4.1, use 4.1
        - If detected kernel version > 4.1, use 6.13
        - If not detected, default to 4.1
        
        Args:
            analysis_results: xScout components analysis results dictionary
            
        Returns:
            Tuple of (kernel_version, recommendation_reason)
        """
        if not analysis_results:
            return (
                KernelVersionService.DEFAULT_KERNEL,
                "No firmware analysis available - using default kernel 4.1 for maximum compatibility"
            )
        
        # Extract best kernel version from analysis
        detected_version = analysis_results.get('best_kernel_version')
        
        if not detected_version:
            return (
                KernelVersionService.DEFAULT_KERNEL,
                "Kernel version not detected in firmware - using default kernel 4.1 for maximum compatibility"
            )
        
        # Parse the version to extract major.minor
        try:
            parsed_version = KernelVersionService._parse_version(detected_version)
            
            if parsed_version is None:
                return (
                    KernelVersionService.DEFAULT_KERNEL,
                    f"Could not parse kernel version '{detected_version}' - using default kernel 4.1"
                )
            
            major, minor = parsed_version
            
            # Compare with 4.1 threshold
            if major < 4 or (major == 4 and minor <= 1):
                return (
                    KernelVersionService.KERNEL_4_1,
                    f"Detected kernel {detected_version} (<=4.1) - using kernel 4.1 for compatibility"
                )
            else:
                return (
                    KernelVersionService.KERNEL_6_13,
                    f"Detected kernel {detected_version} (>4.1) - using kernel 6.13 for better support"
                )
                
        except Exception as e:
            logger.error(f"Error parsing kernel version '{detected_version}': {e}")
            return (
                KernelVersionService.DEFAULT_KERNEL,
                f"Error parsing kernel version - using default kernel 4.1"
            )
    
    @staticmethod
    def _parse_version(version_string: str) -> Optional[Tuple[int, int]]:
        """
        Parse a kernel version string to extract major.minor version.
        
        Examples:
        - "4.9.118" -> (4, 9)
        - "5.10.0-generic" -> (5, 10)
        - "6.1.0-21-amd64" -> (6, 1)
        
        Args:
            version_string: Kernel version string
            
        Returns:
            Tuple of (major, minor) or None if parsing fails
        """
        # Match pattern like "4.9" or "4.9.118-something"
        match = re.match(r'^(\d+)\.(\d+)', version_string)
        
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            return (major, minor)
        
        return None
    
    @staticmethod
    def get_kernel_path(kernel_version: str, arch: str) -> str:
        """
        Get the full kernel path for the given version and architecture.
        
        Args:
            kernel_version: Kernel version (e.g., "4.10" or "6.13")
            arch: Architecture (e.g., "armel", "mipsel")
            
        Returns:
            Full path to kernel image
        """
        # Determine kernel format based on architecture
        if arch in ['armel', 'aarch64', 'arm64']:
            kernel_fmt = 'zImage'
        else:
            kernel_fmt = 'vmlinux'
        
        return f"/igloo_static/kernels/{kernel_version}/{kernel_fmt}.{arch}"
