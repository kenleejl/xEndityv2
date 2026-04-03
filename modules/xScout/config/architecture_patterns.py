"""
Centralized architecture patterns configuration for xScout.

This module contains all architecture detection patterns used throughout the codebase.
All patterns use regex with case-insensitive matching for better detection accuracy.
"""

import re
from typing import Dict, List, Optional

# Architecture patterns for detection and highlighting
ARCHITECTURE_PATTERNS = {
    "ARM": [
        r'\bARM\b',
        r'\bARMv\d+\b', 
        r'\bAArch64\b',
        r'\baarch64\b'
    ],
    "MIPS": [
        r'\bMIPS\b',
        r'\bMIPS\s+R\d+\b',
        r'\bMIPSel\b',
        r'\bmips\b',
        r'\bmipsel\b'
    ],
    "x86": [
        r'\bIntel\s+80386\b',
        r'\bx86[-_]?64\b',
        r'\bi386\b',
        r'\bx86\b',
        r'\bAMD64\b',
        r'\bEM64T\b',
        r'\bamd64\b',
        r'\b80386\b'
    ],
    "PowerPC": [
        r'\bPowerPC\b',
        r'\bPPC\b',
        r'\bPPC64\b',
        r'\bppc64\b'
    ],
    "RISC-V": [
        r'\bRISC-V\b',
        r'\bRISCV\b',
        r'\bRISCV64\b',
        r'\bRISCV32\b',
        r'\briscv\b',
        r'\briscv64\b',
        r'\briscv32\b'
    ],
}

# Endianness patterns for detection and highlighting
ENDIANNESS_PATTERNS = [
    r'\blittle\s+endian\b',
    r'\bbig\s+endian\b',
    r'\bLSB\b',
    r'\bMSB\b',
    r'2\'s\s+complement,\s+little\s+endian',
    r'2\'s\s+complement,\s+big\s+endian'
]

# Bit width patterns for detection and highlighting
BITWIDTH_PATTERNS = [
    r'\bELF32\b',
    r'\bELF64\b', 
    r'\b32-bit\b',
    r'\b64-bit\b'
]

# Floating point patterns for detection and highlighting (ARM-specific)
FLOATING_POINT_PATTERNS = [
    r'\bVFP\s+registers\b',
    r'\bhard-float\b',
    r'\bsoft-float\b',
    r'\bhardfp\b',
    r'\bsoftfp\b',
    r'\bNEON\b',
    r'\blibsoftfp\b',
    r'VFP\s+registers\s+not\s+used',
    r'VFP\s+registers\s+used'
]

# Readelf machine type mappings
READELF_MACHINE_MAPPINGS = {
    "ARM": ["ARM", "AArch64"],
    "MIPS": ["MIPS"],
    "x86": ["Intel 80386", "Advanced Micro Devices X86-64"],
    "PowerPC": ["PowerPC"],
    "RISC-V": ["RISC-V"]
}

def detect_architecture_from_text(text: str) -> Optional[str]:
    """
    Detect architecture from text using centralized patterns.
    
    Args:
        text: Text to analyze for architecture patterns
        
    Returns:
        Detected architecture name or None if not found
    """
    if not text:
        return None
        
    for arch, patterns in ARCHITECTURE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return arch
    
    return None

def detect_architecture_from_readelf_output(readelf_output: str) -> Optional[str]:
    """
    Detect architecture from readelf output using centralized mappings.
    
    Args:
        readelf_output: Output from readelf command
        
    Returns:
        Detected architecture name or None if not found
    """
    if not readelf_output:
        return None
        
    for line in readelf_output.splitlines():
        if "Machine:" in line:
            for arch, machine_types in READELF_MACHINE_MAPPINGS.items():
                for machine_type in machine_types:
                    if machine_type in line:
                        return arch
    
    return None

def highlight_text_with_patterns(text: str, patterns: List[str], css_class: str, title: str = "") -> str:
    """
    Highlight text with specified patterns using regex.
    
    Args:
        text: Text to highlight
        patterns: List of regex patterns to match
        css_class: CSS class for highlighting
        title: Optional title attribute for the span
        
    Returns:
        Text with highlighted patterns
    """
    if not text or not patterns:
        return text
        
    highlighted_text = text
    title_attr = f' title="{title}"' if title else ""
    
    for pattern in patterns:
        highlighted_text = re.sub(
            pattern,
            rf'<span class="{css_class}"{title_attr}>\g<0></span>',
            highlighted_text,
            flags=re.IGNORECASE
        )
    
    return highlighted_text

def get_architecture_patterns_for_highlighting(architecture: str) -> List[str]:
    """
    Get architecture patterns for highlighting a specific architecture.
    
    Args:
        architecture: Architecture name
        
    Returns:
        List of regex patterns for the architecture
    """
    return ARCHITECTURE_PATTERNS.get(architecture, [])

def get_all_architecture_names() -> List[str]:
    """
    Get all supported architecture names.
    
    Returns:
        List of all architecture names
    """
    return list(ARCHITECTURE_PATTERNS.keys()) 