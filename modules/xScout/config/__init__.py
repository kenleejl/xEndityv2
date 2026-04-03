"""
Configuration module for xScout.

This module contains centralized configuration for various patterns and settings
used throughout the xScout codebase.
"""

from .architecture_patterns import (
    ARCHITECTURE_PATTERNS,
    ENDIANNESS_PATTERNS,
    BITWIDTH_PATTERNS,
    FLOATING_POINT_PATTERNS,
    READELF_MACHINE_MAPPINGS,
    detect_architecture_from_text,
    detect_architecture_from_readelf_output,
    highlight_text_with_patterns,
    get_architecture_patterns_for_highlighting,
    get_all_architecture_names
)

__all__ = [
    'ARCHITECTURE_PATTERNS',
    'ENDIANNESS_PATTERNS', 
    'BITWIDTH_PATTERNS',
    'FLOATING_POINT_PATTERNS',
    'READELF_MACHINE_MAPPINGS',
    'detect_architecture_from_text',
    'detect_architecture_from_readelf_output',
    'highlight_text_with_patterns',
    'get_architecture_patterns_for_highlighting',
    'get_all_architecture_names'
] 