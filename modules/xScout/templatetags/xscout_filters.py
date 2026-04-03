"""
Custom template filters for xScout module
"""
from django import template
from django.utils.safestring import mark_safe
import os
import re
import ast
from pathlib import Path

# Import centralized architecture patterns
from ..config.architecture_patterns import (
    ARCHITECTURE_PATTERNS,
    ENDIANNESS_PATTERNS,
    BITWIDTH_PATTERNS,
    FLOATING_POINT_PATTERNS,
    highlight_text_with_patterns,
    get_architecture_patterns_for_highlighting
)

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Get an item from a dictionary by key"""
    return dictionary.get(key)

@register.filter
def multiply(value, arg):
    """Multiply the value by the argument"""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return None

@register.filter
def subtract(value, arg):
    """Subtract the argument from the value"""
    try:
        return int(value) - int(arg)
    except (ValueError, TypeError):
        return None

@register.filter
def replace_underscores(value):
    """Replace underscores with spaces and capitalize each word"""
    if not value:
        return ""
    # Replace underscores with spaces
    value = value.replace('_', ' ')
    # Remove "factor" suffix if present
    value = value.replace(' factor', '')
    # Capitalize each word
    return value.title()

@register.filter
def filename(path):
    """Extract filename from a path"""
    if not path:
        return ""
    return os.path.basename(path)

@register.filter
def relative_path(path):
    """
    Convert an absolute path to a relative path, showing only the extract directory
    or the relevant part after the firmware directory.
    
    Example:
    /home/xendity/xEndity/firmwares/DLink/DIR846/FW100A53DBR/DIR846-FW100A53DBR_extract/extracted_files/...
    becomes:
    DIR846-FW100A53DBR_extract/extracted_files/...
    
    Or for artifact paths:
    /home/xendity/xEndity/firmwares/DLink/DIR846/FW100A53DBR/artifacts/rootfs
    becomes:
    artifacts/rootfs
    
    Also handles list representations of paths:
    ['/home/xendity/xEndity/firmwares/DLink/DIR846/FW100A53DBR/artifacts/boot.img']
    becomes:
    artifacts/boot.img
    """
    if not path:
        return ""
    
    # Handle string representation of lists
    if isinstance(path, str) and path.startswith('[') and path.endswith(']'):
        try:
            # Safely parse the string representation of a list
            paths = ast.literal_eval(path)
            sanitized_paths = []
            for p in paths:
                # Recursively process each path
                sanitized_paths.append(relative_path(p))
            return ', '.join(sanitized_paths)
        except (ValueError, SyntaxError):
            # Return an empty string if parsing fails
            return ""
    
    # Check if it's an absolute path
    if isinstance(path, str) and os.path.isabs(path):
        # Look for extract directory (ends with _extract) or artifacts directory
        components = path.split("/")
        for i, component in enumerate(components):
            if component.endswith("_extract") or component == "artifacts":
                return "/".join(components[i:])
        
        # If no patterns matched, return the original filename
        return os.path.basename(path)
    
    return path

@register.filter
def rootfs_path(path):
    """
    Format a path relative to rootfs directory, showing it as if rootfs was the root directory.
    
    Example:
    /home/xendity/xEndity/firmwares/DLink/DIR846/FW100A53DBR/artifacts/rootfs/etc/init.d/rcS
    becomes:
    /etc/init.d/rcS
    
    Or:
    artifacts/rootfs/etc/init.d/rcS
    becomes:
    /etc/init.d/rcS
    """
    if not path:
        return ""
    
    # Normalize the path
    normalized_path = os.path.normpath(path)
    
    # First, check if it has rootfs in the path
    if "/rootfs/" in normalized_path:
        parts = normalized_path.split("/rootfs/")
        if len(parts) > 1:
            return "/" + parts[1]
    
    # Check for the full path pattern with artifacts
    if "/artifacts/rootfs/" in normalized_path:
        parts = normalized_path.split("/artifacts/rootfs/")
        if len(parts) > 1:
            return "/" + parts[1]
    
    # Handle the case where the path is already relative to rootfs
    if normalized_path.startswith("rootfs/"):
        return "/" + normalized_path[7:]
    
    if normalized_path.startswith("artifacts/rootfs/"):
        return "/" + normalized_path[16:]
    
    # If none of the patterns matched, return the original path
    return path

@register.filter
def clean_command_display(command, binary_path):
    """
    Clean up command display by replacing the full binary path with a simplified version.
    
    Example:
    readelf -h /home/user/firmware/rootfs/bin/busybox
    becomes:
    readelf -h [binary_path]
    """
    if not command or not binary_path:
        return command
    
    # Replace the full binary path with a placeholder
    simplified_command = command.replace(binary_path, "[binary_path]")
    return simplified_command

@register.filter
def highlight_architecture_output(output, detected_arch):
    """
    Highlight architecture-related terms in command output with blue color.
    """
    if not output:
        return output
    
    # Use centralized architecture patterns
    if detected_arch in ARCHITECTURE_PATTERNS:
        patterns = ARCHITECTURE_PATTERNS[detected_arch]
        return mark_safe(highlight_text_with_patterns(
            output, patterns, "bg-blue-200 dark:bg-blue-800 px-1 rounded"
        ))
    
    return mark_safe(output)

@register.filter  
def highlight_endianness_output(output):
    """
    Highlight endianness-related terms in command output with green color.
    """
    if not output:
        return output
    
    return mark_safe(highlight_text_with_patterns(
        output, ENDIANNESS_PATTERNS, "bg-green-200 dark:bg-green-800 px-1 rounded"
    ))

@register.filter
def highlight_bitwidth_output(output):
    """
    Highlight bit width-related terms in command output with purple color.
    """
    if not output:
        return output
    
    return mark_safe(highlight_text_with_patterns(
        output, BITWIDTH_PATTERNS, "bg-purple-200 dark:bg-purple-800 px-1 rounded"
    ))

@register.filter
def highlight_floating_point_output(output):
    """
    Highlight floating point-related terms in command output with indigo color.
    """
    if not output:
        return output
    
    return mark_safe(highlight_text_with_patterns(
        output, FLOATING_POINT_PATTERNS, "bg-indigo-200 dark:bg-indigo-800 px-1 rounded"
    ))

@register.filter
def get_detection_types(detail):
    """Get detection_types from a detail dictionary."""
    return detail.get("detection_types", [])

@register.filter
def get_detected_values(detail):
    """Get detected_values from a detail dictionary."""
    return detail.get("detected_values", {})

@register.filter
def highlight_consolidated_output(output, detail):
    """
    Apply multiple highlighting types to a single command output based on what was detected.
    
    Args:
        output: The command output text
        detail: Dictionary containing detection_types and detected_values
    """
    if not output or not detail:
        return output
    
    highlighted_output = output
    detection_types = detail.get("detection_types", [])
    detected_values = detail.get("detected_values", {})
    
    # Apply architecture highlighting
    if "architecture" in detection_types and detected_values.get("architecture"):
        arch = detected_values["architecture"]
        patterns = get_architecture_patterns_for_highlighting(arch)
        if patterns:
            highlighted_output = highlight_text_with_patterns(
                highlighted_output, patterns, 
                "bg-blue-200 dark:bg-blue-800 px-1 rounded", 
                "Architecture"
            )
    
    # Apply endianness highlighting
    if "endianness" in detection_types:
        highlighted_output = highlight_text_with_patterns(
            highlighted_output, ENDIANNESS_PATTERNS,
            "bg-green-200 dark:bg-green-800 px-1 rounded",
            "Endianness"
        )
    
    # Apply bit width highlighting
    if "bitwidth" in detection_types:
        highlighted_output = highlight_text_with_patterns(
            highlighted_output, BITWIDTH_PATTERNS,
            "bg-purple-200 dark:bg-purple-800 px-1 rounded",
            "Bit Width"
        )
    
    # Apply floating point highlighting
    if "floating_point" in detection_types:
        highlighted_output = highlight_text_with_patterns(
            highlighted_output, FLOATING_POINT_PATTERNS,
            "bg-indigo-200 dark:bg-indigo-800 px-1 rounded",
            "Floating Point"
        )
    
    return mark_safe(highlighted_output) 