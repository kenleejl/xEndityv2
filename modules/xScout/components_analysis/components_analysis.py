#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Kernel Footprinting and Analysis Module for QEMU Emulation
---------------------------------------------------------
This module provides functionality to analyze and extract information
from firmware images that is crucial for QEMU emulation setup.
"""

import os
import re
import shutil
import subprocess
import logging
import datetime
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set, Any, Union, Callable

# Import centralized architecture patterns
from ..config.architecture_patterns import (
    detect_architecture_from_text,
    detect_architecture_from_readelf_output
)

logger = logging.getLogger(__name__)

class BaseAnalyzer:
    """Base class for all analyzers with common utility methods."""
    
    def __init__(self, firmware_path: str):
        """
        Initialize the analyzer with the path to the firmware.
        
        Args:
            firmware_path: Path to the firmware directory or file
        """
        self.firmware_path = Path(firmware_path)
        if not self.firmware_path.exists():
            raise FileNotFoundError(f"Firmware path not found: {firmware_path}")
        
        # Create command outputs directory
        self.command_outputs_dir = self.firmware_path / "command_outputs"
        self.command_outputs_dir.mkdir(exist_ok=True)
        
        # Cache for command outputs to avoid duplicated calls
        self._command_cache = {}
        
        # Track which files contributed to which detections
        self.detection_sources = {
            "strings_output": [],
            "file_output": [],
            "readelf_h_output": [],
            "readelf_A_output": [],
            "readelf_s_output": [],
            "readelf_d_output": [],
            "modinfo_output": []
        }
    
    def _find_files(self, pattern: str, search_path: Optional[Union[str, Path]] = None) -> List[str]:
        """
        Find files matching the pattern in the specified directory.
        
        Args:
            pattern: Glob pattern to match files
            search_path: Path to search in, defaults to firmware_path if None
            
        Returns:
            List of matching file paths
        """
        result = []
        search_path = search_path or self.firmware_path
        
        try:
            # Convert to Path object for robust handling
            if isinstance(search_path, str):
                search_path = Path(search_path)
                
            # Check if search path exists and is accessible
            if not search_path.exists():
                logger.warning(f"Search path does not exist: {search_path}")
                return result
                
            # Walk the directory structure with error handling
            for root, dirs, files in os.walk(search_path, onerror=lambda e: logger.warning(f"Error accessing directory during walk: {e}")):
                # Skip directories we can't access
                dirs[:] = [d for d in dirs if os.access(os.path.join(root, d), os.R_OK)]
                
                for f in files:
                    try:
                        if Path(f).match(pattern):
                            file_path = os.path.join(root, f)
                            # Only add if we can access the file
                            if os.access(file_path, os.R_OK):
                                result.append(file_path)
                    except Exception as e:
                        logger.debug(f"Error matching file pattern for {f}: {e}")
        except Exception as e:
            logger.warning(f"Error finding files with pattern '{pattern}' in {search_path}: {e}")
            
        return result
    
    def _run_command(self, cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
        """
        Run a shell command safely.
        
        Args:
            cmd: Command as a list of strings
            check: Whether to check return code
            
        Returns:
            CompletedProcess instance
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return result
        except Exception as e:
            logger.error(f"Error running command {' '.join(cmd)}: {e}")
            # Return a dummy CompletedProcess with empty outputs
            return subprocess.CompletedProcess(cmd, 1, "", str(e))
    
    def _save_command_output_to_file(self, filename: str, content: str, binary_path: str = "", command: str = ""):
        """
        Save command output to a file in the command_outputs directory.
        
        Args:
            filename: Name of the output file
            content: Command output content
            binary_path: Path to the binary that was analyzed
            command: Command that was executed
        """
        output_file = self.command_outputs_dir / filename
        
        # Create a header with metadata
        header = f"# Command: {command}\n# Binary: {binary_path}\n# Timestamp: {datetime.datetime.now().isoformat()}\n\n"
        
        try:
            # Append to file if it exists, create if it doesn't
            mode = 'a' if output_file.exists() else 'w'
            with open(output_file, mode, encoding='utf-8') as f:
                if mode == 'a':
                    f.write(f"\n{'='*50}\n")
                f.write(header)
                f.write(content)
                f.write("\n")
        except Exception as e:
            logger.warning(f"Error saving command output to {output_file}: {e}")
    
    def _read_command_output_from_file(self, filename: str) -> str:
        """
        Read command output from a file in the command_outputs directory.
        
        Args:
            filename: Name of the output file
            
        Returns:
            File content as string
        """
        output_file = self.command_outputs_dir / filename
        
        if not output_file.exists():
            return ""
        
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.warning(f"Error reading command output from {output_file}: {e}")
            return ""
    
    def _get_command_output(self, cmd_name: str, args: List[str], cache_key: Optional[str] = None) -> str:
        """
        Get command output with caching and file storage.
        
        Args:
            cmd_name: Name of the command to run
            args: Arguments for the command
            cache_key: Optional custom cache key, defaults to cmd_name + args
            
        Returns:
            Command output as string
        """
        if not shutil.which(cmd_name):
            logger.warning(f"{cmd_name} command not found in PATH")
            return ""
        
        # Create a cache key
        if cache_key is None:
            cache_key = f"{cmd_name}:{':'.join(args)}"
        
        # Return cached result if available
        if cache_key in self._command_cache:
            return self._command_cache[cache_key]
        
        # Run command and cache the result
        cmd = [cmd_name] + args
        result = self._run_command(cmd)
        output = result.stdout
        self._command_cache[cache_key] = output
        
        # Save to appropriate file based on command type
        binary_path = args[-1] if args else ""
        command_str = ' '.join(cmd)
        
        if cmd_name == "strings":
            self._save_command_output_to_file("strings_output.txt", output, binary_path, command_str)
        elif cmd_name == "file":
            self._save_command_output_to_file("file_output.txt", output, binary_path, command_str)
        elif cmd_name == "readelf":
            option = args[0] if args else ""
            if option == "-h":
                self._save_command_output_to_file("readelf_h_output.txt", output, binary_path, command_str)
            elif option == "-A":
                self._save_command_output_to_file("readelf_A_output.txt", output, binary_path, command_str)
            elif option == "-s":
                self._save_command_output_to_file("readelf_s_output.txt", output, binary_path, command_str)
            elif option == "-d":
                self._save_command_output_to_file("readelf_d_output.txt", output, binary_path, command_str)
        elif cmd_name == "modinfo":
            self._save_command_output_to_file("modinfo_output.txt", output, binary_path, command_str)
        
        return output
    
    def _get_readelf_output(self, binary_path: str, options: str) -> str:
        """
        Get readelf output for a binary with caching and file storage.
        
        Args:
            binary_path: Path to the binary file
            options: Readelf options (e.g., "-h", "-A", etc.)
            
        Returns:
            Readelf output as string
        """
        return self._get_command_output("readelf", [options, binary_path])
    
    def _get_file_output(self, binary_path: str) -> str:
        """
        Get 'file' command output for a binary with caching and file storage.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            File command output as string
        """
        return self._get_command_output("file", [binary_path])
    
    def _get_modinfo_output(self, module_path: str) -> str:
        """
        Get modinfo output for a kernel module with caching and file storage.
        
        Args:
            module_path: Path to kernel module file
            
        Returns:
            Modinfo output as string
        """
        return self._get_command_output("modinfo", [module_path])
    
    def _get_strings_output(self, binary_path: str) -> str:
        """
        Get strings output for a binary file with caching and file storage.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Strings output as string
        """
        return self._get_command_output("strings", [binary_path])

    def get_modinfo_data(self, module_path: str) -> Dict[str, str]:
        """
        Run modinfo on a kernel module and parse/save the output.
        
        Args:
            module_path: Path to kernel module file
            
        Returns:
            Dictionary with parsed modinfo fields
        """
        results = {}
        
        # Check if file exists and is readable
        if not os.path.isfile(module_path) or not os.access(module_path, os.R_OK):
            logger.warning(f"Module file not found or not readable: {module_path}")
            return results
            
        try:
            # Get raw modinfo output (this will also save to file)
            modinfo_output = self._get_command_output("modinfo", [module_path])
            
            # Parse output into dictionary
            for line in modinfo_output.splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    results[key.strip()] = value.strip()
                    
            return results
        except Exception as e:
            logger.warning(f"Error getting modinfo for {module_path}: {e}")
            return results
    
    def get_saved_outputs_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all saved command outputs for display in web interface.
        
        Returns:
            Dictionary with saved output information
        """
        summary = {}
        
        output_files = [
            "strings_output.txt",
            "file_output.txt", 
            "readelf_h_output.txt",
            "readelf_A_output.txt",
            "readelf_s_output.txt",
            "readelf_d_output.txt",
            "modinfo_output.txt"
        ]
        
        for filename in output_files:
            file_path = self.command_outputs_dir / filename
            if file_path.exists():
                try:
                    # Get file size and line count
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        line_count = len(content.splitlines())
                        size_kb = len(content.encode('utf-8')) / 1024
                    
                    summary[filename] = {
                        "exists": True,
                        "size_kb": round(size_kb, 2),
                        "line_count": line_count,
                        "path": str(file_path)
                    }
                except Exception as e:
                    summary[filename] = {
                        "exists": True,
                        "error": str(e),
                        "path": str(file_path)
                    }
            else:
                summary[filename] = {
                    "exists": False,
                    "path": str(file_path)
                }
        
        return summary
    
    def _create_source_reference(self, filename: str, binary_path: str, command: str, matched_text: str = "", line_number: int = None) -> Dict[str, Any]:
        """
        Create a reference to a specific result in a saved output file.
        
        Args:
            filename: Name of the output file (e.g., "readelf_h_output.txt")
            binary_path: Path to the binary that was analyzed
            command: Command that was executed
            matched_text: The specific text that matched/was used for detection
            line_number: Optional line number where the match was found
            
        Returns:
            Dictionary with source reference information
        """
        return {
            "source_file": filename,
            "binary_path": binary_path,
            "command": command,
            "matched_text": matched_text,
            "line_number": line_number,
            "file_path": str(self.command_outputs_dir / filename)
        }
    
    def _find_text_in_saved_output(self, filename: str, search_text: str, binary_path: str = "") -> Optional[Dict[str, Any]]:
        """
        Find specific text in a saved output file and return reference information.
        
        Args:
            filename: Name of the output file to search
            search_text: Text to search for
            binary_path: Binary path to filter results (optional)
            
        Returns:
            Dictionary with reference information if found, None otherwise
        """
        content = self._read_command_output_from_file(filename)
        if not content:
            return None
        
        lines = content.splitlines()
        current_command = ""
        current_binary = ""
        
        for line_num, line in enumerate(lines, 1):
            # Track current command and binary from headers
            if line.startswith("# Command:"):
                current_command = line.replace("# Command:", "").strip()
            elif line.startswith("# Binary:"):
                current_binary = line.replace("# Binary:", "").strip()
            
            # Search for the text
            if search_text.lower() in line.lower():
                # If binary_path is specified, only return matches from that binary
                if binary_path and binary_path not in current_binary:
                    continue
                    
                return self._create_source_reference(
                    filename=filename,
                    binary_path=current_binary,
                    command=current_command,
                    matched_text=line.strip(),
                    line_number=line_num
                )
        
        return None
    
    def run_all_commands_on_binaries(self, binaries: List[str]) -> None:
        """
        Run all necessary commands on the provided binaries ONCE and save outputs.
        This prevents duplicate command execution across different analyzers.
        
        Args:
            binaries: List of binary paths to analyze
        """
        logger.info(f"Running centralized command execution on {len(binaries)} binaries")
        
        for binary_path in binaries:
            if not os.path.isfile(binary_path) or not os.access(binary_path, os.R_OK):
                logger.warning(f"Binary not accessible: {binary_path}")
                continue
                
            logger.info(f"Executing commands on binary: {binary_path}")
            
            # Run file command
            try:
                self._get_file_output(binary_path)
                logger.debug(f"Executed 'file' on {binary_path}")
            except Exception as e:
                logger.warning(f"Error running 'file' on {binary_path}: {e}")
            
            # Run readelf commands if available
            if shutil.which("readelf"):
                for option in ["-h", "-A", "-s", "-d"]:
                    try:
                        self._get_readelf_output(binary_path, option)
                        logger.debug(f"Executed 'readelf {option}' on {binary_path}")
                    except Exception as e:
                        logger.warning(f"Error running 'readelf {option}' on {binary_path}: {e}")
            
            # Run strings command if available
            if shutil.which("strings"):
                try:
                    self._get_strings_output(binary_path)
                    logger.debug(f"Executed 'strings' on {binary_path}")
                except Exception as e:
                    logger.warning(f"Error running 'strings' on {binary_path}: {e}")
        
        logger.info("Centralized command execution completed")
    
    def get_command_output_for_binary(self, filename: str, binary_path: str) -> str:
        """
        Get command output for a specific binary from saved files.
        
        Args:
            filename: Name of the output file (e.g., "readelf_h_output.txt")
            binary_path: Path to the binary
            
        Returns:
            Command output for the specific binary
        """
        content = self._read_command_output_from_file(filename)
        if not content:
            return ""
        
        lines = content.splitlines()
        current_binary = ""
        binary_output_lines = []
        capturing = False
        
        for line in lines:
            if line.startswith("# Binary:"):
                current_binary = line.replace("# Binary:", "").strip()
                if binary_path in current_binary:
                    capturing = True
                    binary_output_lines = []
                else:
                    capturing = False
            elif line.startswith("# Command:") or line.startswith("# Timestamp:"):
                continue  # Skip metadata lines
            elif line.startswith("=" * 50):
                if capturing:
                    break  # End of this binary's output
                capturing = False
            elif capturing:
                binary_output_lines.append(line)
        
        return "\n".join(binary_output_lines)
    
    def find_binaries_for_analysis(self, rootfs_path: Optional[str] = None) -> List[str]:
        """
        Find all binaries that should be analyzed, used by multiple analyzers.
        
        Args:
            rootfs_path: Path to rootfs
            
        Returns:
            List of binary paths to analyze
        """
        binaries = set()  # Use set to avoid duplicates
        
        # Common binaries likely to be found in firmware images
        common_binaries = [
            "busybox", "sh", "bash", "sshd", "dropbear", "httpd", "telnetd", 
            "udhcpc", "ifconfig", "ls", "cat", "init", "mount", "umount"
        ]
        
        # Determine search path
        search_path = self.firmware_path
        if rootfs_path and os.path.exists(rootfs_path):
            search_path = Path(rootfs_path)
        else:
            # Try to find rootfs in firmware path
            for d in ["rootfs", "root", "squashfs-root"]:
                potential_path = self.firmware_path / d
                if potential_path.exists() and potential_path.is_dir():
                    search_path = potential_path
                    break
        
        # Common paths to check for binaries
        common_binary_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"]
        
        # First look for common binaries in common directories
        for bin_dir in common_binary_dirs:
            bin_dir_path = search_path / bin_dir
            if bin_dir_path.exists() and bin_dir_path.is_dir():
                for binary_name in common_binaries:
                    binary_path = bin_dir_path / binary_name
                    if binary_path.exists() and binary_path.is_file() and os.access(binary_path, os.X_OK):
                        binaries.add(str(binary_path))
                        logger.debug(f"Found common binary: {binary_path}")
        
        # If we don't have enough binaries, look for any executable files
        if len(binaries) < 3:
            for bin_dir in common_binary_dirs:
                bin_dir_path = search_path / bin_dir
                if bin_dir_path.exists() and bin_dir_path.is_dir():
                    for item in bin_dir_path.iterdir():
                        if item.is_file() and os.access(item, os.X_OK):
                            binaries.add(str(item))
                            logger.debug(f"Found executable: {item}")
                            if len(binaries) >= 10:  # Limit to avoid excessive analysis
                                break
                    if len(binaries) >= 10:
                        break
        
        result = list(binaries)[:10]  # Limit to 10 binaries max
        logger.info(f"Found {len(result)} binaries for analysis")
        return result

class KernelVersion(BaseAnalyzer):
    """Class responsible for determining the kernel version."""
    
    def detect(self) -> Dict[str, Any]:
        """
        Detect kernel version from various sources.
        
        Returns:
            Dictionary with kernel version information from various sources with source references
        """
        results = {}
        version_sources = {}
        
        # Detect from kernel modules
        kernel_modules_results = self._detect_from_kernel_modules_path()
        if kernel_modules_results:
            results["kernel_modules"] = kernel_modules_results
            # Add source references for kernel modules
            for result in kernel_modules_results:
                version = result["version"]
                source_ref = self._create_source_reference(
                    "directory_scan", result["source"], "Directory scan",
                    f"Module directory: {result['source']}", None
                )
                if version not in version_sources:
                    version_sources[version] = []
                version_sources[version].append(source_ref)
        
        # Detect from old-style kernel modules
        old_kernel_modules_results = self._detect_from_old_modules()
        if old_kernel_modules_results:
            results["old_kernel_modules"] = old_kernel_modules_results
            # Add source references for old modules
            for result in old_kernel_modules_results:
                version = result["version"]
                source_ref = self._find_text_in_saved_output("strings_output.txt", f"kernel_version={version}", result["source"])
                if not source_ref:
                    source_ref = self._create_source_reference(
                        "strings_output.txt", result["source"], f"strings {result['source']}",
                        f"kernel_version={version}", None
                    )
                if version not in version_sources:
                    version_sources[version] = []
                version_sources[version].append(source_ref)
        
        # Detect from modinfo vermagic
        modinfo_vermagic_results = self._detect_from_modinfo_vermagic()
        if modinfo_vermagic_results:
            results["modinfo_vermagic"] = modinfo_vermagic_results
            # Add source references for modinfo
            for result in modinfo_vermagic_results:
                version = result["version"]
                source_ref = self._find_text_in_saved_output("modinfo_output.txt", f"vermagic:", result["source"])
                if not source_ref:
                    source_ref = self._create_source_reference(
                        "modinfo_output.txt", result["source"], f"modinfo {result['source']}",
                        f"vermagic: {version}", None
                    )
                if version not in version_sources:
                    version_sources[version] = []
                version_sources[version].append(source_ref)
        
        # Detect from kernel binaries
        kernel_binaries_results = self._detect_from_kernel_binaries()
        if kernel_binaries_results:
            results["kernel_binaries"] = kernel_binaries_results
            # Add source references for kernel binaries
            for result in kernel_binaries_results:
                version = result["version"]
                source_ref = self._find_text_in_saved_output("strings_output.txt", version, result["source"])
                if not source_ref:
                    source_ref = self._create_source_reference(
                        "strings_output.txt", result["source"], f"strings {result['source']}",
                        f"Version: {version}", None
                    )
                if version not in version_sources:
                    version_sources[version] = []
                version_sources[version].append(source_ref)
        
        # Detect from kernel config
        kernel_config_results = self._detect_from_kernel_config()
        if kernel_config_results:
            results["kernel_config"] = kernel_config_results
            # Add source references for kernel config
            for result in kernel_config_results:
                version = result["version"]
                source_ref = self._create_source_reference(
                    "kernel_config", result["source"], "Kernel config analysis",
                    f"CONFIG_VERSION: {version}", None
                )
                if version not in version_sources:
                    version_sources[version] = []
                version_sources[version].append(source_ref)
        
        # Detect from uname -a in logs
        uname_results = self._detect_from_uname_logs()
        if uname_results:
            results["uname_logs"] = uname_results
            # Add source references for uname logs
            for result in uname_results:
                version = result["version"]
                source_ref = self._find_text_in_saved_output("strings_output.txt", f"Linux", result["source"])
                if not source_ref:
                    source_ref = self._create_source_reference(
                        "strings_output.txt", result["source"], f"strings {result['source']}",
                        f"uname: {version}", None
                    )
                if version not in version_sources:
                    version_sources[version] = []
                version_sources[version].append(source_ref)
        
        return {
            "version_detections": results,
            "version_sources": version_sources
        }
    
    def _detect_from_kernel_modules_path(self) -> List[Dict[str, str]]:
        """Extract kernel version from kernel module directory structure."""
        versions = []
        
        # Search for /lib/modules/* directories
        module_dirs = self._find_module_dirs()
        
        for module_dir in module_dirs:
            try:
                # The directory name itself is the kernel version
                version = os.path.basename(module_dir)
                if self._is_valid_kernel_version(version):
                    versions.append({
                        "version": version,
                        "source": module_dir,
                        "details": f"Found kernel module directory: {module_dir}"
                    })
                    logger.info(f"Found kernel version {version} from module directory: {module_dir}")
            except Exception as e:
                logger.warning(f"Error extracting kernel version from {module_dir}: {e}")
        
        return versions
    
    def _detect_from_old_modules(self) -> List[Dict[str, str]]:
        """Extract kernel version from old-style kernel module files."""
        versions = []
        
        # Find .o kernel modules
        module_files = self._find_files("*.o")
        
        for module_file in module_files:
            try:
                # Check if file exists and is readable
                if not os.path.isfile(module_file) or not os.access(module_file, os.R_OK):
                    logger.warning(f"Module file not found or not readable: {module_file}")
                    continue
                
                # Extract kernel version using strings
                strings_output = self._get_strings_output(module_file)
                if not strings_output:
                    logger.debug(f"No strings output for module file: {module_file}")
                    continue
                    
                for line in strings_output.splitlines():
                    match = re.search(r"kernel_version=([0-9]+\.[0-9]+\.[0-9]+[^\s]*)", line)
                    if match:
                        version = match.group(1)
                        versions.append({
                            "version": version,
                            "source": module_file,
                            "details": f"Found in module file: {module_file}\nMatched string: {line}"
                        })
                        logger.info(f"Found kernel version {version} from old module: {module_file}")
            except Exception as e:
                logger.warning(f"Error extracting kernel version from {module_file}: {e}")
        
        return versions
    
    def _detect_from_modinfo_vermagic(self) -> List[Dict[str, str]]:
        """Extract kernel version from modinfo vermagic output."""
        versions = []
        
        # Find .ko kernel modules
        ko_files = self._find_files("*.ko")
        # logger.info(f"Found {len(ko_files)} .ko files for vermagic analysis")
        
        # Collect unique vermagic strings
        unique_vermagic = {}
        
        for ko_file in ko_files:
            try:
                # Check if file exists and is readable
                if not os.path.isfile(ko_file) or not os.access(ko_file, os.R_OK):
                    logger.warning(f"Module file not found or not readable: {ko_file}")
                    continue
                
                # Use the centralized modinfo method
                modinfo_data = self.get_modinfo_data(ko_file)
                
                # Get vermagic info which contains kernel version
                vermagic = modinfo_data.get("vermagic", "")
                if not vermagic:
                    continue
                
                # Extract kernel version from vermagic
                # Vermagic format is typically: "2.6.28 preempt mod_unload ARMv5"
                parts = vermagic.split()
                if parts and self._is_valid_kernel_version(parts[0]):
                    version = parts[0]
                    
                    # Store by version to avoid duplicates
                    if version not in unique_vermagic:
                        unique_vermagic[version] = []
                    unique_vermagic[version].append((ko_file, vermagic))
                    
            except Exception as e:
                logger.warning(f"Error extracting kernel version from {ko_file} vermagic: {e}")
        
        # Create version entries from unique vermagic data
        for version, module_data in unique_vermagic.items():
            # Use the first file as reference
            sample_file, sample_vermagic = module_data[0]
            file_count = len(module_data)
            
            if file_count == 1:
                versions.append({
                    "version": version,
                    "source": sample_file,
                    "details": f"Found in module vermagic: {sample_file}\nVermagic: {sample_vermagic}"
                })
            else:
                # If many modules have the same version, just mention the count
                versions.append({
                    "version": version,
                    "source": f"{file_count} modules",
                    "details": f"Found in {file_count} modules\nSample vermagic: {sample_vermagic}"
                })
            
            logger.info(f"Found kernel version {version} from module vermagic (in {file_count} modules)")
        
        return versions
    
    def _detect_from_kernel_binaries(self) -> List[Dict[str, str]]:
        """Extract kernel version from kernel binary files."""
        versions = []
        
        # Common kernel binary names
        kernel_patterns = [
            "vmlinux*", "zImage*", "bzImage*", "kernel*", 
            "vmlinuz*", "Image*", "uImage*"
        ]
        
        # Find kernel binaries
        kernel_files = []
        for pattern in kernel_patterns:
            kernel_files.extend(self._find_files(pattern))
        
        for kernel_file in kernel_files:
            try:
                # Check if file exists and is readable
                if not os.path.isfile(kernel_file) or not os.access(kernel_file, os.R_OK):
                    logger.warning(f"Kernel binary not found or not readable: {kernel_file}")
                    continue
                
                # Get strings output
                strings_output = self._get_strings_output(kernel_file)
                if not strings_output:
                    logger.debug(f"No strings output for kernel binary: {kernel_file}")
                    continue
                
                # Extract kernel version
                for line in strings_output.splitlines():
                    match = re.search(r"Linux version ([0-9]+\.[0-9]+\.[0-9]+[^\s]*)", line)
                    if match:
                        version = match.group(1)
                        versions.append({
                            "version": version,
                            "source": kernel_file,
                            "details": f"Found in kernel binary: {kernel_file}\nMatched string: {line}"
                        })
                        logger.info(f"Found kernel version {version} from kernel binary: {kernel_file}")
            except OSError as e:
                logger.warning(f"OS error processing kernel binary {kernel_file}: {e}")
            except Exception as e:
                logger.warning(f"Error processing kernel binary {kernel_file}: {e}")
        
        return versions
    
    def _detect_from_kernel_config(self) -> List[Dict[str, str]]:
        """Extract kernel version from kernel config."""
        versions = []
        
        # Find kernel config
        config_files = self._find_kernel_config_files()
        
        for config_file in config_files:
            try:
                # First check if file exists and is readable
                if not os.path.isfile(config_file):
                    logger.warning(f"Config file not found or not a file: {config_file}")
                    continue
                    
                # Open with error handling for file encoding issues
                with open(config_file, 'r', errors='replace') as f:
                    content = f.read()
                
                # Look for version information
                local_version_match = re.search(r'CONFIG_LOCALVERSION="([^"]*)"', content)
                kernel_version_match = re.search(r'# Linux/\w+ ([0-9]+\.[0-9]+\.[0-9]+[^\s]*)', content)
                
                if kernel_version_match:
                    version = kernel_version_match.group(1)
                    if local_version_match:
                        version += local_version_match.group(1)
                    
                    versions.append({
                        "version": version,
                        "source": config_file,
                        "details": f"Found in kernel config: {config_file}\nMatched lines:\n" + 
                                  (f"CONFIG_LOCALVERSION=\"{local_version_match.group(1)}\"\n" if local_version_match else "") +
                                  f"# Linux/... {kernel_version_match.group(1)}"
                    })
                    logger.info(f"Found kernel version {version} from kernel config: {config_file}")
            except UnicodeDecodeError as e:
                logger.warning(f"Unicode decode error for config {config_file}: {e}")
            except PermissionError as e:
                logger.warning(f"Permission error accessing config {config_file}: {e}")
            except Exception as e:
                logger.warning(f"Error extracting kernel version from config {config_file}: {e}")
        
        return versions
    
    def _detect_from_uname_logs(self) -> List[Dict[str, str]]:
        """Extract kernel version from uname -a in log files."""
        versions = []
        
        # Find log files
        log_files = self._find_files("*.log")
        log_files.extend(self._find_files("syslog*"))
        log_files.extend(self._find_files("messages*"))
        
        for log_file in log_files:
            try:
                # Use binary mode first to check if it's a text file
                with open(log_file, 'rb') as f:
                    # Read a small sample to check if it's a text file
                    sample = f.read(1024)
                    if b'\0' in sample:  # Binary file detected
                        logger.debug(f"Skipping binary file: {log_file}")
                        continue
                
                # Now read as text
                with open(log_file, 'r', errors='replace') as f:
                    content = f.read()
                
                # Look for uname output
                uname_matches = re.finditer(r'Linux \S+ ([0-9]+\.[0-9]+\.[0-9]+[^\s]*)', content)
                for match in uname_matches:
                    version = match.group(1)
                    versions.append({
                        "version": version,
                        "source": log_file,
                        "details": f"Found in log file: {log_file}\nMatched string: {match.group(0)}"
                    })
                    logger.info(f"Found kernel version {version} from log file: {log_file}")
            except Exception as e:
                logger.warning(f"Error extracting kernel version from log {log_file}: {e}")
        
        return versions
    
    def _find_module_dirs(self) -> List[str]:
        """Find kernel module directories in common locations."""
        module_dirs = []
        
        # Check standard location
        for lib_path in ["lib/modules", "usr/lib/modules"]:
            if os.path.exists(os.path.join(self.firmware_path, lib_path)):
                for item in os.listdir(os.path.join(self.firmware_path, lib_path)):
                    full_path = os.path.join(self.firmware_path, lib_path, item)
                    if os.path.isdir(full_path) and self._is_valid_kernel_version(item):
                        module_dirs.append(full_path)
        
        return module_dirs
    
    def _find_kernel_config_files(self) -> List[str]:
        """Find kernel config files in common locations."""
        config_files = []
        
        # Common kernel config patterns
        config_patterns = [
            "config-*",
            ".config",
            "kernel_config"
        ]
        
        # Look in standard locations
        for config_path in ["boot", "usr/src/linux"]:
            for pattern in config_patterns:
                path_pattern = os.path.join(config_path, pattern)
                config_files.extend(self._find_files(path_pattern))
        
        # Look for standalone config files
        for pattern in config_patterns:
            for cfg in self._find_files(pattern):
                # Check if it's a valid kernel config
                if self._is_valid_kernel_config(cfg):
                    config_files.append(cfg)
        
        return config_files
    
    #One more method to detect kernel version by strings output of kernel binary, need to regex for pattern 

    def _is_valid_kernel_version(self, version: str) -> bool:
        """Check if a string looks like a valid kernel version."""
        return bool(re.match(r"^[0-9]+\.[0-9]+\.[0-9]+", version))
    
    def _is_valid_kernel_config(self, config_file: str) -> bool:
        """Check if a file looks like a valid kernel config file."""
        try:
            with open(config_file, 'r') as f:
                content = f.read(500)  # Read just the beginning
                return any(marker in content for marker in [
                    "CONFIG_KERNEL",
                    "# Linux/",
                    "Automatically generated"
                ])
        except Exception:
            return False

class KernelPreemption(BaseAnalyzer):
    """Class responsible for determining the kernel preemption model."""
    
    def detect(self, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect kernel preemption model from various sources.
        
        Args:
            rootfs_path: Path to rootfs
            
        Returns:
            Dictionary with preemption models, occurrence counts, and detection sources
        """
        preemption_models = {
            "models": {
                "voluntary": 0,      # Server/Voluntary preemption
                "desktop": 0,        # Low-latency desktop preemption
                "rt": 0              # RT preemption (PREEMPT_RT)
            },
            "sources": {
                "modinfo": [],       # Store all modinfo results
                "kernel_config": []  # Store all kernel config results
            }
        }
        
        # 1. Find kernel modules (.ko files)
        logger.info("Looking for kernel modules to detect preemption model")
        self._detect_from_kernel_modules_path(preemption_models, rootfs_path)
        
        # 2. Check kernel config
        self._detect_from_kernel_config(preemption_models)
        
        return preemption_models
        
    def _detect_from_kernel_modules_path(self, preemption_models: Dict[str, Any], rootfs_path: Optional[str] = None) -> None:
        """
        Detect preemption model from kernel modules using modinfo.
        
        Args:
            preemption_models: Dictionary to update with findings
            rootfs_path: Path to rootfs
        """
        # Store unique vermagic outputs
        unique_vermagics = {}
        
        # Check kernel modules in rootfs first (if available)
        if rootfs_path and os.path.exists(rootfs_path):
            try:
                # Use modinfo on .ko files in rootfs
                ko_files = self._find_files("*.ko", rootfs_path)
                # logger.info(f"Found {len(ko_files)} .ko files in rootfs")
                
                for ko_file in ko_files:
                    try:
                        # Use the centralized modinfo method
                        modinfo_data = self.get_modinfo_data(ko_file)
                        
                        # Get vermagic from parsed data
                        vermagic = modinfo_data.get("vermagic", "")
                        
                        if vermagic:
                            # Store unique vermagic outputs
                            if vermagic not in unique_vermagics:
                                unique_vermagics[vermagic] = [ko_file]
                            else:
                                unique_vermagics[vermagic].append(ko_file)
                            
                            # Update model counts based on vermagic content
                            vermagic_lower = vermagic.lower()
                            if "preempt_rt" in vermagic_lower:
                                preemption_models["models"]["rt"] += 1
                            elif "preempt" in vermagic_lower:
                                preemption_models["models"]["desktop"] += 1
                            else:
                                # No preempt string = Server/Voluntary preemption
                                preemption_models["models"]["voluntary"] += 1
                    except Exception as e:
                        logger.warning(f"Error processing kernel module {ko_file}: {str(e)}")
            except Exception as e:
                logger.warning(f"Error scanning rootfs for kernel modules: {str(e)}")
        
        # Store only unique vermagic outputs in the results
        for vermagic, files in unique_vermagics.items():
            if len(files) == 1:
                # Only one file has this vermagic
                relative_path = self._get_relative_path(files[0], rootfs_path)
                preemption_models["sources"]["modinfo"].append({
                    "file": relative_path,
                    "vermagic": vermagic,
                    "type": "Single Module"
                })
            elif len(files) > 1 and len(unique_vermagics) == 1:
                # Only one unique vermagic for all files
                preemption_models["sources"]["modinfo"].append({
                    "file": "all_modules",
                    "vermagic": vermagic,
                    "type": "All Modules"
                })
            else:
                # Multiple files with same vermagic, group them
                file_count = len(files)
                
                if file_count > 3:
                    sample_files = [self._get_relative_path(f, rootfs_path) for f in files[:3]]
                    group_path = f"group ({file_count} files including {', '.join(sample_files)}, ...)"
                else:
                    file_paths = [self._get_relative_path(f, rootfs_path) for f in files]
                    group_path = f"group ({', '.join(file_paths)})"
                
                preemption_models["sources"]["modinfo"].append({
                    "file": group_path,
                    "vermagic": vermagic,
                    "type": "Module Group"
                })
    
    def _detect_from_kernel_config(self, preemption_models: Dict[str, Any]) -> None:
        """
        Detect preemption model from kernel config file.
        
        Args:
            preemption_models: Dictionary to update with findings
        """
        # Check kernel config
        kernel_config = self._find_kernel_config()
        if kernel_config and os.path.exists(kernel_config):
            try:
                # Checking kernel config for preemption settings
                with open(kernel_config, 'r', errors='replace') as f:
                    config_content = f.read()
                
                # Check for RT preemption
                rt_match = re.search(r'CONFIG_PREEMPT_RT\s*=\s*[y]', config_content, re.IGNORECASE)
                if rt_match:
                    result = {
                        "file": kernel_config,
                        "config": rt_match.group(0),
                        "type": "RT Preemption (Basic or Full RT)"
                    }
                    preemption_models["sources"]["kernel_config"].append(result)
                    preemption_models["models"]["rt"] += 1
                
                # Check for desktop preemption
                elif re.search(r'CONFIG_PREEMPT\s*=\s*[y]', config_content, re.IGNORECASE):
                    result = {
                        "file": kernel_config,
                        "config": "CONFIG_PREEMPT=y",
                        "type": "Low-Latency Desktop Preemption"
                    }
                    preemption_models["sources"]["kernel_config"].append(result)
                    preemption_models["models"]["desktop"] += 1
                
                # Check for voluntary preemption
                elif re.search(r'CONFIG_PREEMPT_VOLUNTARY\s*=\s*[y]', config_content, re.IGNORECASE):
                    result = {
                        "file": kernel_config,
                        "config": "CONFIG_PREEMPT_VOLUNTARY=y",
                        "type": "Server or Voluntary Preemption"
                    }
                    preemption_models["sources"]["kernel_config"].append(result)
                    preemption_models["models"]["voluntary"] += 1
                # No preempt = Server preemption (fully non-preemptible)
                else:
                    result = {
                        "file": kernel_config,
                        "config": "No preempt config found (assumed Server/Voluntary)",
                        "type": "Server or Voluntary Preemption"
                    }
                    preemption_models["sources"]["kernel_config"].append(result)
                    preemption_models["models"]["voluntary"] += 1
                
                # Add all preemption-related config entries to the results
                preempt_configs = []
                for line in config_content.splitlines():
                    if "CONFIG_PREEMPT" in line:
                        preempt_configs.append(line.strip())
                
                if preempt_configs:
                    for config in preempt_configs:
                        result = {
                            "file": kernel_config,
                            "config": config,
                            "type": "Additional Config"
                        }
                        preemption_models["sources"]["kernel_config"].append(result)
                
            except Exception as e:
                logger.warning(f"Error checking kernel config: {str(e)}")
        
    def _get_relative_path(self, path: str, rootfs_path: Optional[str] = None) -> str:
        """
        Get the path relative to rootfs.
        
        Args:
            path: Absolute file path
            rootfs_path: Path to rootfs
            
        Returns:
            Path relative to rootfs or the original path if not under rootfs
        """
        if rootfs_path and os.path.exists(rootfs_path):
            try:
                common_path = os.path.commonpath([path, rootfs_path])
                if common_path == rootfs_path:
                    return os.path.relpath(path, rootfs_path)
            except ValueError:
                # Paths are on different drives
                pass
        return path
        
    def _find_kernel_config(self) -> Optional[str]:
        """Find kernel config file in common locations"""
        # Common kernel config file names and paths
        config_patterns = [
            ".config",
            "config-*",
            "kernel_config",
            "*_defconfig"
        ]
        
        # Common locations for kernel config
        config_locations = [
            "boot/",
            "etc/",
            "usr/src/linux/",
            "usr/src/linux-headers-*/",
        ]
        
        # Try looking in specific locations first
        for location in config_locations:
            for pattern in config_patterns:
                path_pattern = os.path.join(location, pattern)
                configs = self._find_files(path_pattern)
                if configs:
                    # Validate it's a real kernel config file
                    for config in configs:
                        if self._is_valid_kernel_config(config):
                            # logger.info(f"Found valid kernel config at {config}")
                            return config
        
        # Try searching in the entire firmware
        for pattern in config_patterns:
            configs = self._find_files(pattern)
            if configs:
                # Validate it's a real kernel config file
                for config in configs:
                    if self._is_valid_kernel_config(config):
                        # logger.info(f"Found valid kernel config at {config}")
                        return config
                
        return None
    
    def _is_valid_kernel_config(self, config_file: str) -> bool:
        """
        Check if a file is a valid kernel config file.
        
        Args:
            config_file: Path to the config file to validate
            
        Returns:
            True if it's a valid kernel config, False otherwise
        """
        try:
            with open(config_file, 'r') as f:
                content = f.read(500)  # Read just the beginning
                
                # Check for common kernel config markers
                kernel_config_markers = [
                    "CONFIG_KERNEL",
                    "CONFIG_ARM",
                    "CONFIG_X86",
                    "CONFIG_MIPS",
                    "CONFIG_PREEMPT",
                    "CONFIG_SMP",
                    "# Linux/",
                    "# Automatically generated make config"
                ]
                
                # A valid kernel config should contain at least one of these markers
                for marker in kernel_config_markers:
                    if marker in content:
                        return True
                
                # If none of the markers are found, it's probably not a kernel config
                return False
                
        except Exception as e:
            logger.warning(f"Error validating kernel config {config_file}: {str(e)}")
            return False
        
    def get_best_match(self, preemption_data: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Get the best matching preemption model based on occurrence counts.
        
        Args:
            preemption_data: Optional preemption data to use instead of calling detect()
            
        Returns:
            String with human-readable preemption model or None
        """
        # Use provided data or get preemption model counts
        if preemption_data is None:
            preemption_data = self.detect()
        preemption_models = preemption_data["models"]
        
        # Find the model with highest count
        max_count = 0
        best_model = None
        
        for model, count in preemption_models.items():
            if count > max_count:
                max_count = count
                best_model = model
        
        # Return human-readable name
        if best_model == "rt":
            return "Real-Time Preemption (PREEMPT_RT)"
        elif best_model == "desktop":
            return "Preemptible Kernel (Low-Latency Desktop)" 
        elif best_model == "voluntary":
            return "Non-Preemptible or Voluntary Preemption"
        
        return None

class KernelConfig(BaseAnalyzer):
    """Class responsible for extracting and analyzing kernel configs."""
    
    def extract(self, kernel_binary: str) -> Optional[str]:
        """
        Extract kernel config from kernel binary if available.
        
        Args:
            kernel_binary: Path to the kernel binary
            
        Returns:
            Path to extracted config file or None if extraction failed
        """
        if not os.path.exists(kernel_binary):
            logger.error(f"Kernel binary not found: {kernel_binary}")
            return None
            
        try:
            # Create a temporary directory for extraction
            temp_dir = os.path.join(os.path.dirname(kernel_binary), "extracted_config")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Extract config using scripts/extract-ikconfig
            # Note: This assumes extract-ikconfig is available in the system
            extract_cmd = ["extract-ikconfig", kernel_binary]
            
            # Define output file path
            output_file = os.path.join(temp_dir, "kernel_config")
            
            with open(output_file, 'w') as f:
                # Use _get_command_output instead of _run_command
                extract_output = self._get_command_output("extract-ikconfig", [kernel_binary])
                f.write(extract_output)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                logger.info(f"Successfully extracted kernel config to {output_file}")
                return output_file
            else:
                logger.warning("Extraction command completed but config file is empty")
                # Fallback: try to find .config in the same directory
                config_file = os.path.join(os.path.dirname(kernel_binary), ".config")
                if os.path.exists(config_file):
                    return config_file
                return None
                
        except Exception as e:
            logger.error(f"Error extracting kernel config: {e}")
            return None

class KernelModules(BaseAnalyzer):
    """Class responsible for analyzing kernel modules."""
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze kernel modules in the firmware.
        
        Returns:
            Dictionary with module information
        """
        # Count different types of kernel modules
        module_types = {}
        total_count = 0
        
        # Store module paths by type
        ko_modules = []
        o_modules = []
        
        # Find .ko files (loadable kernel modules)
        ko_files = self._find_files("*.ko")
        if ko_files:
            module_types["ko"] = len(ko_files)
            total_count += len(ko_files)
            ko_modules = ko_files
            logger.info(f"Found {len(ko_files)} .ko modules")
        
        # Find .o files (older kernel modules)
        o_files = self._find_files("*.o")
        if o_files:
            module_types["o"] = len(o_files)
            total_count += len(o_files)
            o_modules = o_files
            logger.info(f"Found {len(o_files)} .o modules")
        
        # Find other potential module types
        for ext in ["*.ko.gz", "*.ko.xz", "*.ko.zst"]:
            files = self._find_files(ext)
            if files:
                module_types[ext[1:]] = len(files)
                total_count += len(files)
                logger.info(f"Found {len(files)} {ext[1:]} modules")
        
        # Search in rootfs if it exists
        rootfs_path = self.firmware_path / "rootfs"
        if rootfs_path.exists() and rootfs_path.is_dir():
            logger.info(f"Searching for kernel modules in rootfs: {rootfs_path}")
            
            # Find .ko files in rootfs
            try:
                rootfs_ko_files = list(rootfs_path.glob("**/*.ko"))
                if rootfs_ko_files:
                    if "ko" not in module_types:
                        module_types["ko"] = 0
                    module_types["ko"] += len(rootfs_ko_files)
                    total_count += len(rootfs_ko_files)
                    ko_modules.extend([str(f) for f in rootfs_ko_files])
                    logger.info(f"Found {len(rootfs_ko_files)} .ko modules in rootfs")
            except Exception as e:
                logger.error(f"Error finding .ko files in rootfs: {e}")
            
            # Find .o files in rootfs
            try:
                rootfs_o_files = list(rootfs_path.glob("**/*.o"))
                if rootfs_o_files:
                    if "o" not in module_types:
                        module_types["o"] = 0
                    module_types["o"] += len(rootfs_o_files)
                    total_count += len(rootfs_o_files)
                    o_modules.extend([str(f) for f in rootfs_o_files])
                    logger.info(f"Found {len(rootfs_o_files)} .o modules in rootfs")
            except Exception as e:
                logger.error(f"Error finding .o files in rootfs: {e}")
        
        return {
            "module_count": total_count,
            "module_types": module_types,
            "ko_modules": ko_modules,
            "o_modules": o_modules
        }

class BootParameters(BaseAnalyzer):
    """Class responsible for extracting kernel parameters and boot arguments."""
    
    def extract(self, kernel_binary: Optional[str] = None, kernel_csv_log: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Extract kernel boot parameters and init settings.
        
        Args:
            kernel_binary: Path to kernel binary file (optional)
            kernel_csv_log: Path to kernel CSV log file (optional)
            
        Returns:
            Dictionary with parameter types as keys and found parameters as values
        """
        results = {
            "init_params": [],
            "rdinit_params": [],
            "init_entries": []
        }
        
        # Extract from kernel binary
        if kernel_binary and os.path.exists(kernel_binary):
            try:
                # Get strings output using centralized method
                strings_output = self._get_strings_output(kernel_binary)
                
                # Extract init parameters
                for line in strings_output.splitlines():
                    if "init=/" in line:
                        if "rdinit=" in line:
                            param = re.search(r'rdinit=[^\s"]*', line)
                            if param:
                                results["rdinit_params"].append(param.group(0))
                        else:
                            param = re.search(r'init=[^\s"]*', line)
                            if param:
                                results["init_params"].append(param.group(0))
            except Exception as e:
                logger.warning(f"Error processing kernel binary {kernel_binary}: {e}")
        
        # Extract from CSV log
        if kernel_csv_log and os.path.exists(kernel_csv_log):
            try:
                with open(kernel_csv_log, 'r') as f:
                    for line in f:
                        if ";rdinit=/" in line:
                            parts = line.split(";")
                            if len(parts) >= 5:
                                param = re.search(r'rdinit=[^\s]*', parts[4])
                                if param:
                                    results["rdinit_params"].append(param.group(0))
                        
                        if ";init=/" in line:
                            parts = line.split(";")
                            if len(parts) >= 5:
                                param = re.search(r'init=[^\s]*', parts[4])
                                if param:
                                    results["init_entries"].append(param.group(0))
            except Exception as e:
                logger.warning(f"Error processing CSV log {kernel_csv_log}: {e}")
        
        # Remove duplicates and sort
        for key in results:
            results[key] = sorted(list(set(results[key])))
            
        return {k: v for k, v in results.items() if v}  # Filter out empty results
    
    def find_init_params_from_csv(self, csv_log_file: str) -> List[str]:
        """
        Extract init parameters from CSV log file.
        
        Args:
            csv_log_file: Path to CSV log file
            
        Returns:
            List of init parameters
        """
        init_params = []
        
        if not os.path.exists(csv_log_file):
            logger.error(f"CSV log file not found: {csv_log_file}")
            return init_params
            
        try:
            with open(csv_log_file, 'r') as f:
                for line in f:
                    if ";init=/" in line:
                        parts = line.split(";")
                        if len(parts) >= 5:
                            param = re.search(r'init=[^\s]*', parts[4])
                            if param:
                                init_params.append(param.group(0))
        except Exception as e:
            logger.error(f"Error processing CSV log file {csv_log_file}: {e}")
            
        return sorted(list(set(init_params)))

class GetArchi(BaseAnalyzer):
    """Class responsible for determining CPU architecture."""
    
    # Common binaries likely to be found in firmware images
    COMMON_BINARIES = [
        "busybox", "sh", "bash", "sshd", "dropbear", "httpd", "telnetd", "udhcpc", "ifconfig"
    ]
    
    def detect(self, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect CPU architecture from binaries.
        
        Args:
            rootfs_path: Path to rootfs (optional, will search in firmware_path otherwise)
            
        Returns:
            Dictionary with detected architectures, consolidated command outputs, and source references
        """
        architectures = set()
        all_detection_details = []
        architecture_sources = {}
        
        # Find binaries to analyze
        binaries = self._find_binaries_to_analyze(rootfs_path)
        
        # Analyze each binary
        for binary_path in binaries:
            try:
                # Use 'file' command to get basic info
                file_output = self._get_file_output(binary_path)
                
                # Try to determine architecture from file output
                arch = self._parse_architecture_from_file(file_output)
                if arch:
                    architectures.add(arch)
                    
                    # Create source reference pointing to saved file
                    source_ref = self._find_text_in_saved_output("file_output.txt", arch, binary_path)
                    if not source_ref:
                        # Fallback source reference
                        source_ref = self._create_source_reference(
                            "file_output.txt", binary_path, f"file {binary_path}", 
                            f"Architecture: {arch}", None
                        )
                    
                    # Store source reference for this architecture
                    if arch not in architecture_sources:
                        architecture_sources[arch] = []
                    architecture_sources[arch].append(source_ref)
                    
                    all_detection_details.append({
                        "binary": binary_path,
                        "command": f"file {binary_path}",
                        "output": file_output,
                        "detected_arch": arch,
                        "method": "file",
                        "source_reference": source_ref
                    })
                
                # Use readelf for more detailed info
                if shutil.which("readelf"):
                    readelf_output = self._get_readelf_output(binary_path, "-h")
                    arch_from_readelf = self._get_architecture_from_readelf(binary_path)
                    if arch_from_readelf:
                        architectures.add(arch_from_readelf)
                        
                        # Create source reference pointing to saved file
                        source_ref = self._find_text_in_saved_output("readelf_h_output.txt", "Machine:", binary_path)
                        if not source_ref:
                            # Fallback source reference
                            source_ref = self._create_source_reference(
                                "readelf_h_output.txt", binary_path, f"readelf -h {binary_path}",
                                f"Architecture: {arch_from_readelf}", None
                            )
                        
                        # Store source reference for this architecture
                        if arch_from_readelf not in architecture_sources:
                            architecture_sources[arch_from_readelf] = []
                        architecture_sources[arch_from_readelf].append(source_ref)
                        
                        all_detection_details.append({
                            "binary": binary_path,
                            "command": f"readelf -h {binary_path}",
                            "output": readelf_output,
                            "detected_arch": arch_from_readelf,
                            "method": "readelf",
                            "source_reference": source_ref
                        })
                
            except Exception as e:
                logger.warning(f"Error analyzing binary {binary_path}: {e}")
        
        # Consolidate detection details - prefer one representative sample per method
        consolidated_details = self._consolidate_detection_details(all_detection_details)
        
        return {
            "architectures": list(architectures),
            "architecture_sources": architecture_sources,
            "detection_details": consolidated_details
        }
    
    def _consolidate_detection_details(self, all_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolidate detection details to show one representative sample per command,
        grouping by exact command rather than method+value to avoid duplicates.
        """
        # Group by exact command to avoid duplicates in final output
        command_groups = {}
        for detail in all_details:
            # Create key based on binary and command to group identical executions
            binary_path = detail["binary"]
            command = detail["command"]
            key = f"{binary_path}||{command}"
            
            if key not in command_groups:
                command_groups[key] = []
            command_groups[key].append(detail)
        
        # For each unique command, pick one representative
        consolidated = []
        for key, details in command_groups.items():
            # Pick the first one as representative
            representative = details[0]
            
            # If multiple entries exist for same command (shouldn't happen), mention it
            if len(details) > 1:
                representative["note"] = f"Same command executed {len(details)} times"
            
            consolidated.append(representative)
        
        return consolidated
    
    def detect_simple(self, rootfs_path: Optional[str] = None) -> List[str]:
        """
        Simple detection method that returns just the architecture list for backward compatibility.
        
        Args:
            rootfs_path: Path to rootfs (optional, will search in firmware_path otherwise)
            
        Returns:
            List of detected architectures
        """
        result = self.detect(rootfs_path)
        return result["architectures"]
    
    def _find_binaries_to_analyze(self, rootfs_path: Optional[str] = None) -> List[str]:
        """
        Find binaries to analyze for architecture detection.
        
        Args:
            rootfs_path: Path to rootfs
            
        Returns:
            List of binary paths
        """
        binaries = []
        
        # Determine search path
        search_path = self.firmware_path
        if rootfs_path and os.path.exists(rootfs_path):
            search_path = Path(rootfs_path)
        else:
            # Try to find rootfs in firmware path
            for d in ["rootfs", "root", "squashfs-root"]:
                potential_path = self.firmware_path / d
                if potential_path.exists() and potential_path.is_dir():
                    search_path = potential_path
                    break
        
        # Find common binaries
        for binary_name in self.COMMON_BINARIES:
            # Look for exact matches
            for root, _, files in os.walk(search_path):
                if binary_name in files:
                    binary_path = os.path.join(root, binary_name)
                    # Check if it's an executable
                    if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
                        binaries.append(binary_path)
                        break  # Found this binary, move to next
        
        # Limit to 5 binaries max
        return binaries[:5]
    
    def _parse_architecture_from_file(self, file_output: str) -> Optional[str]:
        """
        Parse architecture from file command output.
        
        Args:
            file_output: Output from file command
            
        Returns:
            Architecture name or None if not detected
        """
        return detect_architecture_from_text(file_output)
    
    def _get_architecture_from_readelf(self, binary_path: str) -> Optional[str]:
        """
        Extract architecture information using readelf.
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            Architecture name or None if not detected
        """
        readelf_output = self._get_readelf_output(binary_path, "-h")
        return detect_architecture_from_readelf_output(readelf_output)

class GetEndianess(BaseAnalyzer):
    """Class responsible for determining endianness."""
    
    def detect(self, binary_path: Optional[str] = None, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect endianness from binaries.
        
        Args:
            binary_path: Optional specific binary to check
            rootfs_path: Optional path to rootfs directory
            
        Returns:
            Dictionary with detected endianness, consolidated command outputs, and source references
        """
        results = []
        all_detection_details = []
        endianness_sources = {}
        
        # Check specific binary if provided
        if binary_path and os.path.exists(binary_path):
            logger.info(f"Checking endianness for specific binary: {binary_path}")
            endianness, details = self._get_endianness_for_binary_with_details(binary_path)
            if endianness:
                results.append(endianness)
                all_detection_details.extend(details)
                
                # Create source reference
                source_ref = self._find_text_in_saved_output("readelf_h_output.txt", "Data:", binary_path)
                if not source_ref:
                    source_ref = self._find_text_in_saved_output("file_output.txt", "endian", binary_path)
                if not source_ref:
                    source_ref = self._create_source_reference(
                        "readelf_h_output.txt", binary_path, f"readelf -h {binary_path}",
                        f"Endianness: {endianness}", None
                    )
                
                endianness_sources[endianness] = [source_ref]
                logger.info(f"Detected endianness from specific binary: {endianness}")
        
        # Otherwise check binaries in rootfs
        elif rootfs_path:
            logger.info(f"Scanning rootfs for binaries to determine endianness: {rootfs_path}")
            search_path = Path(rootfs_path)
            
            # Common paths to check for binaries
            binary_paths = []
            common_binary_dirs = ["bin", "sbin", "usr/bin", "usr/sbin"]
            common_binaries = ["busybox", "sh", "ls", "cat", "init"]
            
            # First look for common binaries
            for bin_dir in common_binary_dirs:
                for binary in common_binaries:
                    bin_path = search_path / bin_dir / binary
                    if bin_path.exists() and bin_path.is_file():
                        binary_paths.append(str(bin_path))
                        logger.info(f"Found common binary for endianness detection: {bin_path}")
            
            # If no common binaries found, look for any executable
            if not binary_paths:
                logger.info("No common binaries found, looking for any executable")
                for bin_dir in common_binary_dirs:
                    bin_dir_path = search_path / bin_dir
                    if bin_dir_path.exists() and bin_dir_path.is_dir():
                        for item in bin_dir_path.iterdir():
                            if item.is_file() and os.access(item, os.X_OK):
                                binary_paths.append(str(item))
                                logger.info(f"Found executable for endianness detection: {item}")
                                if len(binary_paths) >= 5:  # Limit to 5 binaries for performance
                                    break
                        if len(binary_paths) >= 5:
                            break
            
            # Check found binaries
            for binary in binary_paths:
                endianness, details = self._get_endianness_for_binary_with_details(binary)
                if endianness and endianness not in results:
                    results.append(endianness)
                    all_detection_details.extend(details)
                    
                    # Create source reference
                    source_ref = self._find_text_in_saved_output("readelf_h_output.txt", "Data:", binary)
                    if not source_ref:
                        source_ref = self._find_text_in_saved_output("file_output.txt", "endian", binary)
                    if not source_ref:
                        source_ref = self._create_source_reference(
                            "readelf_h_output.txt", binary, f"readelf -h {binary}",
                            f"Endianness: {endianness}", None
                        )
                    
                    if endianness not in endianness_sources:
                        endianness_sources[endianness] = []
                    endianness_sources[endianness].append(source_ref)
                    
                    logger.info(f"Detected endianness from {binary}: {endianness}")
                    if len(results) >= 1:  # One is enough
                        break
        
        # Consolidate detection details
        consolidated_details = self._consolidate_endianness_details(all_detection_details)
        
        return {
            "endianness": results,
            "endianness_sources": endianness_sources,
            "detection_details": consolidated_details
        }
    
    def _consolidate_endianness_details(self, all_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolidate endianness detection details to avoid redundant outputs.
        """
        # Group by exact command to avoid duplicates in final output
        command_groups = {}
        for detail in all_details:
            # Create key based on binary and command to group identical executions
            binary_path = detail["binary"]
            command = detail["command"]
            key = f"{binary_path}||{command}"
            
            if key not in command_groups:
                command_groups[key] = []
            command_groups[key].append(detail)
        
        # For each unique command, pick one representative
        consolidated = []
        for key, details in command_groups.items():
            # Pick the first one as representative
            representative = details[0]
            
            # If multiple entries exist for same command (shouldn't happen), mention it
            if len(details) > 1:
                representative["note"] = f"Same command executed {len(details)} times"
            
            consolidated.append(representative)
        
        return consolidated
    
    def detect_simple(self, binary_path: Optional[str] = None, rootfs_path: Optional[str] = None) -> List[str]:
        """
        Simple detection method that returns just the endianness list for backward compatibility.
        
        Args:
            binary_path: Optional specific binary to check
            rootfs_path: Optional path to rootfs directory
            
        Returns:
            List of detected endianness values
        """
        result = self.detect(binary_path, rootfs_path)
        return result["endianness"]
    
    def _get_endianness_for_binary_with_details(self, binary_path: str) -> Tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Get endianness for a specific binary with command output details.
        
        Args:
            binary_path: Path to binary
            
        Returns:
            Tuple of (endianness as string or None, list of detection details)
        """
        details = []
        
        try:
            # Try readelf first
            readelf_output = self._get_readelf_output(binary_path, "-h")
            
            if "Data:" in readelf_output:
                data_line = [line for line in readelf_output.split('\n') if "Data:" in line][0]
                
                details.append({
                    "binary": binary_path,
                    "command": f"readelf -h {binary_path}",
                    "output": readelf_output,
                    "method": "readelf"
                })
                
                if "little endian" in data_line.lower():
                    return "little", details
                elif "big endian" in data_line.lower():
                    return "big", details
            
            # Fall back to file command
            file_output = self._get_file_output(binary_path)
            
            details.append({
                "binary": binary_path,
                "command": f"file {binary_path}",
                "output": file_output,
                "method": "file"
            })
            
            if "LSB" in file_output or "little endian" in file_output.lower():
                return "little", details
            elif "MSB" in file_output or "big endian" in file_output.lower():
                return "big", details
            
        except Exception as e:
            logger.error(f"Error determining endianness for {binary_path}: {e}")
        
        return None, details


class GetBitWidth(BaseAnalyzer):
    """Class responsible for determining architecture bit width."""
    
    def detect(self, binary_path: Optional[str] = None, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect architecture bit width from binaries.
        
        Args:
            binary_path: Optional specific binary to check
            rootfs_path: Optional path to rootfs directory
            
        Returns:
            Dictionary with detected bit width, consolidated command outputs, and source references
        """
        results = []
        all_detection_details = []
        bit_width_sources = {}
        
        # Check specific binary if provided
        if binary_path and os.path.exists(binary_path):
            logger.info(f"Checking bit width for specific binary: {binary_path}")
            bit_width, details = self._get_bit_width_for_binary_with_details(binary_path)
            if bit_width:
                results.append(bit_width)
                all_detection_details.extend(details)
                
                # Create source reference
                source_ref = self._find_text_in_saved_output("readelf_h_output.txt", "Class:", binary_path)
                if not source_ref:
                    source_ref = self._find_text_in_saved_output("file_output.txt", f"{bit_width}-bit", binary_path)
                if not source_ref:
                    source_ref = self._create_source_reference(
                        "readelf_h_output.txt", binary_path, f"readelf -h {binary_path}",
                        f"Bit width: {bit_width}", None
                    )
                
                bit_width_sources[bit_width] = [source_ref]
                logger.info(f"Detected bit width from specific binary: {bit_width}")
        
        # Otherwise check binaries in rootfs
        elif rootfs_path:
            logger.info(f"Scanning rootfs for binaries to determine bit width: {rootfs_path}")
            search_path = Path(rootfs_path)
            
            # Common paths to check for binaries
            binary_paths = []
            common_binary_dirs = ["bin", "sbin", "usr/bin", "usr/sbin"]
            common_binaries = ["busybox", "sh", "ls", "cat", "init"]
            
            # First look for common binaries
            for bin_dir in common_binary_dirs:
                for binary in common_binaries:
                    bin_path = search_path / bin_dir / binary
                    if bin_path.exists() and bin_path.is_file():
                        binary_paths.append(str(bin_path))
                        logger.info(f"Found common binary for bit width detection: {bin_path}")
            
            # If no common binaries found, look for any executable
            if not binary_paths:
                logger.info("No common binaries found, looking for any executable")
                for bin_dir in common_binary_dirs:
                    bin_dir_path = search_path / bin_dir
                    if bin_dir_path.exists() and bin_dir_path.is_dir():
                        for item in bin_dir_path.iterdir():
                            if item.is_file() and os.access(item, os.X_OK):
                                binary_paths.append(str(item))
                                logger.info(f"Found executable for bit width detection: {item}")
                                if len(binary_paths) >= 5:  # Limit to 5 binaries for performance
                                    break
                        if len(binary_paths) >= 5:
                            break
            
            # Check found binaries
            for binary in binary_paths:
                bit_width, details = self._get_bit_width_for_binary_with_details(binary)
                if bit_width and bit_width not in results:
                    results.append(bit_width)
                    all_detection_details.extend(details)
                    
                    # Create source reference
                    source_ref = self._find_text_in_saved_output("readelf_h_output.txt", "Class:", binary)
                    if not source_ref:
                        source_ref = self._find_text_in_saved_output("file_output.txt", f"{bit_width}-bit", binary)
                    if not source_ref:
                        source_ref = self._create_source_reference(
                            "readelf_h_output.txt", binary, f"readelf -h {binary}",
                            f"Bit width: {bit_width}", None
                        )
                    
                    if bit_width not in bit_width_sources:
                        bit_width_sources[bit_width] = []
                    bit_width_sources[bit_width].append(source_ref)
                    
                    logger.info(f"Detected bit width from {binary}: {bit_width}")
                    if len(results) >= 1:  # One is enough
                        break
        
        # Consolidate detection details
        consolidated_details = self._consolidate_bit_width_details(all_detection_details)
        
        return {
            "bit_width": results,
            "bit_width_sources": bit_width_sources,
            "detection_details": consolidated_details
        }
    
    def _consolidate_bit_width_details(self, all_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolidate bit width detection details to avoid redundant outputs.
        """
        # Group by exact command to avoid duplicates in final output
        command_groups = {}
        for detail in all_details:
            # Create key based on binary and command to group identical executions
            binary_path = detail["binary"]
            command = detail["command"]
            key = f"{binary_path}||{command}"
            
            if key not in command_groups:
                command_groups[key] = []
            command_groups[key].append(detail)
        
        # For each unique command, pick one representative
        consolidated = []
        for key, details in command_groups.items():
            # Pick the first one as representative
            representative = details[0]
            
            # If multiple entries exist for same command (shouldn't happen), mention it
            if len(details) > 1:
                representative["note"] = f"Same command executed {len(details)} times"
            
            consolidated.append(representative)
        
        return consolidated
    
    def detect_simple(self, binary_path: Optional[str] = None, rootfs_path: Optional[str] = None) -> List[str]:
        """
        Simple detection method that returns just the bit width list for backward compatibility.
        
        Args:
            binary_path: Optional specific binary to check
            rootfs_path: Optional path to rootfs directory
            
        Returns:
            List of detected bit width values
        """
        result = self.detect(binary_path, rootfs_path)
        return result["bit_width"]
    
    def _get_bit_width_for_binary_with_details(self, binary_path: str) -> Tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Get bit width for a specific binary with command output details.
        
        Args:
            binary_path: Path to binary
            
        Returns:
            Tuple of (bit width as string or None, list of detection details)
        """
        details = []
        
        try:
            # Try readelf first
            readelf_output = self._get_readelf_output(binary_path, "-h")
            
            if "Class:" in readelf_output:
                class_line = [line for line in readelf_output.split('\n') if "Class:" in line][0]
                
                details.append({
                    "binary": binary_path,
                    "command": f"readelf -h {binary_path}",
                    "output": readelf_output,
                    "method": "readelf"
                })
                
                if "ELF32" in class_line:
                    return "32", details
                elif "ELF64" in class_line:
                    return "64", details
            
            # Fall back to file command
            file_output = self._get_file_output(binary_path)
            
            details.append({
                "binary": binary_path,
                "command": f"file {binary_path}",
                "output": file_output,
                "method": "file"
            })
            
            if "32-bit" in file_output:
                return "32", details
            elif "64-bit" in file_output:
                return "64", details
            
        except Exception as e:
            logger.error(f"Error determining bit width for {binary_path}: {e}")
        
        return None, details

class GetFloatingType(BaseAnalyzer):
    """Class responsible for determining ARM floating point type (hard/soft)."""
    
    def detect(self, binary_path: Optional[str] = None, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect ARM floating point type from binaries.
        
        Args:
            binary_path: Path to specific binary to analyze (optional)
            rootfs_path: Path to rootfs (optional, will search in firmware_path otherwise)
            
        Returns:
            Dictionary with detected floating point types and consolidated command outputs
        """
        floating_types = set()
        all_detection_details = []
        
        # If a specific binary is provided, analyze only that
        if binary_path and os.path.exists(binary_path):
            # Verify it's an ARM binary first
            arch_analyzer = GetArchi(self.firmware_path)
            file_output = self._get_file_output(binary_path)
            arch = arch_analyzer._parse_architecture_from_file(file_output)
            
            if arch == "ARM":
                fp_type, details = self._get_floating_type_for_binary_with_details(binary_path)
                if fp_type:
                    floating_types.add(fp_type)
                    all_detection_details.extend(details)
            
            # Consolidate detection details
            consolidated_details = self._consolidate_floating_type_details(all_detection_details)
            
            return {
                "floating_types": list(floating_types),
                "detection_details": consolidated_details
            }
        
        # Otherwise find ARM binaries to analyze
        arch_analyzer = GetArchi(self.firmware_path)
        all_binaries = arch_analyzer._find_binaries_to_analyze(rootfs_path)
        
        # Filter for ARM binaries
        arm_binaries = []
        for binary in all_binaries:
            file_output = self._get_file_output(binary)
            arch = arch_analyzer._parse_architecture_from_file(file_output)
            if arch == "ARM":
                arm_binaries.append(binary)
        
        # Analyze each ARM binary
        for binary in arm_binaries:
            fp_type, details = self._get_floating_type_for_binary_with_details(binary)
            if fp_type:
                floating_types.add(fp_type)
                all_detection_details.extend(details)
        
        # Consolidate detection details
        consolidated_details = self._consolidate_floating_type_details(all_detection_details)
        
        return {
            "floating_types": list(floating_types),
            "detection_details": consolidated_details
        }
    
    def _consolidate_floating_type_details(self, all_details: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolidate floating point type detection details to avoid redundant outputs.
        """
        # Group by exact command to avoid duplicates in final output
        command_groups = {}
        for detail in all_details:
            # Create key based on binary and command to group identical executions
            binary_path = detail["binary"]
            command = detail["command"]
            key = f"{binary_path}||{command}"
            
            if key not in command_groups:
                command_groups[key] = []
            command_groups[key].append(detail)
        
        # For each unique command, pick one representative
        consolidated = []
        for key, details in command_groups.items():
            # Pick the first one as representative
            representative = details[0]
            
            # If multiple entries exist for same command (shouldn't happen), mention it
            if len(details) > 1:
                representative["note"] = f"Same command executed {len(details)} times"
            
            consolidated.append(representative)
        
        return consolidated
    
    def detect_simple(self, binary_path: Optional[str] = None, rootfs_path: Optional[str] = None) -> List[str]:
        """
        Simple detection method that returns just the floating point types list for backward compatibility.
        
        Args:
            binary_path: Path to specific binary to analyze (optional)
            rootfs_path: Path to rootfs (optional, will search in firmware_path otherwise)
            
        Returns:
            List of detected floating point types ('hard', 'soft')
        """
        result = self.detect(binary_path, rootfs_path)
        return result["floating_types"]
    
    def _get_floating_type_for_binary_with_details(self, binary_path: str) -> Tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Determine ARM floating point type for a binary with command output details.
        
        Args:
            binary_path: Path to ARM binary file
            
        Returns:
            Tuple of ('hard' or 'soft' or None, list of detection details)
        """
        details = []
        
        if not shutil.which("readelf"):
            return None, details
            
        try:
            # Use readelf to check for hard float ABI
            readelf_attributes = self._get_readelf_output(binary_path, "-A")
            
            details.append({
                "binary": binary_path,
                "command": f"readelf -A {binary_path}",
                "output": readelf_attributes,
                "method": "readelf_attributes"
            })
            
            # Check for hard float indicators
            if "VFP registers" in readelf_attributes or "hard-float" in readelf_attributes:
                return "hard", details
            elif "soft-float" in readelf_attributes:
                return "soft", details
            
            # If no explicit indicators, check for VFP/NEON symbols
            readelf_symbols = self._get_readelf_output(binary_path, "-s")
            if readelf_symbols and ("VFP" in readelf_symbols or "NEON" in readelf_symbols):
                details.append({
                    "binary": binary_path,
                    "command": f"readelf -s {binary_path}",
                    "output": readelf_symbols[:1000] + "..." if len(readelf_symbols) > 1000 else readelf_symbols,  # Truncate for display
                    "method": "readelf_symbols"
                })
                return "hard", details
            
            # Check dynamic section for soft float libs
            readelf_dynamic = self._get_readelf_output(binary_path, "-d")
            if readelf_dynamic and "libsoftfp" in readelf_dynamic:
                details.append({
                    "binary": binary_path,
                    "command": f"readelf -d {binary_path}",
                    "output": readelf_dynamic,
                    "method": "readelf_dynamic"
                })
                return "soft", details
            
            # Check file output for clues
            file_output = self._get_file_output(binary_path)
            details.append({
                "binary": binary_path,
                "command": f"file {binary_path}",
                "output": file_output,
                "method": "file"
            })
            
            if "hardfp" in file_output.lower():
                return "hard", details
            elif "softfp" in file_output.lower():
                return "soft", details
                
        except Exception as e:
            logger.warning(f"Error checking ARM float type for {binary_path}: {e}")
            
        return None, details

class InitFinder(BaseAnalyzer):
    """Class responsible for finding init files and analyzing init systems."""
    
    def find_init_files(self, rootfs_path: str = None) -> Dict[str, List[str]]:
        """
        Find init files in the firmware filesystem.
        
        Args:
            rootfs_path: Optional path to the rootfs. If provided, will search only there.
            
        Returns:
            Dictionary with init file types and their paths
        """
        results = {
            "preinit": [],
            "rcS": [],
            "rc.sysinit": [],
            "init": [],
            "linuxrc": [],
            "other_init_scripts": [],
            "inittab": []
        }
        
        # Find common init file names
        init_patterns = ["preinit", "rcS*", "rc.sysinit", "init", "linuxrc"]
        
        # Use provided rootfs_path or try to find it
        search_path = None
        if rootfs_path and os.path.exists(rootfs_path):
            search_path = Path(rootfs_path)
            logger.info(f"Using provided rootfs path for init file search: {search_path}")
        else:
            # Fallback search in rootfs or the entire firmware path
            for d in ["rootfs", "root", "squashfs-root"]:
                potential_path = self.firmware_path / d
                if potential_path.exists() and potential_path.is_dir():
                    search_path = potential_path
                    logger.info(f"Found rootfs directory for init file search: {search_path}")
                    break
            
            # If still not found, use firmware path
            if not search_path:
                search_path = self.firmware_path
                logger.info(f"Using firmware path for init file search: {search_path}")
        
        # Find specific init files - using globbing for more reliable file finding
        for pattern in init_patterns:
            try:
                for match in search_path.glob(f"**/{pattern}"):
                    if match.is_file():
                        file_path = str(match)
                        #logger.info(f"Found init file: {file_path}")
                        if "preinit" in match.name:
                            results["preinit"].append(file_path)
                        elif match.name.startswith("rcS"):
                            results["rcS"].append(file_path)
                        elif "rc.sysinit" in match.name:
                            results["rc.sysinit"].append(file_path)
                        elif match.name == "init":
                            results["init"].append(file_path)
                        elif match.name == "linuxrc":
                            results["linuxrc"].append(file_path)
            except Exception as e:
                logger.error(f"Error searching for {pattern}: {e}")
        
        # Look for other potential init scripts in common locations
        init_dirs = [
            "etc/init.d", 
            "etc/rc.d", 
            "etc/rc.d/init.d", 
            "sbin/init.d"
        ]
        
        for init_dir in init_dirs:
            dir_path = search_path / init_dir
            if dir_path.exists() and dir_path.is_dir():
                for file_path in dir_path.glob("*"):
                    if file_path.is_file() and os.access(file_path, os.X_OK):
                        results["other_init_scripts"].append(str(file_path))
        
        # Parse inittab if exists
        inittab_path = search_path / "etc" / "inittab"
        if inittab_path.exists():
            logger.info(f"Found inittab: {inittab_path}")
            results["inittab"].append(str(inittab_path))
            sysinit_entries = self.parse_inittab_sysinit(str(inittab_path))
            if sysinit_entries:
                results["sysinit_from_inittab"] = sysinit_entries
        
        return {k: v for k, v in results.items() if v}  # Filter out empty results
    
    def parse_inittab_sysinit(self, inittab_path: str) -> List[str]:
        """
        Parse inittab file for sysinit entries.
        
        Args:
            inittab_path: Path to inittab file
            
        Returns:
            List of sysinit entries
        """
        sysinit_entries = []
        
        if not os.path.exists(inittab_path):
            return sysinit_entries
        
        try:
            with open(inittab_path, 'r') as f:
                for line in f:
                    # Skip comments and empty lines
                    if line.strip().startswith('#') or not line.strip():
                        continue
                    
                    # Look for sysinit entries
                    if ":sysinit:" in line:
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            # The last part contains the command
                            cmd = parts[-1].strip()
                            # Extract the first word (command/script)
                            cmd_parts = cmd.split()
                            if cmd_parts:
                                sysinit_entries.append(cmd_parts[0])
                                logger.info(f"Found sysinit entry: {cmd_parts[0]}")
        except Exception as e:
            logger.error(f"Error parsing inittab {inittab_path}: {e}")
        
        return sysinit_entries
    
    def find_init_scripts_location(self, rootfs_path: str = None) -> Dict[str, List[str]]:
        """
        Find init scripts locations in the firmware.
        
        Args:
            rootfs_path: Optional path to the rootfs. If provided, will search only there.
            
        Returns:
            Dictionary with init script types and their locations
        """
        results = {
            "init.d": [],
            "rc.d": [],
            "systemd_units": [],
            "system_services": []
        }
        
        # Use provided rootfs_path or try to find it
        search_path = None
        if rootfs_path and os.path.exists(rootfs_path):
            search_path = Path(rootfs_path)
            logger.info(f"Using provided rootfs path for init scripts search: {search_path}")
        else:
            # Fallback search in rootfs or the entire firmware path
            for d in ["rootfs", "root", "squashfs-root"]:
                potential_path = self.firmware_path / d
                if potential_path.exists() and potential_path.is_dir():
                    search_path = potential_path
                    logger.info(f"Found rootfs directory for init scripts search: {search_path}")
                    break
            
            # If still not found, use firmware path
            if not search_path:
                search_path = self.firmware_path
                logger.info(f"Using firmware path for init scripts search: {search_path}")
        
        # Common init script directories
        init_script_dirs = [
            "etc/init.d",
            "etc/rc.d",
            "etc/rc.d/init.d",
            "sbin/init.d",
            "lib/systemd/system",
            "usr/lib/systemd/system",
            "etc/systemd/system"
        ]
        
        for init_dir in init_script_dirs:
            dir_path = search_path / init_dir
            if dir_path.exists() and dir_path.is_dir():
                scripts = []
                for file_path in dir_path.glob("*"):
                    if file_path.is_file():
                        scripts.append(str(file_path))
                
                if "init.d" in init_dir:
                    results["init.d"].extend(scripts)
                elif "rc.d" in init_dir:
                    results["rc.d"].extend(scripts)
                elif "systemd" in init_dir:
                    results["systemd_units"].extend(scripts)
        
        # Look for upstart configs
        upstart_dir = search_path / "etc" / "init"
        if upstart_dir.exists() and upstart_dir.is_dir():
            for file_path in upstart_dir.glob("*.conf"):
                if file_path.is_file():
                    results["system_services"].append(str(file_path))
                    logger.info(f"Found upstart config: {file_path}")
        
        return {k: v for k, v in results.items() if v}  # Filter out empty results


class UserAccountAnalyzer(BaseAnalyzer):
    """Analyzer for user account and authentication configuration"""

    def _detect_hash_algo_from_libc(self, rootfs_path: 'Path') -> 'Optional[tuple]':
        """
        Inspect libc binary via strings to detect libc type and return hash algorithm.

        Searches common libc paths in the extracted rootfs and checks for
        well-known marker strings to identify uclibc, musl, or glibc.

        Args:
            rootfs_path: Path object pointing to the extracted rootfs directory.

        Returns:
            Tuple of (hash_algo, libc_type, signal_str) if detected, None otherwise.
            hash_algo is one of 'md5' or 'sha512'.
            signal_str is a human-readable description of what was found.
        """
        LIBC_SEARCH_PATHS = [
            'lib/libc.so',
            'lib/libc.so.0',
            'lib/libc.so.6',
            'usr/lib/libc.so',
            'usr/lib/libc.so.6',
            'lib/ld-uClibc.so.0',
            'lib/ld-linux.so.2',
        ]
        LIBC_MARKERS = {
            'uclibc': ['uClibc', '__uClibc_start_main', 'uClibc_version'],
            'musl':   ['musl libc', 'musl version'],
            'glibc':  ['GNU C Library', 'GLIBC_', 'GNU libc'],
        }
        LIBC_ALGO_MAP = {
            'uclibc': 'md5',
            'musl':   'md5',
            'glibc':  'sha512',
        }

        for rel_path in LIBC_SEARCH_PATHS:
            libc_path = rootfs_path / rel_path
            if not libc_path.exists() or not libc_path.is_file():
                continue
            try:
                strings_out = self._get_strings_output(str(libc_path))
                for libc_type, markers in LIBC_MARKERS.items():
                    for marker in markers:
                        if marker in strings_out:
                            algo = LIBC_ALGO_MAP[libc_type]
                            signal = f"{rel_path}: '{marker}' found"
                            logger.info(
                                f"_detect_hash_algo_from_libc: detected {libc_type} "
                                f"via '{marker}' in {rel_path} -> hash_algo={algo}"
                            )
                            return (algo, libc_type, signal)
            except Exception as e:
                logger.warning(f"_detect_hash_algo_from_libc: failed to inspect {rel_path}: {e}")
                continue

        # Also check for glob patterns (ld-musl-*.so.1, lib/libc-*.so)
        for pattern in ['lib/ld-musl-*.so.1', 'lib/libc-*.so', 'lib/ld-linux-*.so.2']:
            try:
                matches = list(rootfs_path.glob(pattern))
                for libc_path in matches:
                    strings_out = self._get_strings_output(str(libc_path))
                    for libc_type, markers in LIBC_MARKERS.items():
                        for marker in markers:
                            if marker in strings_out:
                                algo = LIBC_ALGO_MAP[libc_type]
                                signal = f"{libc_path.relative_to(rootfs_path)}: '{marker}' found"
                                logger.info(
                                    f"_detect_hash_algo_from_libc: detected {libc_type} "
                                    f"via glob '{marker}' -> hash_algo={algo}"
                                )
                                return (algo, libc_type, signal)
            except Exception as e:
                logger.warning(f"_detect_hash_algo_from_libc glob {pattern}: {e}")

        return None

    def analyze_user_accounts(self, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze user accounts and password hash configuration
        
        Args:
            rootfs_path: Path to rootfs
            
        Returns:
            Dictionary with user account information
        """
        results = {
            "root_hash_type": None,
            "hash_source": None,
            "has_shadow_file": False,
            "users": [],
            # Authoritative detection results (Phase 6: PASS-01/PASS-02)
            "hash_algo": None,
            "hash_detection_method": None,
            "hash_detection_signal": None,
        }
        
        # Determine search path
        search_path = self.firmware_path
        if rootfs_path and os.path.exists(rootfs_path):
            search_path = Path(rootfs_path)
        
        # Look for /etc/passwd first to get all users
        passwd_path = search_path / "etc" / "passwd"
        users_dict = {}
        
        if passwd_path.exists() and passwd_path.is_file():
            logger.info(f"Found passwd file at: {passwd_path}")
            try:
                with open(passwd_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 7:
                                username = parts[0]
                                uid = parts[2]
                                gid = parts[3]
                                home = parts[5]
                                shell = parts[6]
                                
                                # Store user info
                                users_dict[username] = {
                                    "username": username,
                                    "uid": uid,
                                    "gid": gid,
                                    "home": home,
                                    "shell": shell,
                                    "has_password": False,
                                    "hash_type": None
                                }
            except Exception as e:
                logger.error(f"Failed to read passwd file: {e}")
        
        # Look for /etc/shadow for password hashes
        shadow_path = search_path / "etc" / "shadow"
        
        if shadow_path.exists() and shadow_path.is_file():
            results["has_shadow_file"] = True
            logger.info(f"Found shadow file at: {shadow_path}")
            
            try:
                with open(shadow_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and ':' in line:
                            parts = line.split(':')
                            if len(parts) > 1:
                                username = parts[0]
                                hash_field = parts[1]
                                
                                # Detect hash type from existing passwords
                                hash_type = None
                                has_password = False
                                
                                if hash_field and hash_field not in ['*', '!', '!!', 'x']:
                                    has_password = True
                                    if hash_field.startswith('$6$'):
                                        hash_type = 'sha512'
                                    elif hash_field.startswith('$5$'):
                                        hash_type = 'sha256'
                                    elif hash_field.startswith('$1$'):
                                        hash_type = 'md5'
                                    elif hash_field.startswith('$2a$') or hash_field.startswith('$2b$') or hash_field.startswith('$2y$'):
                                        hash_type = 'bcrypt'
                                
                                # Update user info with password data
                                if username in users_dict:
                                    users_dict[username]["has_password"] = has_password
                                    users_dict[username]["hash_type"] = hash_type
                                elif has_password:
                                    # User in shadow but not in passwd (unusual)
                                    users_dict[username] = {
                                        "username": username,
                                        "uid": "?",
                                        "gid": "?",
                                        "home": "?",
                                        "shell": "?",
                                        "has_password": has_password,
                                        "hash_type": hash_type
                                    }
                                
                                # Set root hash type for backward compatibility
                                if hash_type:
                                    if username == 'root' and not results["root_hash_type"]:
                                        results["root_hash_type"] = hash_type
                                        results["hash_source"] = f"root user in /etc/shadow"
                                        logger.info(f"Detected {hash_type} hash for root user")
                                    elif not results["root_hash_type"]:
                                        # Use first found hash if no root hash yet
                                        results["root_hash_type"] = hash_type
                                        results["hash_source"] = f"{username} user in /etc/shadow"
                                        logger.info(f"Detected {hash_type} hash from {username} user")
                
            except Exception as e:
                logger.error(f"Failed to read shadow file: {e}")
        else:
            logger.warning(f"No shadow file found at {shadow_path}")
        
        # Convert users_dict to list, prioritizing root and common users
        priority_users = ['root', 'admin', 'administrator', 'user', 'guest']
        users_list = []
        
        # Add priority users first
        for priority_user in priority_users:
            if priority_user in users_dict:
                users_list.append(users_dict[priority_user])
                del users_dict[priority_user]
        
        # Add remaining users sorted by UID
        remaining_users = sorted(users_dict.values(), key=lambda x: int(x['uid']) if x['uid'].isdigit() else 999999)
        users_list.extend(remaining_users)
        
        results["users"] = users_list

        # --- Hash algorithm detection priority ---
        # 1. Primary: ELF/strings libc inspection
        elf_result = self._detect_hash_algo_from_libc(search_path)
        if elf_result:
            algo, libc_type, signal = elf_result
            results["hash_algo"] = algo
            results["hash_detection_method"] = "elf_inspection"
            results["hash_detection_signal"] = signal
            logger.info(f"Hash algo detection: ELF inspection -> {algo} (libc={libc_type})")

        # 2. Fallback: shadow file (root_hash_type already populated above)
        elif results.get("root_hash_type"):
            results["hash_algo"] = results["root_hash_type"]
            results["hash_detection_method"] = "shadow_file"
            results["hash_detection_signal"] = results.get("hash_source")
            logger.info(f"Hash algo detection: shadow file fallback -> {results['hash_algo']}")

        # 3. Fallback: firmware metadata (/etc/openwrt_release)
        else:
            openwrt_release_path = search_path / 'etc' / 'openwrt_release'
            if openwrt_release_path.exists():
                try:
                    release_content = openwrt_release_path.read_text(errors='replace').lower()
                    if 'uclibc' in release_content:
                        results["hash_algo"] = 'md5'
                        results["hash_detection_method"] = "metadata"
                        results["hash_detection_signal"] = "/etc/openwrt_release: 'uclibc' found"
                        logger.info("Hash algo detection: openwrt_release metadata -> md5")
                    elif 'musl' in release_content:
                        results["hash_algo"] = 'md5'
                        results["hash_detection_method"] = "metadata"
                        results["hash_detection_signal"] = "/etc/openwrt_release: 'musl' found"
                        logger.info("Hash algo detection: openwrt_release metadata -> md5")
                except Exception as e:
                    logger.warning(f"Could not read /etc/openwrt_release: {e}")

        # 4. Final fallback: default to md5 (safer for embedded uclibc/musl targets)
        if not results["hash_algo"]:
            results["hash_algo"] = 'md5'
            results["hash_detection_method"] = "default"
            results["hash_detection_signal"] = (
                "No libc binary, shadow, or metadata evidence found; defaulting to md5"
            )
            logger.warning(
                "analyze_user_accounts: no hash algorithm evidence found, "
                "defaulting to md5 (safer for embedded uclibc/musl firmware)"
            )

        return results


class SSHServiceAnalyzer(BaseAnalyzer):
    """Analyzer for SSH service detection"""
    
    def analyze_ssh_service(self, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect SSH service implementation
        
        Args:
            rootfs_path: Path to rootfs
            
        Returns:
            Dictionary with SSH service information
        """
        results = {
            "implementation": "unknown",
            "binary_path": None,
            "config_path": None,
            "config_content": None,
            "config_size": None
        }
        
        # Determine search path
        search_path = self.firmware_path
        if rootfs_path and os.path.exists(rootfs_path):
            search_path = Path(rootfs_path)
        
        # Check for Dropbear (most common in IoT/embedded devices)
        dropbear_paths = [
            "usr/sbin/dropbear",
            "sbin/dropbear",
            "usr/bin/dropbear",
            "bin/dropbear"
        ]
        
        for dropbear_path in dropbear_paths:
            full_path = search_path / dropbear_path
            if full_path.exists():
                results["implementation"] = "dropbear"
                results["binary_path"] = str(full_path.relative_to(search_path))
                
                # Check for config - OpenWrt UCI style
                config_path = search_path / "etc" / "config" / "dropbear"
                if config_path.exists() and config_path.is_file():
                    results["config_path"] = "/etc/config/dropbear"
                    try:
                        with open(config_path, 'r', errors='ignore') as f:
                            results["config_content"] = f.read()
                            results["config_size"] = len(results["config_content"])
                    except Exception as e:
                        logger.error(f"Error reading dropbear config: {e}")
                else:
                    # Check for Debian-style config
                    config_path = search_path / "etc" / "default" / "dropbear"
                    if config_path.exists() and config_path.is_file():
                        results["config_path"] = "/etc/default/dropbear"
                        try:
                            with open(config_path, 'r', errors='ignore') as f:
                                results["config_content"] = f.read()
                                results["config_size"] = len(results["config_content"])
                        except Exception as e:
                            logger.error(f"Error reading dropbear config: {e}")
                
                logger.info(f"Detected Dropbear SSH at {results['binary_path']}")
                return results
        
        # Check for OpenSSH (standard full-featured SSH)
        openssh_paths = [
            "usr/sbin/sshd",
            "sbin/sshd",
            "usr/bin/sshd"
        ]
        
        for sshd_path in openssh_paths:
            full_path = search_path / sshd_path
            if full_path.exists():
                results["implementation"] = "openssh"
                results["binary_path"] = str(full_path.relative_to(search_path))
                
                # Check for config
                config_path = search_path / "etc" / "ssh" / "sshd_config"
                if config_path.exists() and config_path.is_file():
                    results["config_path"] = "/etc/ssh/sshd_config"
                    try:
                        with open(config_path, 'r', errors='ignore') as f:
                            results["config_content"] = f.read()
                            results["config_size"] = len(results["config_content"])
                    except Exception as e:
                        logger.error(f"Error reading OpenSSH config: {e}")
                
                logger.info(f"Detected OpenSSH at {results['binary_path']}")
                return results
        
        # Check for TinySSH (minimalist SSH for embedded systems)
        tinyssh_paths = [
            "usr/sbin/tinysshd",
            "sbin/tinysshd",
            "usr/bin/tinysshd"
        ]
        
        for tinyssh_path in tinyssh_paths:
            full_path = search_path / tinyssh_path
            if full_path.exists():
                results["implementation"] = "tinyssh"
                results["binary_path"] = str(full_path.relative_to(search_path))
                
                # TinySSH typically doesn't have a config file, but note the key directory
                config_path = search_path / "etc" / "tinyssh"
                if config_path.exists() and config_path.is_dir():
                    results["config_path"] = "/etc/tinyssh (key directory)"
                
                logger.info(f"Detected TinySSH at {results['binary_path']}")
                return results
        
        # Generic SSH detection - check common binary locations
        generic_ssh_paths = [
            "usr/bin/ssh",
            "bin/ssh",
            "usr/local/sbin/sshd"
        ]
        
        for ssh_path in generic_ssh_paths:
            full_path = search_path / ssh_path
            if full_path.exists():
                results["implementation"] = "unknown"
                results["binary_path"] = str(full_path.relative_to(search_path))
                logger.warning(f"Detected unknown SSH implementation at {results['binary_path']}")
                return results
        
        logger.info("No SSH service detected in firmware")
        return results


class NetworkConfigAnalyzer(BaseAnalyzer):
    """Analyzer for detecting network configuration in firmware"""
    
    def analyze_network_config(self, rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze network configuration and detect network manager
        
        Args:
            rootfs_path: Path to rootfs
            
        Returns:
            Dictionary with network configuration information
        """
        results = {
            "network_manager": None,
            "network_manager_path": None,
            "config_files": [],
            "interfaces": [],
            "default_ips": []
        }
        
        # Determine search path
        search_path = self.firmware_path
        if rootfs_path and os.path.exists(rootfs_path):
            search_path = Path(rootfs_path)
        
        # Network manager detection patterns
        network_managers = {
            "netifd": {
                "paths": ["sbin/netifd", "usr/sbin/netifd"],
                "config_locations": ["etc/config/network"],
                "type": "openwrt_uci"
            },
            "NetworkManager": {
                "paths": ["usr/sbin/NetworkManager", "usr/bin/NetworkManager", "sbin/NetworkManager"],
                "config_locations": ["etc/NetworkManager/NetworkManager.conf"],
                "type": "networkmanager"
            },
            "systemd-networkd": {
                "paths": ["lib/systemd/systemd-networkd", "usr/lib/systemd/systemd-networkd"],
                "config_locations": ["etc/systemd/network", "lib/systemd/network"],
                "type": "systemd"
            },
            "ifupdown": {
                "paths": ["sbin/ifup", "sbin/ifdown"],
                "config_locations": ["etc/network/interfaces"],
                "type": "debian"
            },
            "connman": {
                "paths": ["usr/sbin/connmand", "sbin/connmand"],
                "config_locations": ["var/lib/connman", "etc/connman"],
                "type": "connman"
            },
            "netplan": {
                "paths": ["usr/sbin/netplan", "usr/bin/netplan"],
                "config_locations": ["etc/netplan"],
                "type": "netplan"
            }
        }
        
        # Detect network manager
        for manager_name, manager_info in network_managers.items():
            for binary_path in manager_info["paths"]:
                full_path = search_path / binary_path
                if full_path.exists():
                    results["network_manager"] = manager_name
                    results["network_manager_path"] = "/" + binary_path
                    results["manager_type"] = manager_info["type"]
                    logger.info(f"Detected {manager_name} at {binary_path}")
                    
                    # Find config files
                    for config_loc in manager_info["config_locations"]:
                        config_path = search_path / config_loc
                        if config_path.exists():
                            if config_path.is_file():
                                # Single config file
                                rel_path = "/" + str(config_path.relative_to(search_path))
                                try:
                                    with open(config_path, 'r', errors='ignore') as f:
                                        content = f.read()
                                    results["config_files"].append({
                                        "path": rel_path,
                                        "content": content,
                                        "size": len(content)
                                    })
                                except Exception as e:
                                    logger.error(f"Error reading {rel_path}: {e}")
                            elif config_path.is_dir():
                                # Directory of config files
                                for config_file in config_path.rglob("*.network"):
                                    rel_path = "/" + str(config_file.relative_to(search_path))
                                    try:
                                        with open(config_file, 'r', errors='ignore') as f:
                                            content = f.read()
                                        results["config_files"].append({
                                            "path": rel_path,
                                            "content": content,
                                            "size": len(content)
                                        })
                                    except Exception as e:
                                        logger.error(f"Error reading {rel_path}: {e}")
                                # For netplan, look for yaml files
                                for config_file in config_path.rglob("*.yaml"):
                                    rel_path = "/" + str(config_file.relative_to(search_path))
                                    try:
                                        with open(config_file, 'r', errors='ignore') as f:
                                            content = f.read()
                                        results["config_files"].append({
                                            "path": rel_path,
                                            "content": content,
                                            "size": len(content)
                                        })
                                    except Exception as e:
                                        logger.error(f"Error reading {rel_path}: {e}")
                    
                    # Parse config for interfaces and IPs
                    if results["manager_type"] == "openwrt_uci":
                        self._parse_uci_config(results)
                    elif results["manager_type"] == "systemd":
                        self._parse_systemd_config(results)
                    elif results["manager_type"] == "debian":
                        self._parse_debian_interfaces(results)
                    elif results["manager_type"] == "netplan":
                        self._parse_netplan_config(results)
                    
                    break
            if results["network_manager"]:
                break
        
        # If no manager detected, try to find standalone network configs
        if not results["network_manager"]:
            logger.info("No network manager detected, checking for standalone configs")
            standalone_configs = [
                "etc/config/network",
                "etc/network/interfaces",
                "etc/systemd/network",
                "etc/netplan"
            ]
            
            for config_path in standalone_configs:
                full_path = search_path / config_path
                if full_path.exists():
                    rel_path = "/" + config_path
                    if full_path.is_file():
                        try:
                            with open(full_path, 'r', errors='ignore') as f:
                                content = f.read()
                            results["config_files"].append({
                                "path": rel_path,
                                "content": content,
                                "size": len(content)
                            })
                            results["network_manager"] = "standalone_config"
                            
                            # Try to detect type from path
                            if "config/network" in config_path:
                                results["manager_type"] = "openwrt_uci"
                                self._parse_uci_config(results)
                            elif "network/interfaces" in config_path:
                                results["manager_type"] = "debian"
                                self._parse_debian_interfaces(results)
                        except Exception as e:
                            logger.error(f"Error reading {rel_path}: {e}")
        
        # Check for common network interfaces in /sys/class/net if available
        net_class_path = search_path / "sys" / "class" / "net"
        if net_class_path.exists() and net_class_path.is_dir():
            for iface_dir in net_class_path.iterdir():
                if iface_dir.is_dir() and iface_dir.name not in ['lo', '.', '..']:
                    results["interfaces"].append(iface_dir.name)
        
        return results
    
    def _parse_uci_config(self, results: Dict[str, Any]):
        """Parse OpenWrt UCI network config"""
        for config_file in results["config_files"]:
            if "/config/network" in config_file["path"]:
                content = config_file["content"]
                current_interface = None
                
                for line in content.splitlines():
                    line = line.strip()
                    
                    # Match config interface blocks
                    if line.startswith("config interface"):
                        parts = line.split("'")
                        if len(parts) >= 2:
                            current_interface = {
                                "name": parts[1],
                                "type": "uci",
                                "proto": None,
                                "ipaddr": None,
                                "netmask": None,
                                "gateway": None
                            }
                    
                    # Parse options within interface block
                    elif current_interface and line.startswith("option"):
                        if "ifname" in line:
                            match = re.search(r"option\s+ifname\s+['\"]([^'\"]+)['\"]", line)
                            if match:
                                current_interface["ifname"] = match.group(1)
                        elif "proto" in line:
                            match = re.search(r"option\s+proto\s+['\"]([^'\"]+)['\"]", line)
                            if match:
                                current_interface["proto"] = match.group(1)
                        elif "ipaddr" in line:
                            match = re.search(r"option\s+ipaddr\s+['\"]([^'\"]+)['\"]", line)
                            if match:
                                current_interface["ipaddr"] = match.group(1)
                                if current_interface["ipaddr"] and current_interface["ipaddr"] not in results["default_ips"]:
                                    results["default_ips"].append(current_interface["ipaddr"])
                        elif "netmask" in line:
                            match = re.search(r"option\s+netmask\s+['\"]([^'\"]+)['\"]", line)
                            if match:
                                current_interface["netmask"] = match.group(1)
                        elif "gateway" in line:
                            match = re.search(r"option\s+gateway\s+['\"]([^'\"]+)['\"]", line)
                            if match:
                                current_interface["gateway"] = match.group(1)
                    
                    # End of interface block or empty line - save current interface
                    elif not line or (line.startswith("config") and current_interface):
                        if current_interface and current_interface.get("name"):
                            results["interfaces"].append(current_interface)
                        current_interface = None
                
                # Save last interface if exists
                if current_interface and current_interface.get("name"):
                    results["interfaces"].append(current_interface)
    
    def _parse_systemd_config(self, results: Dict[str, Any]):
        """Parse systemd-networkd config"""
        for config_file in results["config_files"]:
            content = config_file["content"]
            current_section = None
            current_interface = {
                "type": "systemd",
                "file": config_file["path"]
            }
            
            for line in content.splitlines():
                line = line.strip()
                
                # Section headers
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                
                # Parse Network section
                elif current_section == "Network" and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "Address":
                        # Can be in CIDR notation
                        ip_addr = value.split('/')[0]
                        current_interface["ipaddr"] = ip_addr
                        if ip_addr not in results["default_ips"]:
                            results["default_ips"].append(ip_addr)
                    elif key == "Gateway":
                        current_interface["gateway"] = value
                    elif key == "DHCP":
                        current_interface["proto"] = "dhcp" if value.lower() == "yes" else "static"
            
            if current_interface.get("ipaddr") or current_interface.get("proto"):
                results["interfaces"].append(current_interface)
    
    def _parse_debian_interfaces(self, results: Dict[str, Any]):
        """Parse Debian /etc/network/interfaces"""
        for config_file in results["config_files"]:
            if "network/interfaces" in config_file["path"]:
                content = config_file["content"]
                current_interface = None
                
                for line in content.splitlines():
                    line = line.strip()
                    
                    # Match iface lines
                    if line.startswith("iface"):
                        parts = line.split()
                        if len(parts) >= 4:
                            current_interface = {
                                "name": parts[1],
                                "type": "debian",
                                "proto": "dhcp" if parts[3] == "dhcp" else "static"
                            }
                    
                    # Parse address/netmask/gateway for static interfaces
                    elif current_interface and current_interface["proto"] == "static":
                        if line.startswith("address"):
                            ip_addr = line.split()[1]
                            current_interface["ipaddr"] = ip_addr
                            if ip_addr not in results["default_ips"]:
                                results["default_ips"].append(ip_addr)
                        elif line.startswith("netmask"):
                            current_interface["netmask"] = line.split()[1]
                        elif line.startswith("gateway"):
                            current_interface["gateway"] = line.split()[1]
                    
                    # Save interface when we hit a new one or empty line
                    elif not line or (line.startswith("iface") and current_interface):
                        if current_interface and current_interface.get("name"):
                            results["interfaces"].append(current_interface)
                        current_interface = None
                
                # Save last interface
                if current_interface and current_interface.get("name"):
                    results["interfaces"].append(current_interface)
    
    def _parse_netplan_config(self, results: Dict[str, Any]):
        """Parse netplan YAML config (basic parsing without YAML library)"""
        for config_file in results["config_files"]:
            if ".yaml" in config_file["path"] or ".yml" in config_file["path"]:
                content = config_file["content"]
                current_interface = None
                indent_level = 0
                
                for line in content.splitlines():
                    stripped = line.lstrip()
                    if not stripped or stripped.startswith('#'):
                        continue
                    
                    # Detect interface name (ethernets:, wifis:, etc.)
                    if ':' in stripped and not stripped.startswith('-'):
                        key = stripped.split(':')[0].strip()
                        current_indent = len(line) - len(stripped)
                        
                        # Interface name level
                        if current_indent > 8 and current_interface:
                            if key == "dhcp4" or key == "dhcp6":
                                current_interface["proto"] = "dhcp"
                            elif key == "addresses":
                                # Next lines will have IP addresses
                                pass
                        elif current_indent > 4:
                            # New interface
                            if current_interface:
                                results["interfaces"].append(current_interface)
                            current_interface = {
                                "name": key,
                                "type": "netplan"
                            }
                    elif stripped.startswith('- ') and current_interface:
                        # Address in list
                        addr = stripped[2:].strip()
                        ip_addr = addr.split('/')[0]
                        current_interface["ipaddr"] = ip_addr
                        if ip_addr not in results["default_ips"]:
                            results["default_ips"].append(ip_addr)
                
                # Save last interface
                if current_interface and current_interface.get("name"):
                    results["interfaces"].append(current_interface)


class FirmwareAnalyzer:
    """
    Main controller class that coordinates all the analyzers for firmware analysis.
    This class focuses solely on analysis and information gathering.
    """
    
    def __init__(self, firmware_path: str):
        """
        Initialize the firmware analyzer.
        
        Args:
            firmware_path: Path to the firmware
        """
        self.firmware_path = Path(firmware_path)
        if not self.firmware_path.exists():
            raise FileNotFoundError(f"Firmware path not found: {firmware_path}")
        
        # Initialize all analyzers
        self.kernel_version = KernelVersion(firmware_path)
        self.kernel_config = KernelConfig(firmware_path)
        self.kernel_modules = KernelModules(firmware_path)
        self.kernel_preemption = KernelPreemption(firmware_path)
        self.boot_parameters = BootParameters(firmware_path)
        self.init_finder = InitFinder(firmware_path)
        self.arch_analyzer = GetArchi(firmware_path)
        self.endianness_analyzer = GetEndianess(firmware_path)
        self.bit_width_analyzer = GetBitWidth(firmware_path)
        self.float_type_analyzer = GetFloatingType(firmware_path)
        # New analyzers for additional info
        self.user_account_analyzer = UserAccountAnalyzer(firmware_path)
        self.ssh_service_analyzer = SSHServiceAnalyzer(firmware_path)
        self.network_config_analyzer = NetworkConfigAnalyzer(firmware_path)
    
    def analyze_all(self, kernel_binary: Optional[str] = None, 
                   kernel_csv_log: Optional[str] = None,
                   rootfs_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze all firmware components and gather information.
        
        Args:
            kernel_binary: Path to kernel binary (if known)
            kernel_csv_log: Path to kernel CSV log (if available)
            rootfs_path: Path to rootfs (if known)
            
        Returns:
            Dictionary with all analysis results
        """
        results = {}
        
        # If rootfs_path is provided, validate it
        if rootfs_path and os.path.exists(rootfs_path):
            logger.info(f"Using provided rootfs path: {rootfs_path}")
        else:
            logger.warning(f"No valid rootfs path provided, using default path: {self.firmware_path}")
            rootfs_path = self.firmware_path
        
        try:
            # Step 1: Find all binaries for analysis
            logger.info("Finding binaries for analysis...")
            base_analyzer = BaseAnalyzer(self.firmware_path)
            binaries_to_analyze = base_analyzer.find_binaries_for_analysis(rootfs_path)
            
            # Step 2: Run all commands centrally on all binaries ONCE
            logger.info("Running centralized command execution...")
            base_analyzer.run_all_commands_on_binaries(binaries_to_analyze)
            
            # Step 3: Build consolidated detection details from saved outputs
            logger.info("Building detection details from saved outputs...")
            consolidated_detection_details = self._build_detection_details_from_saved_outputs(
                binaries_to_analyze, base_analyzer, results
            )
            results["consolidated_detection_details"] = consolidated_detection_details
            
            # Step 4: Detect kernel version
            logger.info("Detecting kernel version...")
            kernel_version_data = self.kernel_version.detect()
            results["kernel_version"] = kernel_version_data["version_detections"]
            results["kernel_version_sources"] = kernel_version_data["version_sources"]
            
            # Find best kernel version match
            kernel_versions = kernel_version_data["version_detections"]
            best_kernel_version = None
            if "kernel_modules" in kernel_versions and kernel_versions["kernel_modules"]:
                best_kernel_version = kernel_versions["kernel_modules"][0]["version"]
            elif "modinfo_vermagic" in kernel_versions and kernel_versions["modinfo_vermagic"]:
                best_kernel_version = kernel_versions["modinfo_vermagic"][0]["version"]
            elif "old_kernel_modules" in kernel_versions and kernel_versions["old_kernel_modules"]:
                best_kernel_version = kernel_versions["old_kernel_modules"][0]["version"]
            elif "kernel_binaries" in kernel_versions and kernel_versions["kernel_binaries"]:
                best_kernel_version = kernel_versions["kernel_binaries"][0]["version"]
            elif "kernel_config" in kernel_versions and kernel_versions["kernel_config"]:
                best_kernel_version = kernel_versions["kernel_config"][0]["version"]
            elif "uname_logs" in kernel_versions and kernel_versions["uname_logs"]:
                best_kernel_version = kernel_versions["uname_logs"][0]["version"]
            
            # If we still don't have a version, check artifact metadata
            if not best_kernel_version:
                # Try to find version in any remaining sources
                for source in ["kernel_config", "uname_logs"]:
                    if source in kernel_versions and kernel_versions[source]:
                        best_kernel_version = kernel_versions[source][0]["version"]
                        break
            
            if best_kernel_version:
                results["best_kernel_version"] = best_kernel_version
                # Add source reference for best version
                if best_kernel_version in kernel_version_data["version_sources"]:
                    results["best_kernel_version_source"] = kernel_version_data["version_sources"][best_kernel_version][0]
            
            # Step 5: Detect preemption model
            logger.info("Detecting kernel preemption model...")
            preemption_results = self.kernel_preemption.detect(rootfs_path)
            results["kernel_preemption"] = preemption_results
            
            # Get best preemption model match
            best_preemption = self.kernel_preemption.get_best_match(preemption_results)
            if best_preemption:
                results["best_preemption_model"] = best_preemption
            
            # Step 6: Extract kernel parameters
            logger.info("Extracting kernel boot parameters...")
            boot_params = self.boot_parameters.extract(kernel_binary, kernel_csv_log)
            results["boot_parameters"] = boot_params
            
            # Step 7: Analyze kernel modules
            logger.info("Analyzing kernel modules...")
            module_results = self.kernel_modules.analyze()
            results["kernel_modules"] = module_results
            
            # Step 8: Find init files and analyze init systems
            logger.info(f"Finding init files in rootfs: {rootfs_path}...")
            init_files_data = self.init_finder.find_init_files(rootfs_path)
            results["init_files"] = init_files_data
            
            # Create source references for init files
            init_files_sources = {}
            for file_type, files in init_files_data.items():
                init_files_sources[file_type] = []
                for file_path in files:
                    source_ref = self.init_finder._create_source_reference(
                        "filesystem_scan", file_path, "Filesystem scan",
                        f"Found {file_type}: {file_path}", None
                    )
                    init_files_sources[file_type].append(source_ref)
            results["init_files_sources"] = init_files_sources
            
            logger.info(f"Finding init scripts in rootfs: {rootfs_path}...")
            init_scripts_data = self.init_finder.find_init_scripts_location(rootfs_path)
            results["init_scripts_location"] = init_scripts_data
            
            # Create source references for init scripts
            init_scripts_sources = {}
            for script_type, scripts in init_scripts_data.items():
                init_scripts_sources[script_type] = []
                for script_path in scripts:
                    source_ref = self.init_finder._create_source_reference(
                        "filesystem_scan", script_path, "Filesystem scan",
                        f"Found {script_type}: {script_path}", None
                    )
                    init_scripts_sources[script_type].append(source_ref)
            results["init_scripts_sources"] = init_scripts_sources
            
            # Step 9: Extract architecture results from saved outputs
            logger.info("Extracting architecture information from saved outputs...")
            arch_results = self._extract_architecture_from_saved_outputs(binaries_to_analyze, base_analyzer)
            results["architecture"] = arch_results["architectures"]
            results["architecture_sources"] = arch_results["architecture_sources"]
            
            # Step 10: Extract endianness from saved outputs
            logger.info("Extracting endianness from saved outputs...")
            endianness_results = self._extract_endianness_from_saved_outputs(binaries_to_analyze, base_analyzer)
            results["endianness"] = endianness_results["endianness"]
            results["endianness_sources"] = endianness_results["endianness_sources"]
            
            # Step 11: Extract bit width from saved outputs
            logger.info("Extracting bit width from saved outputs...")
            bit_width_results = self._extract_bit_width_from_saved_outputs(binaries_to_analyze, base_analyzer)
            results["bit_width"] = bit_width_results["bit_width"]
            results["bit_width_sources"] = bit_width_results["bit_width_sources"]
            
            # Step 12: Extract floating point type for ARM architecture
            if "ARM" in arch_results["architectures"]:
                logger.info("Extracting floating point type for ARM architecture from saved outputs...")
                float_type_results = self._extract_floating_type_from_saved_outputs(binaries_to_analyze, base_analyzer)
                results["floating_point_type"] = float_type_results["floating_types"]
            
            # Get saved outputs summary
            saved_outputs_summary = base_analyzer.get_saved_outputs_summary()
            
            # Step 13: Analyze user accounts and authentication
            logger.info("Analyzing user accounts and authentication...")
            user_accounts_data = self.user_account_analyzer.analyze_user_accounts(rootfs_path)
            results["user_accounts"] = user_accounts_data
            
            # Step 14: Detect SSH service implementation
            logger.info("Detecting SSH service implementation...")
            ssh_service_data = self.ssh_service_analyzer.analyze_ssh_service(rootfs_path)
            results["ssh_service"] = ssh_service_data
            
            # Step 15: Analyze network configuration
            logger.info("Analyzing network configuration...")
            network_config_data = self.network_config_analyzer.analyze_network_config(rootfs_path)
            results["network_config"] = network_config_data
            
            # Add analysis metadata
            results["analysis_timestamp"] = datetime.datetime.now().isoformat()
            results["firmware_path"] = str(self.firmware_path)
            results["saved_outputs_summary"] = saved_outputs_summary
            
            return results
            
        except Exception as e:
            logger.error(f"Error during firmware analysis: {e}")
            # Add error information and return partial results
            results["error"] = str(e)
            return results
    
    def _consolidate_all_detection_details(self, arch_details, endian_details, bitwidth_details, floating_details, analysis_results):
        """
        Consolidate all detection details into unified command outputs to avoid duplication.
        
        Args:
            arch_details: Architecture detection details
            endian_details: Endianness detection details  
            bitwidth_details: Bit width detection details
            floating_details: Floating point detection details
            analysis_results: The main analysis results dictionary
            
        Returns:
            List of consolidated detection details with combined highlighting
        """
        consolidated = []
        
        # Collect all details by command and binary
        command_groups = {}
        
        # Group all details by binary and command
        all_details = []
        if arch_details:
            for detail in arch_details:
                detail["detection_types"] = ["architecture"]
                all_details.append(detail)
        
        if endian_details:
            for detail in endian_details:
                detail["detection_types"] = ["endianness"] 
                all_details.append(detail)
                
        if bitwidth_details:
            for detail in bitwidth_details:
                detail["detection_types"] = ["bitwidth"]
                all_details.append(detail)
                
        if floating_details:
            for detail in floating_details:
                detail["detection_types"] = ["floating_point"]
                all_details.append(detail)
        
        # Group by binary and normalized command to find overlaps
        for detail in all_details:
            # Normalize the command to handle slight variations
            binary_path = detail['binary']
            command = detail['command']
            
            # Create a normalized key that groups similar commands together
            # e.g., "readelf -h /path/to/binary" should be the same regardless of analyzer
            normalized_command = command.strip()
            key = f"{binary_path}||{normalized_command}"
            
            if key not in command_groups:
                command_groups[key] = {
                    "binary": binary_path,
                    "command": normalized_command, 
                    "output": detail["output"],
                    "detection_types": [],
                    "detected_values": {},
                    "method": detail.get("method", ""),
                    "note": detail.get("note", "")
                }
            
            # Merge detection types and values
            command_groups[key]["detection_types"].extend(detail["detection_types"])
            
            if "architecture" in detail["detection_types"]:
                command_groups[key]["detected_values"]["architecture"] = detail.get("detected_arch")
            if "endianness" in detail["detection_types"]:
                command_groups[key]["detected_values"]["endianness"] = analysis_results.get("endianness", [])
            if "bitwidth" in detail["detection_types"]:
                command_groups[key]["detected_values"]["bitwidth"] = analysis_results.get("bit_width", [])
            if "floating_point" in detail["detection_types"]:
                command_groups[key]["detected_values"]["floating_point"] = analysis_results.get("floating_point_type", [])
            
            # Update note to reflect multiple detections if needed
            detection_count = len(set(command_groups[key]["detection_types"]))
            if detection_count > 1:
                command_groups[key]["note"] = f"Used for {detection_count} different detections"
        
        # Convert to final consolidated list
        for key, group in command_groups.items():
            # Remove duplicate detection types
            group["detection_types"] = list(set(group["detection_types"]))
            consolidated.append(group)
        
        # Sort by binary path and command for consistent ordering
        consolidated.sort(key=lambda x: (x["binary"], x["command"]))
        
        return consolidated
    
    def _build_detection_details_from_saved_outputs(self, binaries: List[str], base_analyzer: BaseAnalyzer, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build consolidated detection details from saved command outputs.
        Pick one representative binary per command type to avoid showing redundant outputs.
        
        Args:
            binaries: List of binary paths that were analyzed
            base_analyzer: BaseAnalyzer instance with saved outputs
            results: Analysis results dictionary to populate with detected values
            
        Returns:
            List of consolidated detection details
        """
        detection_details = []
        
        # Collect all successful detections first
        file_detections = []
        readelf_detections = []
        
        for binary_path in binaries:
            # Process file command output
            file_output = base_analyzer.get_command_output_for_binary("file_output.txt", binary_path)
            if file_output:
                command_str = f"file {binary_path}"
                
                # Extract multiple detections from file output
                detected_values = {}
                detection_types = []
                
                # Architecture detection
                arch = self._parse_architecture_from_file_output(file_output)
                if arch:
                    detected_values["architecture"] = arch
                    detection_types.append("architecture")
                    
                # Endianness detection
                if "LSB" in file_output or "little endian" in file_output.lower():
                    detected_values["endianness"] = ["little"]
                    detection_types.append("endianness")
                elif "MSB" in file_output or "big endian" in file_output.lower():
                    detected_values["endianness"] = ["big"]
                    detection_types.append("endianness")
                
                # Bit width detection
                if "ELF32" in file_output or "32-bit" in file_output:
                    detected_values["bitwidth"] = ["32"]
                    detection_types.append("bitwidth")
                elif "ELF64" in file_output or "64-bit" in file_output:
                    detected_values["bitwidth"] = ["64"]
                    detection_types.append("bitwidth")
                
                if detection_types:
                    file_detections.append({
                        "binary": binary_path,
                        "command": command_str,
                        "output": file_output,
                        "detection_types": detection_types,
                        "detected_values": detected_values,
                        "method": "file"
                    })
            
            # Process readelf -h output
            readelf_output = base_analyzer.get_command_output_for_binary("readelf_h_output.txt", binary_path)
            if readelf_output:
                command_str = f"readelf -h {binary_path}"
                
                detected_values = {}
                detection_types = []
                
                # Architecture detection
                arch = self._parse_architecture_from_readelf_output(readelf_output)
                if arch:
                    detected_values["architecture"] = arch
                    detection_types.append("architecture")
                
                # Endianness detection
                if "Data:" in readelf_output:
                    for line in readelf_output.splitlines():
                        if "Data:" in line:
                            if "little endian" in line.lower():
                                detected_values["endianness"] = ["little"]
                                detection_types.append("endianness")
                            elif "big endian" in line.lower():
                                detected_values["endianness"] = ["big"]
                                detection_types.append("endianness")
                            break
                
                # Bit width detection
                if "Class:" in readelf_output:
                    for line in readelf_output.splitlines():
                        if "Class:" in line:
                            if "ELF32" in line:
                                detected_values["bitwidth"] = ["32"]
                                detection_types.append("bitwidth")
                            elif "ELF64" in line:
                                detected_values["bitwidth"] = ["64"]
                                detection_types.append("bitwidth")
                            break
                
                if detection_types:
                    readelf_detections.append({
                        "binary": binary_path,
                        "command": command_str,
                        "output": readelf_output,
                        "detection_types": detection_types,
                        "detected_values": detected_values,
                        "method": "readelf"
                    })
        
        # Pick one representative from each command type
        # Prefer common binaries like busybox for better representation
        def get_preferred_binary(detections_list):
            if not detections_list:
                return None
            
            # Prefer busybox if available
            for detection in detections_list:
                if "busybox" in detection["binary"].lower():
                    return detection
            
            # Otherwise prefer binaries with shorter paths (likely in /bin or /sbin)
            sorted_detections = sorted(detections_list, key=lambda x: (len(x["binary"]), x["binary"]))
            return sorted_detections[0]
        
        # Add one representative file command output
        if file_detections:
            preferred_file_detection = get_preferred_binary(file_detections)
            if preferred_file_detection:
                if len(file_detections) > 1:
                    preferred_file_detection["note"] = f"Same result from {len(file_detections)} binaries"
                detection_details.append(preferred_file_detection)
        
        # Add one representative readelf command output
        if readelf_detections:
            preferred_readelf_detection = get_preferred_binary(readelf_detections)
            if preferred_readelf_detection:
                if len(readelf_detections) > 1:
                    preferred_readelf_detection["note"] = f"Same result from {len(readelf_detections)} binaries"
                detection_details.append(preferred_readelf_detection)
        
        return detection_details
    
    def _extract_architecture_from_saved_outputs(self, binaries: List[str], base_analyzer: BaseAnalyzer) -> Dict[str, Any]:
        """Extract architecture information from saved command outputs."""
        architectures = set()
        architecture_sources = {}
        
        for binary_path in binaries:
            # Check file output
            file_output = base_analyzer.get_command_output_for_binary("file_output.txt", binary_path)
            if file_output:
                arch = self._parse_architecture_from_file_output(file_output)
                if arch:
                    architectures.add(arch)
                    source_ref = base_analyzer._find_text_in_saved_output("file_output.txt", arch, binary_path)
                    if not source_ref:
                        source_ref = base_analyzer._create_source_reference(
                            "file_output.txt", binary_path, f"file {binary_path}",
                            f"Architecture: {arch}", None
                        )
                    if arch not in architecture_sources:
                        architecture_sources[arch] = []
                    architecture_sources[arch].append(source_ref)
            
            # Check readelf output
            readelf_output = base_analyzer.get_command_output_for_binary("readelf_h_output.txt", binary_path)
            if readelf_output:
                arch = self._parse_architecture_from_readelf_output(readelf_output)
                if arch:
                    architectures.add(arch)
                    source_ref = base_analyzer._find_text_in_saved_output("readelf_h_output.txt", "Machine:", binary_path)
                    if not source_ref:
                        source_ref = base_analyzer._create_source_reference(
                            "readelf_h_output.txt", binary_path, f"readelf -h {binary_path}",
                            f"Architecture: {arch}", None
                        )
                    if arch not in architecture_sources:
                        architecture_sources[arch] = []
                    architecture_sources[arch].append(source_ref)
        
        return {
            "architectures": list(architectures),
            "architecture_sources": architecture_sources
        }
    
    def _extract_endianness_from_saved_outputs(self, binaries: List[str], base_analyzer: BaseAnalyzer) -> Dict[str, Any]:
        """Extract endianness information from saved command outputs."""
        endianness_list = []
        endianness_sources = {}
        
        for binary_path in binaries:
            # Check readelf output first (more reliable)
            readelf_output = base_analyzer.get_command_output_for_binary("readelf_h_output.txt", binary_path)
            if readelf_output and "Data:" in readelf_output:
                for line in readelf_output.splitlines():
                    if "Data:" in line:
                        if "little endian" in line.lower():
                            endianness = "little"
                        elif "big endian" in line.lower():
                            endianness = "big"
                        else:
                            continue
                        
                        if endianness not in endianness_list:
                            endianness_list.append(endianness)
                        
                        source_ref = base_analyzer._find_text_in_saved_output("readelf_h_output.txt", "Data:", binary_path)
                        if not source_ref:
                            source_ref = base_analyzer._create_source_reference(
                                "readelf_h_output.txt", binary_path, f"readelf -h {binary_path}",
                                f"Endianness: {endianness}", None
                            )
                        if endianness not in endianness_sources:
                            endianness_sources[endianness] = []
                        endianness_sources[endianness].append(source_ref)
                        break
            
            # Fallback to file output if readelf didn't work
            if not endianness_list:
                file_output = base_analyzer.get_command_output_for_binary("file_output.txt", binary_path)
                if file_output:
                    if "LSB" in file_output or "little endian" in file_output.lower():
                        endianness = "little"
                    elif "MSB" in file_output or "big endian" in file_output.lower():
                        endianness = "big"
                    else:
                        continue
                    
                    if endianness not in endianness_list:
                        endianness_list.append(endianness)
                    
                    source_ref = base_analyzer._find_text_in_saved_output("file_output.txt", endianness, binary_path)
                    if not source_ref:
                        source_ref = base_analyzer._create_source_reference(
                            "file_output.txt", binary_path, f"file {binary_path}",
                            f"Endianness: {endianness}", None
                        )
                    if endianness not in endianness_sources:
                        endianness_sources[endianness] = []
                    endianness_sources[endianness].append(source_ref)
        
        return {
            "endianness": endianness_list,
            "endianness_sources": endianness_sources
        }
    
    def _extract_bit_width_from_saved_outputs(self, binaries: List[str], base_analyzer: BaseAnalyzer) -> Dict[str, Any]:
        """Extract bit width information from saved command outputs."""
        bit_width_list = []
        bit_width_sources = {}
        
        for binary_path in binaries:
            # Check readelf output first (more reliable)
            readelf_output = base_analyzer.get_command_output_for_binary("readelf_h_output.txt", binary_path)
            if readelf_output and "Class:" in readelf_output:
                for line in readelf_output.splitlines():
                    if "Class:" in line:
                        if "ELF32" in line:
                            bit_width = "32"
                        elif "ELF64" in line:
                            bit_width = "64"
                        else:
                            continue
                        
                        if bit_width not in bit_width_list:
                            bit_width_list.append(bit_width)
                        
                        source_ref = base_analyzer._find_text_in_saved_output("readelf_h_output.txt", "Class:", binary_path)
                        if not source_ref:
                            source_ref = base_analyzer._find_text_in_saved_output("file_output.txt", f"{bit_width}-bit", binary_path)
                        if not source_ref:
                            source_ref = base_analyzer._create_source_reference(
                                "readelf_h_output.txt", binary_path, f"readelf -h {binary_path}",
                                f"Bit width: {bit_width}", None
                            )
                        if bit_width not in bit_width_sources:
                            bit_width_sources[bit_width] = []
                        bit_width_sources[bit_width].append(source_ref)
                        break
            
            # Fallback to file output if readelf didn't work
            if not bit_width_list:
                file_output = base_analyzer.get_command_output_for_binary("file_output.txt", binary_path)
                if file_output:
                    if "ELF32" in file_output or "32-bit" in file_output:
                        bit_width = "32"
                    elif "ELF64" in file_output or "64-bit" in file_output:
                        bit_width = "64"
                    else:
                        continue
                    
                    if bit_width not in bit_width_list:
                        bit_width_list.append(bit_width)
                    
                    source_ref = base_analyzer._find_text_in_saved_output("file_output.txt", f"{bit_width}-bit", binary_path)
                    if not source_ref:
                        source_ref = base_analyzer._create_source_reference(
                            "file_output.txt", binary_path, f"file {binary_path}",
                            f"Bit width: {bit_width}", None
                        )
                    if bit_width not in bit_width_sources:
                        bit_width_sources[bit_width] = []
                    bit_width_sources[bit_width].append(source_ref)
        
        return {
            "bit_width": bit_width_list,
            "bit_width_sources": bit_width_sources
        }
    
    def _extract_floating_type_from_saved_outputs(self, binaries: List[str], base_analyzer: BaseAnalyzer) -> Dict[str, Any]:
        """Extract floating point type information from saved command outputs for ARM."""
        floating_types = []
        # Floating point detection would need more complex analysis
        # For now, return empty results since this is ARM-specific and complex
        return {
            "floating_types": floating_types
        }
    
    def _parse_architecture_from_file_output(self, file_output: str) -> Optional[str]:
        """Parse architecture from file command output."""
        return detect_architecture_from_text(file_output)
    
    def _parse_architecture_from_readelf_output(self, readelf_output: str) -> Optional[str]:
        """Parse architecture from readelf command output."""
        return detect_architecture_from_readelf_output(readelf_output)

# Example usage
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python analysis.py <firmware_path> [kernel_binary] [kernel_csv_log] [rootfs_path]")
        sys.exit(1)
    
    firmware_path = sys.argv[1]
    kernel_binary = sys.argv[2] if len(sys.argv) > 2 else None
    kernel_csv_log = sys.argv[3] if len(sys.argv) > 3 else None
    rootfs_path = sys.argv[4] if len(sys.argv) > 4 else None
    
    try:
        analyzer = FirmwareAnalyzer(firmware_path)
        results = analyzer.analyze_all(
            kernel_binary=kernel_binary,
            kernel_csv_log=kernel_csv_log,
            rootfs_path=rootfs_path
        )
        
        # Print results in a readable format
        print("\n=== Firmware Analysis Results ===\n")
        
        # Kernel Version
        print("\n=== Kernel Version Detection ===")
        for source, versions in results.get("kernel_version", {}).items():
            print(f"\nFrom {source}:")
            for v in versions:
                print(f"  - {v}")
        
        # Kernel Preemption
        if "kernel_preemption" in results:
            print("\n=== Kernel Preemption Model ===")
            preemption = results["kernel_preemption"]
            
            if "models" in preemption:
                print("\nDetected models:")
                for model, count in preemption["models"].items():
                    if count > 0:
                        if model == "rt":
                            name = "RT Preemption (Basic or Full RT)"
                        elif model == "desktop":
                            name = "Low-Latency Desktop Preemption"
                        elif model == "voluntary":
                            name = "Server or Voluntary Preemption"
                        else:
                            name = model.replace("_", " ").title()
                        print(f"  - {name}: {count} occurrences")
                
            if "best_preemption_model" in results:
                print(f"\nBest match: {results['best_preemption_model']}")
            else:
                print("\nCould not determine preemption model")
        
        # Kernel Parameters
        if "boot_parameters" in results:
            print("\n=== Kernel Parameters ===")
            for param_type, values in results["boot_parameters"].items():
                print(f"\n{param_type}:")
                for v in values:
                    print(f"  - {v}")
        
        # Kernel Modules
        print("\n=== Kernel Module Analysis ===")
        modules = results.get("kernel_modules", {})
        print(f"Total modules: {modules.get('module_count', 0)}")
        print(f"Module types: {modules.get('module_types', {})}")
        
        # Kernel Config
        if "kernel_config_file" in results and results["kernel_config_file"]:
            print(f"\n=== Kernel Config ===")
            print(f"Config extracted to: {results['kernel_config_file']}")
        
        # Architecture Information
        print("\n=== Architecture Analysis ===")
        print(f"Architecture: {', '.join(results.get('architecture', []))}")
        print(f"Endianness: {', '.join(results.get('endianness', []))}")
        print(f"Bit Width: {', '.join(results.get('bit_width', []))}")
        
        if "floating_point_type" in results:
            print(f"ARM Floating Point: {', '.join(results.get('floating_point_type', []))}")
        
        # Init Files and Scripts
        if "init_files" in results:
            print("\n=== Init Files ===")
            for file_type, files in results["init_files"].items():
                print(f"\n{file_type}:")
                # Show only first 5 files
                for f in files[:5]:
                    print(f"  - {f}")
                if len(files) > 5:
                    print(f"  ... and {len(files) - 5} more")
        
        # Init Scripts Location
        if "init_scripts_location" in results:
            print("\n=== Init Scripts Location ===")
            for script_type, scripts in results["init_scripts_location"].items():
                print(f"\n{script_type}:")
                # Show only first 5 scripts
                for s in scripts[:5]:
                    print(f"  - {s}")
                if len(scripts) > 5:
                    print(f"  ... and {len(scripts) - 5} more")
        
        # Save results to JSON file
        output_file = f"{os.path.basename(firmware_path)}_analysis.json"
        with open(output_file, 'w') as f:
            # Custom JSON encoder to handle Path objects
            class PathEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, Path):
                        return str(obj)
                    return json.JSONEncoder.default(self, obj)
            
            json.dump(results, f, cls=PathEncoder, indent=2)
        
        print(f"\nDetailed results saved to {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1) 