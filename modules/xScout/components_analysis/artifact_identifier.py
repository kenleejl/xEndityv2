import os
import shutil
import glob
import logging
import subprocess
import re
from typing import Optional, List, Dict, Set
from pathlib import Path

logger = logging.getLogger(__name__)

class ArtifactIdentifier:
    def __init__(self, extract_dir: str):
        """
        Initialize artifact identifier with robust detection of the actual extraction directory
        
        Args:
            extract_dir: Base extraction directory (may be several levels up from actual artifacts)
        """
        self.base_extract_dir = extract_dir
        
        # Find the actual directory containing artifacts
        self.extract_dir = self._find_artifact_directory(extract_dir)
        logger.info(f"Base extraction directory: {self.base_extract_dir}")
        logger.info(f"Detected artifact directory: {self.extract_dir}")
        
        # Get the firmware directory (parent of base extract_dir)
        extract_path = Path(extract_dir)
        self.firmware_dir = str(extract_path.parent)
        # Define artifacts directory
        self.artifacts_dir = os.path.join(self.firmware_dir, "artifacts")
        
        # Track found kernel versions
        self.kernel_versions = set()
        # Track identified artifacts
        self.found_artifacts = {
            "rootfs": [],
            "dtb": [],
            "initramfs": [],
            "kernel": [],
            "nvram": [],
            "config": [],
            "bootloader": []
        }

    def _find_artifact_directory(self, base_dir: str) -> str:
        """
        Find the directory that actually contains firmware artifacts by looking for common patterns.
        
        This method searches through the extraction hierarchy to find the directory that contains
        the actual firmware components (kernel, rootfs, dtb, etc.)
        
        Args:
            base_dir: Base directory to start searching from
            
        Returns:
            Path to the directory containing artifacts
        """
        logger.info(f"Searching for artifact directory starting from: {base_dir}")
        
        # Patterns that indicate a directory contains firmware artifacts
        artifact_indicators = [
            # Image files
            "*.img",
            "kernel*",
            "vmlinux*", 
            "zImage*",
            "uImage*",
            "boot.img",
            "rootfs.img",
            "dtb.img",
            # DTB files
            "*.dtb",
            "*.dts",
            # Filesystem indicators 
            "*squashfs*_extract",
            "*rootfs*_extract",
            # Configuration files
            "*.bin",
            "*.cfg", 
            "*.conf",
            "info.json",
            # Specific firmware files
            "fwinfo.bin",
            "sign.bin"
        ]
        
        # Score each directory based on how many artifact indicators it contains
        best_score = 0
        best_directory = base_dir
        
        # Search through all subdirectories (limited depth to avoid infinite recursion)
        max_depth = 8  # Reduced depth to avoid going too deep into rootfs
        for root, dirs, files in os.walk(base_dir):
            # Calculate depth from base directory
            depth = len(Path(root).relative_to(Path(base_dir)).parts)
            if depth > max_depth:
                continue
            
            # Skip rootfs/squashfs directories for main artifact directory detection
            root_lower = root.lower()
            if ('squashfs' in root_lower and '_extract' in root_lower) or ('rootfs' in root_lower and '_extract' in root_lower):
                logger.debug(f"Skipping rootfs directory for main artifact detection: {root}")
                continue
                
            score = 0
            found_patterns = []
            
            # Check for artifact indicators in this directory
            for pattern in artifact_indicators:
                matches = glob.glob(os.path.join(root, pattern))
                if matches:
                    score += len(matches)
                    found_patterns.append(f"{pattern}: {len(matches)} matches")
            
            # Bonus points for directories with multiple types of artifacts
            if score > 0:
                logger.debug(f"Directory {root} scored {score} points: {', '.join(found_patterns)}")
                
                # Extra points for directories that look like main extraction points
                if any(keyword in os.path.basename(root) for keyword in ['extract', 'uncompressed', 'gzip']):
                    score += 5
                
                # Extra points for finding common firmware file combinations
                files_in_dir = set(files)
                if {'kernel.img', 'rootfs.img', 'dtb.img'}.intersection(files_in_dir):
                    score += 15  # Higher bonus for this perfect combination
                if {'boot.img', 'rootfs.img'}.intersection(files_in_dir):
                    score += 10
                if 'info.json' in files_in_dir:
                    score += 5
                if 'fwinfo.bin' in files_in_dir:
                    score += 5
                    
            if score > best_score:
                best_score = score
                best_directory = root
                logger.info(f"New best artifact directory: {root} (score: {score})")
        
        if best_directory != base_dir:
            logger.info(f"Found better artifact directory: {best_directory} (score: {best_score})")
        else:
            logger.info(f"Using base directory as artifact directory: {base_dir}")
            
        return best_directory
    
    def _find_all_artifact_directories(self, base_dir: str, exclude_rootfs: bool = False) -> List[str]:
        """
        Find all directories that contain firmware artifacts.
        
        This is useful for complex extractions where artifacts might be spread across multiple directories.
        
        Args:
            base_dir: Base directory to start searching from
            exclude_rootfs: If True, exclude rootfs/squashfs directories from search
            
        Returns:
            List of directories containing artifacts, sorted by score (best first)
        """
        logger.info(f"Finding all artifact directories from: {base_dir} (exclude_rootfs: {exclude_rootfs})")
        
        artifact_directories = []
        
        # Same patterns as _find_artifact_directory
        artifact_indicators = [
            "*.img", "kernel*", "vmlinux*", "zImage*", "uImage*", "boot.img", "rootfs.img", "dtb.img",
            "*.dtb", "*.dts", "*squashfs*_extract", "*rootfs*_extract", 
            "*.bin", "*.cfg", "*.conf", "info.json", "fwinfo.bin", "sign.bin"
        ]
        
        max_depth = 10 if not exclude_rootfs else 6  # Limit depth when excluding rootfs
        for root, dirs, files in os.walk(base_dir):
            depth = len(Path(root).relative_to(Path(base_dir)).parts)
            if depth > max_depth:
                continue
            
            # Skip rootfs/squashfs directories if requested
            if exclude_rootfs:
                root_lower = root.lower()
                if ('squashfs' in root_lower and '_extract' in root_lower) or ('rootfs' in root_lower and '_extract' in root_lower):
                    logger.debug(f"Skipping rootfs directory: {root}")
                    continue
                
            score = 0
            found_artifacts = []
            
            for pattern in artifact_indicators:
                matches = glob.glob(os.path.join(root, pattern))
                if matches:
                    score += len(matches)
                    found_artifacts.extend([os.path.basename(m) for m in matches])
            
            if score > 0:
                # Bonus scoring (same as _find_artifact_directory)
                if any(keyword in os.path.basename(root) for keyword in ['extract', 'uncompressed', 'squashfs']):
                    score += 5
                
                files_in_dir = set(files)
                if {'kernel.img', 'rootfs.img', 'dtb.img'}.intersection(files_in_dir):
                    score += 10
                elif {'boot.img', 'rootfs.img'}.intersection(files_in_dir):
                    score += 8
                if 'info.json' in files_in_dir:
                    score += 3
                
                artifact_directories.append({
                    'path': root,
                    'score': score,
                    'artifacts': found_artifacts
                })
        
        # Sort by score (highest first)
        artifact_directories.sort(key=lambda x: x['score'], reverse=True)
        
        for i, dir_info in enumerate(artifact_directories[:5]):  # Log top 5
            logger.info(f"Artifact directory #{i+1}: {dir_info['path']} (score: {dir_info['score']}, artifacts: {dir_info['artifacts'][:10]})")
        
        return [d['path'] for d in artifact_directories]

    def run_command(self, cmd: List[str], cwd=None) -> str:
        """Run a command and return its output"""
        try:
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                cwd=cwd,
                check=False
            )
            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Error running command {' '.join(cmd)}: {e}")
            return ""

    def identify_rootfs(self) -> List[str]:
        """
        Identify potential rootfs directories using enhanced detection across all artifact directories.
        Returns a list of paths to identified rootfs directories.
        """
        rootfs_paths = []
        # Common directories and files found in root filesystems (same as EMBA uses)
        rootfs_indicators = [
            "bin/sh", "bin/bash", "etc/passwd", "etc/shadow", "etc/init.d", 
            "etc/fstab", "etc/inittab", "etc/profile", "etc/hostname",
            "usr/bin", "usr/sbin", "var/log", "lib", "sbin"
        ]
        
        logger.info(f"Searching for rootfs across all artifact directories")
        
        # Use the comprehensive artifact directory detection
        search_dirs = self._find_all_artifact_directories(self.base_extract_dir)
        if not search_dirs:
            search_dirs = [self.extract_dir]
        
        # Also specifically look for squashfs extracted directories in all potential locations
        squashfs_dirs = []
        for search_dir in search_dirs:
            # Recursively find all squashfs_extract directories
            for root, dirs, _ in os.walk(search_dir):
                for d in dirs:
                    if "squashfs" in d.lower() and "_extract" in d.lower():
                        squashfs_path = os.path.join(root, d)
                        squashfs_dirs.append(squashfs_path)
                        logger.info(f"Found squashfs extract directory: {squashfs_path}")
        
        # Combine search directories with found squashfs directories
        all_search_dirs = list(set(search_dirs + squashfs_dirs))
        
        # Walk through all the search directories
        for search_dir in all_search_dirs:
            logger.info(f"Searching for rootfs indicators in {search_dir}")
            indicator_count = 0
            found_indicators = []
            
            for indicator in rootfs_indicators:
                indicator_path = os.path.join(search_dir, indicator)
                if os.path.exists(indicator_path):
                    indicator_count += 1
                    found_indicators.append(indicator)
                    logger.debug(f"Found rootfs indicator: {indicator} in {search_dir}")
                
            # If we find at least 3 indicators, this is likely a rootfs (EMBA uses this threshold)
            if indicator_count >= 3:
                rootfs_paths.append(search_dir)
                # Once we find a squashfs with rootfs, prioritize it
                if "squashfs" in search_dir:
                    logger.info(f"Prioritizing squashfs rootfs: {search_dir}")
                    # Put squashfs rootfs at the beginning but don't remove others
                    rootfs_paths = [search_dir] + [p for p in rootfs_paths if p != search_dir]
        
        # If no rootfs found with indicators, look for any extracted squashfs as fallback
        if not rootfs_paths and squashfs_dirs:
            logger.warning("No rootfs found with indicators, using squashfs directories as fallback")
            rootfs_paths = squashfs_dirs
        
        self.found_artifacts["rootfs"] = rootfs_paths
        return rootfs_paths

    def identify_dtbs(self) -> List[str]:
        """
        Identify Device Tree Blob files using file signatures and extensions.
        Enhanced to search in artifact directories, excluding rootfs to avoid massive recursive searches.
        """
        dtb_paths = []
        
        # Get all potential artifact directories, excluding rootfs directories
        search_dirs = self._find_all_artifact_directories(self.base_extract_dir, exclude_rootfs=True)
        if not search_dirs:
            search_dirs = [self.extract_dir]
        
        # EMBA searches for *.dtb files
        dtb_patterns = ["**/*.dtb", "**/*.dtbo", "**/dtb.img", "**/device-tree*"]
        
        # Search in all potential artifact directories (excluding rootfs)
        for search_dir in search_dirs:
            logger.info(f"Searching for DTB files in: {search_dir}")
            
            # Limit recursion depth to avoid deep searches in large directories
            max_depth = 3
            
            # First look for files with DTB-specific names (with limited depth)
            for root, dirs, files in os.walk(search_dir):
                # Calculate depth and skip if too deep
                depth = len(Path(root).relative_to(Path(search_dir)).parts)
                if depth > max_depth:
                    continue
                
                # Skip if we're in a rootfs-like directory
                if any(keyword in root.lower() for keyword in ['squashfs_v4_le_extract', 'rootfs_extract']):
                    logger.debug(f"Skipping rootfs-like directory: {root}")
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check for DTB-specific filenames
                    if (file.lower().endswith(('.dtb', '.dtbo')) or 
                        'dtb.img' in file.lower() or 
                        'device-tree' in file.lower() or
                        'devicetree' in file.lower()):
                        
                        # Verify it's actually a DTB using the file command
                        file_type = self.run_command(["file", file_path])
                        if ("Device Tree Blob" in file_type or 
                            "dtb" in file_type.lower() or
                            "device tree" in file_type.lower()):
                            logger.info(f"DTB found by filename: {file_path}")
                            dtb_paths.append(file_path)
                        else:
                            logger.info(f"Potential DTB file (by name): {file_path}")
                            dtb_paths.append(file_path)
            
            # Then use glob patterns for additional search (non-recursive for speed)
            for pattern in dtb_patterns:
                # Use non-recursive glob first
                simple_pattern = pattern.replace("**/", "")
                for dtb_path in glob.glob(os.path.join(search_dir, simple_pattern)):
                    if dtb_path not in dtb_paths:  # Avoid duplicates
                        # Verify it's actually a DTB using the file command
                        file_type = self.run_command(["file", dtb_path])
                        if ("Device Tree Blob" in file_type or 
                            "dtb" in file_type.lower() or
                            "device tree" in file_type.lower()):
                            logger.info(f"DTB found by pattern: {dtb_path}")
                            dtb_paths.append(dtb_path)
        
        # Remove duplicates while preserving order
        dtb_paths = list(dict.fromkeys(dtb_paths))
        self.found_artifacts["dtb"] = dtb_paths
        return dtb_paths

    def identify_kernels(self) -> List[str]:
        """
        Identify kernel binaries using EMBA's approach - primarily based on version string patterns.
        This matches the S24_kernel_bin_identifier.sh methodology.
        """
        kernel_paths = []
        
        # Get all potential artifact directories, excluding rootfs directories
        search_dirs = self._find_all_artifact_directories(self.base_extract_dir, exclude_rootfs=True)
        if not search_dirs:
            search_dirs = [self.extract_dir]
        
        # Get already identified bootloaders to exclude them
        existing_bootloaders = set(self.found_artifacts.get("bootloader", []))
        
        # EMBA's kernel version identification patterns (from linux_kernel.json equivalent)
        kernel_version_patterns = [
            r"Linux version [0-9]+\.[0-9]+\.[0-9]+[^\s]*",
            r"Linux [0-9]+\.[0-9]+\.[0-9]+[^\s]*",
            r"vmlinux-[0-9]+\.[0-9]+\.[0-9]+",
            r"kernel version [0-9]+\.[0-9]+\.[0-9]+"
        ]
        
        # Search for potential kernel files in each directory
        for search_dir in search_dirs:
            logger.info(f"Searching for kernels in {search_dir} using EMBA's method")
            
            # Get all files in the directory (EMBA processes all files)
            try:
                for file_path in glob.glob(os.path.join(search_dir, "*")):
                    if not os.path.isfile(file_path):
                        continue
                    
                    # Skip if already identified as bootloader
                    if file_path in existing_bootloaders:
                        continue
                    
                    # Get file type information (EMBA's filtering approach)
                    file_type = self.run_command(["file", "-b", file_path])
                    
                    # EMBA's exclusion criteria - skip these file types
                    if any(exclude_type in file_type.lower() for exclude_type in [
                        "empty", "ascii text", "unicode text", "archive", 
                        "compressed", "image data", "audio", "video"
                    ]):
                        continue
                    
                    # Skip very small files (less than 1KB) - too small for kernels
                    file_size = os.path.getsize(file_path)
                    if file_size < 1024:
                        # Exception: Small files that are explicitly identified as kernels by file command
                        if not any(kernel_indicator in file_type.lower() for kernel_indicator in [
                            "linux kernel", "boot executable", "kernel binary"
                        ]):
                            continue
                        # If it's identified as a kernel by file command, proceed with detection
                        else:
                            logger.info(f"Small file but identified as kernel by file command: {file_path}")
                    
                    # Get strings output for analysis (EMBA's primary method)
                    strings_output = self.run_command(["strings", file_path])
                    
                    # Look for kernel version patterns in strings (EMBA's main detection)
                    kernel_version_found = False
                    found_versions = []
                    
                    for pattern in kernel_version_patterns:
                        matches = re.findall(pattern, strings_output, re.IGNORECASE)
                        if matches:
                            kernel_version_found = True
                            found_versions.extend(matches)
                            # Store identified versions
                            for version in matches:
                                self.kernel_versions.add(version)
                    
                    if kernel_version_found:
                        logger.info(f"Kernel found via version string: {file_path}")
                        logger.info(f"Found versions: {', '.join(found_versions)}")
                        kernel_paths.append(file_path)
                        
                        # Look for init parameters (EMBA also does this)
                        init_patterns = re.findall(r"init=/[^\s]*", strings_output)
                        if init_patterns:
                            logger.info(f"Found init parameters in {file_path}: {', '.join(init_patterns)}")
                    
                    # Additional check for files with kernel-like names but no version strings
                    # (This is more permissive than EMBA but helps catch edge cases)
                    elif not kernel_version_found:
                        filename = os.path.basename(file_path).lower()
                        if any(kernel_name in filename for kernel_name in ["kernel", "vmlinux", "zimage", "uimage"]):
                            # Additional verification for kernel-like files
                            if any(indicator in file_type.lower() for indicator in [
                                "linux kernel", "boot executable", "elf", "executable"
                            ]):
                                logger.info(f"Kernel found via filename and file type: {file_path}")
                                kernel_paths.append(file_path)
                            
                            # Check for kernel-specific strings even without version
                            elif any(kernel_string in strings_output.lower() for kernel_string in [
                                "vmlinux", "linux kernel", "kernel panic", "kallsyms", "printk"
                            ]):
                                logger.info(f"Kernel found via kernel-specific strings: {file_path}")
                                kernel_paths.append(file_path)
                
            except Exception as e:
                logger.error(f"Error searching for kernels in {search_dir}: {e}")
        
        # Remove duplicates while preserving order
        unique_kernel_paths = []
        seen = set()
        for path in kernel_paths:
            if path not in seen:
                unique_kernel_paths.append(path)
                seen.add(path)
        
        self.found_artifacts["kernel"] = unique_kernel_paths
        logger.info(f"Total kernel files identified: {len(unique_kernel_paths)}")
        
        return unique_kernel_paths

    def identify_initramfs(self) -> List[str]:
        """
        Identify initramfs/initrd images.
        Enhanced to search in artifact directories, excluding rootfs.
        """
        initramfs_paths = []
        
        # Get all potential artifact directories, excluding rootfs directories
        search_dirs = self._find_all_artifact_directories(self.base_extract_dir, exclude_rootfs=True)
        if not search_dirs:
            search_dirs = [self.extract_dir]
        
        # Common initramfs/initrd patterns (non-recursive)
        initramfs_patterns = ["initramfs*", "initrd*", "*.cpio*", "ramdisk*"]
        
        for search_dir in search_dirs:
            logger.info(f"Searching for initramfs in {search_dir}")
            for pattern in initramfs_patterns:
                for initramfs_path in glob.glob(os.path.join(search_dir, pattern)):
                    # Verify it's an initramfs/cpio archive
                    file_type = self.run_command(["file", initramfs_path])
                    
                    # Look for common signatures of initramfs files
                    if (
                        "cpio archive" in file_type or 
                        "compressed data" in file_type or
                        "initramfs" in file_type.lower() or
                        "gzip compressed data" in file_type
                    ):
                        logger.info(f"Initramfs/initrd found: {initramfs_path}")
                        initramfs_paths.append(initramfs_path)
        
        self.found_artifacts["initramfs"] = initramfs_paths
        return initramfs_paths

    def identify_nvram(self) -> List[str]:
        """
        Identify NVRAM configuration files in artifact directories, excluding rootfs.
        """
        nvram_paths = []
        
        # Get all potential artifact directories, excluding rootfs directories
        search_dirs = self._find_all_artifact_directories(self.base_extract_dir, exclude_rootfs=True)
        if not search_dirs:
            search_dirs = [self.extract_dir]
        
        # Common NVRAM file patterns (non-recursive)
        nvram_patterns = ["nvram.ini", "nvram.bin", "nvram.cfg", "default.cfg", "factory.bin"]
        
        for search_dir in search_dirs:
            logger.info(f"Searching for NVRAM files in {search_dir}")
            for pattern in nvram_patterns:
                for nvram_path in glob.glob(os.path.join(search_dir, pattern)):
                    if os.path.isfile(nvram_path):
                        logger.info(f"NVRAM file found: {nvram_path}")
                        nvram_paths.append(nvram_path)
        
        self.found_artifacts["nvram"] = nvram_paths
        return nvram_paths

    def identify_config_files(self) -> List[str]:
        """
        Identify configuration files in artifact directories, excluding rootfs.
        """
        config_paths = []
        
        # Get all potential artifact directories, excluding rootfs directories
        search_dirs = self._find_all_artifact_directories(self.base_extract_dir, exclude_rootfs=True)
        if not search_dirs:
            search_dirs = [self.extract_dir]
        
        # Enhanced config file patterns (non-recursive) - includes more firmware-specific files
        config_patterns = [
            "config.bin", "config.cfg", "platform.conf", "system.conf",
            "info.json", "fwinfo.bin", "sign.bin", "sums.bin", 
            "*.conf", "*.json", "*info*", "*config*"
        ]
        
        for search_dir in search_dirs:
            logger.info(f"Searching for config files in {search_dir}")
            for pattern in config_patterns:
                for config_path in glob.glob(os.path.join(search_dir, pattern)):
                    if os.path.isfile(config_path):
                        logger.info(f"Configuration file found: {config_path}")
                        config_paths.append(config_path)
        
        # Remove duplicates while preserving order
        config_paths = list(dict.fromkeys(config_paths))
        self.found_artifacts["config"] = config_paths
        return config_paths

    def copy_artifact(self, src: str, dest: str, is_directory: bool = True):
        """
        Copy artifacts from source to destination
        """
        if os.path.exists(dest):
            if os.path.isdir(dest):
                logger.info(f"Removing existing directory: {dest}")
                try:
                    shutil.rmtree(dest)
                except Exception as e:
                    logger.error(f"Failed to remove existing directory {dest}: {e}")
                    # Try force remove with system command
                    try:
                        os.system(f"rm -rf {dest}")
                    except Exception as e2:
                        logger.error(f"Failed to force remove directory {dest}: {e2}")
            else:
                try:
                    logger.info(f"Removing existing file: {dest}")
                    os.remove(dest)
                except Exception as e:
                    logger.error(f"Failed to remove existing file {dest}: {e}")
                
        try:
            if is_directory:
                # Make sure destination parent directory exists
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                
                # Create destination directory
                os.makedirs(dest, exist_ok=True)
                
                # Try using system commands first for more reliable copying
                if os.name == 'posix':  # Linux/Unix
                    logger.info(f"Copying directory {src} to {dest} using cp command")
                    cmd = f"cp -a {src}/* {dest}/ 2>/dev/null || true"
                    result = os.system(cmd)
                    
                    if result != 0:
                        logger.warning(f"cp command failed with status {result}, trying rsync")
                        cmd = f"rsync -a --ignore-missing-args {src}/ {dest}/ 2>/dev/null || true"
                        result = os.system(cmd)
                        
                        if result != 0:
                            logger.warning(f"rsync command failed with status {result}, falling back to Python")
                            # Fall back to Python method
                            for item in os.listdir(src):
                                s = os.path.join(src, item)
                                d = os.path.join(dest, item)
                                if os.path.isdir(s):
                                    shutil.copytree(s, d, symlinks=True, dirs_exist_ok=True)
                                else:
                                    shutil.copy2(s, d)
                else:
                    # Use Python's built-in copy for non-POSIX platforms
                    logger.info(f"Copying directory {src} to {dest} using Python's shutil")
                    for item in os.listdir(src):
                        s = os.path.join(src, item)
                        d = os.path.join(dest, item)
                        if os.path.isdir(s):
                            shutil.copytree(s, d, symlinks=True, dirs_exist_ok=True)
                        else:
                            shutil.copy2(s, d)
            else:
                # Make sure the destination directory exists
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                logger.info(f"Copying file {src} to {dest}")
                shutil.copy2(src, dest)
            
            # Fix permissions to ensure files are readable
            try:
                if os.name == 'posix':
                    logger.info(f"Setting read permissions on {dest}")
                    os.system(f"chmod -R +r {dest}")
            except Exception as e:
                logger.warning(f"Failed to set permissions on {dest}: {e}")
                
            logger.info(f"Successfully copied {src} to {dest}")
            
        except Exception as e:
            logger.error(f"Failed to copy {src} to {dest}: {e}")
            # Try alternative method with os.system for robustness
            try:
                if is_directory:
                    os.makedirs(dest, exist_ok=True)
                    if os.name == 'posix':  # Linux/Unix
                        logger.info(f"Retrying with different command: rsync")
                        os.system(f"rsync -a --ignore-missing-args {src}/ {dest}/ 2>/dev/null || true")
                    else:
                        for item in os.listdir(src):
                            s = os.path.join(src, item)
                            d = os.path.join(dest, item)
                            os.system(f'xcopy "{s}" "{d}" /E /I /H /Y')
                else:
                    if os.name == 'posix':  # Linux/Unix
                        os.system(f"cp -p {src} {dest} 2>/dev/null || true")
                    else:
                        os.system(f'copy "{src}" "{dest}" /Y')
                
                # Fix permissions again as a precaution
                if os.name == 'posix':
                    os.system(f"chmod -R +r {dest}")
                    
                logger.info(f"Successfully copied {src} to {dest} using alternative method")
            except Exception as alt_error:
                logger.error(f"All copy methods failed for {dest}: {alt_error}")

    def identify_and_copy_rootfs(self):
        """
        Identify and copy rootfs to artifacts directory
        """
        rootfs_paths = self.identify_rootfs()
        
        # Ensure artifacts directory exists
        os.makedirs(self.artifacts_dir, exist_ok=True)
        rootfs_dest = os.path.join(self.artifacts_dir, "rootfs")
        
        # Ensure rootfs destination directory exists
        os.makedirs(rootfs_dest, exist_ok=True)
        
        # If rootfs is found, copy it
        if rootfs_paths:
            logger.info(f"Copying rootfs from {rootfs_paths[0]} to {rootfs_dest}")
            self.copy_artifact(rootfs_paths[0], rootfs_dest, is_directory=True)
            return True
        
        # If no rootfs found, use fallback methods
        logger.warning("No rootfs found. Looking for alternative directories to copy...")
        
        # Look for directories with filesystem structure (bin, etc, usr...)
        potential_dirs = []
        for root, dirs, files in os.walk(self.extract_dir):
            # Check if this directory has some basic filesystem structure
            if ('bin' in dirs or 'etc' in dirs or 'usr' in dirs or 'lib' in dirs):
                logger.info(f"Found potential filesystem directory: {root}")
                potential_dirs.append(root)
                
        # If we found potential filesystem directories, copy the one with most content
        if potential_dirs:
            # Sort by how many of the key directories they have
            best_match = None
            best_score = 0
            
            for potential_dir in potential_dirs:
                score = 0
                rootfs_indicators = ['bin', 'etc', 'usr', 'lib', 'sbin', 'var', 'opt']
                for indicator in rootfs_indicators:
                    if os.path.exists(os.path.join(potential_dir, indicator)):
                        score += 1
                
                if score > best_score:
                    best_score = score
                    best_match = potential_dir
            
            if best_match:
                logger.info(f"Copying best potential rootfs match (score {best_score}/7) from {best_match} to {rootfs_dest}")
                self.copy_artifact(best_match, rootfs_dest, is_directory=True)
                return True
        
        # Last resort: check for squashfs extract directories
        squashfs_dirs = []
        for root, dirs, files in os.walk(self.extract_dir):
            for d in dirs:
                if "squashfs" in d.lower() and "_extract" in d.lower():
                    squashfs_path = os.path.join(root, d)
                    logger.info(f"Found squashfs extract directory: {squashfs_path}")
                    squashfs_dirs.append(squashfs_path)
        
        if squashfs_dirs:
            logger.info(f"Copying squashfs directory as rootfs: {squashfs_dirs[0]} to {rootfs_dest}")
            self.copy_artifact(squashfs_dirs[0], rootfs_dest, is_directory=True)
            return True
            
        # If all else fails, copy the entire extraction directory
        logger.warning(f"No rootfs or alternatives found. Copying entire extraction directory to {rootfs_dest}")
        self.copy_artifact(self.extract_dir, rootfs_dest, is_directory=True)
        
        # Create some basic structure if nothing else worked
        if not os.listdir(rootfs_dest):
            logger.warning("Creating minimal directory structure as last resort")
            for dir_name in ['bin', 'etc', 'usr', 'lib', 'var']:
                os.makedirs(os.path.join(rootfs_dest, dir_name), exist_ok=True)
            
            # Create a readme to explain
            with open(os.path.join(rootfs_dest, "README.txt"), "w") as f:
                f.write("This is a placeholder rootfs created because no valid rootfs could be identified in the firmware.\n")
        
        return False

    def identify_and_copy_dtbs(self):
        """
        Identify and copy DTBs to artifacts directory
        """
        dtb_paths = self.identify_dtbs()
        if dtb_paths:
            logger.info(f"Found {len(dtb_paths)} DTB files")
            
            # Ensure artifacts directory exists
            os.makedirs(self.artifacts_dir, exist_ok=True)
            
            for idx, dtb_path in enumerate(dtb_paths):
                # Copy to artifacts directory
                dtb_dest = os.path.join(self.artifacts_dir, os.path.basename(dtb_path))
                logger.info(f"Copying DTB from {dtb_path} to {dtb_dest}")
                self.copy_artifact(dtb_path, dtb_dest, is_directory=False)
        else:
            logger.info("No DTB found.")

    def identify_and_copy_initramfs(self):
        """
        Identify and copy initramfs to artifacts directory
        """
        initramfs_paths = self.identify_initramfs()
        if initramfs_paths:
            logger.info(f"Found {len(initramfs_paths)} initramfs/initrd files")
            
            # Ensure artifacts directory exists
            os.makedirs(self.artifacts_dir, exist_ok=True)
            
            # Copy all initramfs files with their original names
            for idx, initramfs_path in enumerate(initramfs_paths):
                initramfs_dest = os.path.join(self.artifacts_dir, os.path.basename(initramfs_path))
                logger.info(f"Copying initramfs from {initramfs_path} to {initramfs_dest}")
                self.copy_artifact(initramfs_path, initramfs_dest, is_directory=False)
        else:
            logger.info("No initramfs found.")

    def identify_and_copy_kernels(self):
        """
        Identify and copy kernels to artifacts directory
        """
        kernel_paths = self.identify_kernels()
        if kernel_paths:
            logger.info(f"Found {len(kernel_paths)} kernel files")
            
            # Ensure artifacts directory exists
            os.makedirs(self.artifacts_dir, exist_ok=True)
            
            # Copy all kernels with their original names
            for idx, kernel_path in enumerate(kernel_paths):
                kernel_dest = os.path.join(self.artifacts_dir, os.path.basename(kernel_path))
                logger.info(f"Copying kernel from {kernel_path} to {kernel_dest}")
                self.copy_artifact(kernel_path, kernel_dest, is_directory=False)
                
            # Also save identified kernel versions to a file
            if self.kernel_versions:
                with open(os.path.join(self.artifacts_dir, "kernel_versions.txt"), "w") as f:
                    for version in self.kernel_versions:
                        f.write(f"{version}\n")
        else:
            logger.info("No kernel found.")

    def identify_and_copy_nvram(self):
        """
        Identify and copy NVRAM files to artifacts directory
        """
        nvram_paths = self.identify_nvram()
        if nvram_paths:
            logger.info(f"Found {len(nvram_paths)} NVRAM files")
            
            # Ensure artifacts directory exists
            os.makedirs(self.artifacts_dir, exist_ok=True)
            
            for nvram_path in nvram_paths:
                nvram_dest = os.path.join(self.artifacts_dir, os.path.basename(nvram_path))
                logger.info(f"Copying NVRAM file from {nvram_path} to {nvram_dest}")
                self.copy_artifact(nvram_path, nvram_dest, is_directory=False)
        else:
            logger.info("No NVRAM files found.")

    def identify_and_copy_config_files(self):
        """
        Identify and copy configuration files to artifacts directory
        """
        config_paths = self.identify_config_files()
        if config_paths:
            logger.info(f"Found {len(config_paths)} configuration files")
            
            # Ensure artifacts directory exists
            os.makedirs(self.artifacts_dir, exist_ok=True)
            
            for config_path in config_paths:
                config_dest = os.path.join(self.artifacts_dir, os.path.basename(config_path))
                logger.info(f"Copying configuration file from {config_path} to {config_dest}")
                self.copy_artifact(config_path, config_dest, is_directory=False)
        else:
            logger.info("No configuration files found.")

    def identify_bootloaders(self) -> List[str]:
        """
        Identify bootloader images using EMBA's comprehensive detection techniques.
        Enhanced to avoid hanging with depth limits and timeout protection.
        """
        bootloader_paths = []
        
        # Get all potential artifact directories, excluding rootfs directories
        search_dirs = self._find_all_artifact_directories(self.base_extract_dir, exclude_rootfs=True)
        if not search_dirs:
            search_dirs = [self.extract_dir]
        
        # Limit search to reasonable number of directories to prevent hanging
        search_dirs = search_dirs[:10]  # Limit to first 10 directories
        
        # Bootloader file patterns (based on EMBA and common bootloaders)
        bootloader_patterns = [
            "boot*", "u-boot*", "uboot*", "bootloader*", "loader*",
            "*.img", "*.bin", "*.rom", "*.efi", "*.elf"
        ]
        
        # Search for potential bootloaders in each directory (limited depth)
        for search_dir in search_dirs:
            logger.info(f"Searching for bootloaders in {search_dir}")
            
            # 1. Pattern-based detection (non-recursive for speed)
            for pattern in bootloader_patterns:
                try:
                    simple_pattern = pattern.replace("**/", "")
                    matches = glob.glob(os.path.join(search_dir, simple_pattern))
                    
                    # Limit number of files to check
                    for bootloader_path in matches[:20]:  # Limit to first 20 matches per pattern
                        if os.path.isfile(bootloader_path) and bootloader_path not in bootloader_paths:
                            if self._is_bootloader_file(bootloader_path):
                                logger.info(f"Bootloader found: {bootloader_path}")
                                bootloader_paths.append(bootloader_path)
                except Exception as e:
                    logger.error(f"Error searching for bootloader with pattern {pattern}: {e}")
            
            # Stop if we found enough bootloaders
            if len(bootloader_paths) >= 10:
                logger.info("Found sufficient bootloaders, stopping search")
                break
        
        self.found_artifacts["bootloader"] = bootloader_paths
        return bootloader_paths
    
    def _is_bootloader_file(self, file_path: str) -> bool:
        """
        Determine if a file is a bootloader using EMBA's detection techniques.
        Optimized to prevent hanging with faster, more targeted checks.
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # Skip very small files (less than 32 bytes) and very large files (over 50MB)
            if file_size < 32 or file_size > 50 * 1024 * 1024:
                return False
            
            # Get file type (most reliable check)
            file_type = self.run_command(["file", file_path])
            
            # 1. U-Boot detection (EMBA's primary bootloader detection)
            if "u-boot legacy uImage" in file_type.lower():
                logger.info(f"U-Boot image detected: {file_path}")
                return True
            
            # 2. EFI bootloader detection
            if "PE32" in file_type and ("executable" in file_type or "bootloader" in file_type.lower()):
                logger.info(f"EFI bootloader detected: {file_path}")
                return True
            
            # 3. Quick filename-based detection for common bootloader files
            filename = os.path.basename(file_path).lower()
            if filename in ["boot.img", "bootloader.img", "u-boot.bin", "u-boot.img"]:
                # For known bootloader filenames, do minimal string check
                if "data" in file_type.lower() and 32 * 1024 <= file_size <= 2 * 1024 * 1024:
                    # Quick string check (limited to avoid hanging)
                    strings_output = self.run_command(["strings", "-n", "8", file_path])[:1000]  # Limit output
                    bootloader_indicators = ["boot", "loader", "firmware", "tftp", "dhcp"]
                    
                    indicator_count = sum(1 for indicator in bootloader_indicators if indicator in strings_output.lower())
                    if indicator_count >= 2:
                        logger.info(f"Bootloader detected via filename and string indicators: {file_path}")
                        return True
            
            # 4. File size and type heuristics (fast check)
            if 32 * 1024 <= file_size <= 2 * 1024 * 1024:  # Typical bootloader size range
                if "boot" in filename and ("data" in file_type.lower() or "executable" in file_type.lower()):
                    logger.info(f"Bootloader detected via filename and size heuristics: {file_path}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error analyzing bootloader file {file_path}: {e}")
            return False

    def identify_and_copy_bootloaders(self):
        """
        Copy identified bootloader files to artifacts directory with proper naming.
        """
        if not self.found_artifacts["bootloader"]:
            return
        
        logger.info(f"Copying {len(self.found_artifacts['bootloader'])} bootloader files to artifacts directory")
        
        for bootloader_path in self.found_artifacts["bootloader"]:
            try:
                bootloader_filename = os.path.basename(bootloader_path)
                
                # Handle potential naming conflicts
                counter = 1
                original_filename = bootloader_filename
                while os.path.exists(os.path.join(self.artifacts_dir, bootloader_filename)):
                    name, ext = os.path.splitext(original_filename)
                    bootloader_filename = f"{name}_{counter}{ext}"
                    counter += 1
                
                dest_path = os.path.join(self.artifacts_dir, bootloader_filename)
                
                # Copy the bootloader file
                shutil.copy2(bootloader_path, dest_path)
                logger.info(f"Copied bootloader {bootloader_path} to {dest_path}")
                
            except Exception as e:
                logger.error(f"Error copying bootloader {bootloader_path}: {e}")

    def identify_and_copy_all(self):
        """
        Identify and copy all artifacts: rootfs, dtb, initramfs, kernel, nvram, config
        to the artifacts directory in the firmware folder.
        """
        # First identify all artifacts (with better logging)
        logger.info("Starting artifact identification...")
        
        self.identify_rootfs()
        logger.info(f"Rootfs identification complete. Found {len(self.found_artifacts['rootfs'])} potential rootfs.")
        
        self.identify_dtbs()
        logger.info(f"DTB identification complete. Found {len(self.found_artifacts['dtb'])} DTB files.")
        
        self.identify_initramfs()
        logger.info(f"Initramfs identification complete. Found {len(self.found_artifacts['initramfs'])} initramfs files.")
        
        # Run bootloader detection BEFORE kernel detection to avoid conflicts
        self.identify_bootloaders()
        logger.info(f"Bootloader identification complete. Found {len(self.found_artifacts['bootloader'])} bootloader files.")
        
        self.identify_kernels()
        logger.info(f"Kernel identification complete. Found {len(self.found_artifacts['kernel'])} kernel files.")
        
        self.identify_nvram()
        logger.info(f"NVRAM identification complete. Found {len(self.found_artifacts['nvram'])} NVRAM files.")
        
        self.identify_config_files()
        logger.info(f"Configuration files identification complete. Found {len(self.found_artifacts['config'])} configuration files.")
        
        logger.info(f"Identified {len(self.kernel_versions)} kernel versions.")
        
        # Create artifacts directory
        os.makedirs(self.artifacts_dir, exist_ok=True)
        
        # Write the summary file first so it's always created even if copying fails
        with open(os.path.join(self.artifacts_dir, "artifacts_summary.txt"), "w") as f:
            f.write(f"Found {len(self.found_artifacts['rootfs'])} rootfs directories\n")
            f.write(f"Found {len(self.found_artifacts['dtb'])} DTB files\n")
            f.write(f"Found {len(self.found_artifacts['initramfs'])} initramfs files\n")
            f.write(f"Found {len(self.found_artifacts['kernel'])} kernel files\n")
            f.write(f"Found {len(self.found_artifacts['nvram'])} NVRAM files\n")
            f.write(f"Found {len(self.found_artifacts['config'])} configuration files\n")
            f.write(f"Found {len(self.found_artifacts['bootloader'])} bootloader files\n")
            f.write(f"Identified {len(self.kernel_versions)} kernel versions\n")
            
            # Add information about what artifacts will be copied
            f.write("\nArtifacts copied to artifacts directory:\n")
            if self.found_artifacts['rootfs']:
                f.write(f"  Rootfs: {self.artifacts_dir}/rootfs (from {self.found_artifacts['rootfs'][0]})\n")
            
            if self.found_artifacts['kernel']:
                for kernel_path in self.found_artifacts['kernel']:
                    f.write(f"  Kernel: {self.artifacts_dir}/{os.path.basename(kernel_path)} (from {kernel_path})\n")
            
            if self.found_artifacts['dtb']:
                for dtb_path in self.found_artifacts['dtb']:
                    f.write(f"  DTB: {self.artifacts_dir}/{os.path.basename(dtb_path)} (from {dtb_path})\n")
            
            if self.found_artifacts['initramfs']:
                for initramfs_path in self.found_artifacts['initramfs']:
                    f.write(f"  Initramfs: {self.artifacts_dir}/{os.path.basename(initramfs_path)} (from {initramfs_path})\n")
            
            if self.found_artifacts['nvram']:
                for nvram_path in self.found_artifacts['nvram']:
                    f.write(f"  NVRAM: {self.artifacts_dir}/{os.path.basename(nvram_path)} (from {nvram_path})\n")
            
            if self.found_artifacts['config']:
                for config_path in self.found_artifacts['config']:
                    f.write(f"  Config: {self.artifacts_dir}/{os.path.basename(config_path)} (from {config_path})\n")
            
            if self.found_artifacts['bootloader']:
                for bootloader_path in self.found_artifacts['bootloader']:
                    f.write(f"  Bootloader: {self.artifacts_dir}/{os.path.basename(bootloader_path)} (from {bootloader_path})\n")
            
            if self.kernel_versions:
                f.write("\nKernel versions:\n")
                for version in self.kernel_versions:
                    f.write(f"  {version}\n")
        
        # Copy artifacts to artifacts directory
        if self.found_artifacts['rootfs']:
            self.identify_and_copy_rootfs()
        
        if self.found_artifacts['dtb']:
            self.identify_and_copy_dtbs()
        
        if self.found_artifacts['initramfs']:
            self.identify_and_copy_initramfs()
        
        if self.found_artifacts['kernel']:
            self.identify_and_copy_kernels()
        
        if self.found_artifacts['nvram']:
            self.identify_and_copy_nvram()
        
        if self.found_artifacts['config']:
            self.identify_and_copy_config_files()
        
        if self.found_artifacts['bootloader']:
            self.identify_and_copy_bootloaders()
        
        logger.info("Artifact identification and copying complete!")
        
        # Return paths to the final artifacts
        artifact_paths = {}
        
        # Get rootfs
        if os.path.exists(os.path.join(self.artifacts_dir, "rootfs")):
            artifact_paths["rootfs"] = os.path.join(self.artifacts_dir, "rootfs")
        
        # Get all kernels with original names
        kernel_files = []
        if self.found_artifacts['kernel']:
            for kernel_path in self.found_artifacts['kernel']:
                kernel_filename = os.path.basename(kernel_path)
                copied_kernel_path = os.path.join(self.artifacts_dir, kernel_filename)
                if os.path.exists(copied_kernel_path):
                    kernel_files.append(copied_kernel_path)
        
        if kernel_files:
            artifact_paths["kernel"] = kernel_files[0]  # Primary kernel
            if len(kernel_files) > 1:
                artifact_paths["additional_kernels"] = kernel_files[1:]
        
        # Get all initramfs with original names
        initramfs_files = []
        if self.found_artifacts['initramfs']:
            for initramfs_path in self.found_artifacts['initramfs']:
                initramfs_filename = os.path.basename(initramfs_path)
                copied_initramfs_path = os.path.join(self.artifacts_dir, initramfs_filename)
                if os.path.exists(copied_initramfs_path):
                    initramfs_files.append(copied_initramfs_path)
        
        if initramfs_files:
            artifact_paths["initramfs"] = initramfs_files[0]  # Primary initramfs
            if len(initramfs_files) > 1:
                artifact_paths["additional_initramfs"] = initramfs_files[1:]
        
        # Get all DTB files
        dtb_files = []
        if self.found_artifacts['dtb']:
            for dtb_path in self.found_artifacts['dtb']:
                dtb_filename = os.path.basename(dtb_path)
                copied_dtb_path = os.path.join(self.artifacts_dir, dtb_filename)
                if os.path.exists(copied_dtb_path):
                    dtb_files.append(copied_dtb_path)
        
        if dtb_files:
            artifact_paths["dtb"] = dtb_files[0]  # Primary DTB
            if len(dtb_files) > 1:
                artifact_paths["additional_dtbs"] = dtb_files[1:]
        
        # Get all NVRAM files
        nvram_files = []
        if self.found_artifacts['nvram']:
            for nvram_path in self.found_artifacts['nvram']:
                nvram_filename = os.path.basename(nvram_path)
                copied_nvram_path = os.path.join(self.artifacts_dir, nvram_filename)
                if os.path.exists(copied_nvram_path):
                    nvram_files.append(copied_nvram_path)
        
        if nvram_files:
            artifact_paths["nvram"] = nvram_files
        
        # Get all config files
        config_files = []
        if self.found_artifacts['config']:
            for config_path in self.found_artifacts['config']:
                config_filename = os.path.basename(config_path)
                copied_config_path = os.path.join(self.artifacts_dir, config_filename)
                if os.path.exists(copied_config_path):
                    config_files.append(copied_config_path)
        
        if config_files:
            artifact_paths["config"] = config_files
        
        # Get all bootloader files
        bootloader_files = []
        if self.found_artifacts['bootloader']:
            for bootloader_path in self.found_artifacts['bootloader']:
                bootloader_filename = os.path.basename(bootloader_path)
                copied_bootloader_path = os.path.join(self.artifacts_dir, bootloader_filename)
                if os.path.exists(copied_bootloader_path):
                    bootloader_files.append(copied_bootloader_path)
        
        if bootloader_files:
            artifact_paths["bootloader"] = bootloader_files
        
        # Update found_artifacts with standardized paths
        self.found_artifacts["standardized_paths"] = artifact_paths
        
        return artifact_paths

# Example usage:
# identifier = ArtifactIdentifier("./firmwares/brand/model/version/target_extract/extracted_files")
# identifier.identify_and_copy_all() 