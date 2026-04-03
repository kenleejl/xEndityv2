"""
Service for firmware extraction using xfs
"""
import os
import sys
import json
import logging
import subprocess
import threading
import time
import shutil
import glob
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.core.cache import cache
from modules.xQuire.models import Firmware
from modules.xScout.models.repositories import FirmwareAnalysisRepository
from modules.xScout.models.mongo_models import FirmwareAnalysisModel
from modules.base.utils.docker_utils import DockerUtils

logger = logging.getLogger(__name__)

class FirmwareExtractionService:
    """Service for extracting firmware files"""
    
    def __init__(self):
        self.repository = FirmwareAnalysisRepository()
    
    def extract_firmware(self, firmware_id: int) -> Tuple[bool, str]:
        """
        Start of firmware extraction process
        1. Perform checks & preparations   
        2. _run_xfs: Run extraction process with xfs
        3. _post_extraction: Post-process the extraction results
        
        Args:
            firmware_id: ID of the firmware to extract
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            # Get firmware details
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Check if firmware file exists
            if not os.path.exists(firmware.file.path):
                error_msg = f"Firmware file not found: {firmware.file.path}"
                logger.error(error_msg)
                return False, error_msg
            
            # Get the firmware filename and path
            fw_file = os.path.basename(firmware.file.path)
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(fw_file)[0]
            
            # Clean up any existing extraction directory
            output_dir = os.path.join(fw_dir, f"{fw_name}_extract")
            
            # Remove existing extraction directory if it exists
            if os.path.exists(output_dir):
                logger.info(f"Removing existing extraction directory: {output_dir}")
                try:
                    shutil.rmtree(output_dir)
                except Exception as e:
                    logger.warning(f"Failed to remove existing extraction directory: {e}")
            
            # Start extraction in a new thread
            threading.Thread(
                target=self._run_xfs,
                args=(firmware, fw_file, fw_name, fw_dir)
            ).start()
            
            return True, f"Extraction started for {fw_file}"
        
        except Firmware.DoesNotExist:
            error_msg = f"Firmware with ID {firmware_id} not found"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error starting firmware extraction: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _run_xfs(self, firmware: Firmware, fw_file: str, fw_name: str, fw_dir: str):
        """
        Run the firmware extraction process using xfs Docker container
        
        Args:
            firmware: Firmware model instance
            fw_file: Firmware file name
            fw_name: Firmware name without extension
            fw_dir: Directory containing the firmware file
        """
        try:
            # Create output directory with cleaner naming
            output_dir = os.path.join(fw_dir, f"{fw_name}_extract")
            os.makedirs(output_dir, exist_ok=True)
            
            # Get full paths for firmware file and output directory
            firmware_path = firmware.file.path
            
            logger.info(f"Starting extraction for {fw_file} using xfs Docker container")
            
            # Check if Docker is available
            if not DockerUtils.is_docker_available():
                logger.error("Docker is not available")
                return
            
            logger.info(f"Output directory: {output_dir}")
            
            # Get absolute paths for volume mapping
            firmware_dir = os.path.dirname(firmware_path)
            firmware_filename = os.path.basename(firmware_path)
            output_dir_abs = os.path.abspath(output_dir)
            firmware_dir_abs = os.path.abspath(firmware_dir)
            
            # Create unique guest paths based on directory names
            firmware_guest_dir = f"/host_{os.path.basename(firmware_dir_abs)}"
            output_guest_dir = f"/host_{os.path.basename(output_dir_abs)}"
            
            # Set up volume mappings
            volumes = {
                firmware_dir_abs: {'bind': firmware_guest_dir, 'mode': 'ro'},
                output_dir_abs: {'bind': output_guest_dir, 'mode': 'rw'}
            }
            
            # Build the xfs command arguments for the container
            xfs_args = [
                f"{firmware_guest_dir}/{firmware_filename}",
                "--force",
                "--progress", 
                "--output", output_guest_dir
            ]
            
            # Get current user info for proper permissions
            user_id, group_id = DockerUtils.get_current_user_info()
            user_spec = f"{user_id}:{group_id}"
            
            # Set up environment variables
            environment = {
                'XFS_HASH': 'python_wrapper'  # Placeholder hash for Python wrapper
            }
            
            # Create log file for xfs output
            log_file_path = os.path.join(output_dir, "xfs.log")
            
            logger.info(f"Running Docker command with volumes: {volumes}")
            logger.info(f"XFS args: {xfs_args}")
            
            # Run the Docker container
            success, container, error_msg = DockerUtils.run_container(
                image="xendity/xfs",
                command=["fakeroot_xfs"] + xfs_args,
                environment=environment,
                volumes=volumes,
                user=user_spec,
                remove=True,
                detach=True
            )
            
            if not success:
                logger.error(f"Failed to start xfs container: {error_msg}")
                return
            
            logger.info(f"XFS container started: {container.id}")
            
            # Stream logs and wait for completion
            extraction_succeeded = False
            
            try:
                # Open log file for writing
                with open(log_file_path, 'w') as log_file:
                    # Stream container logs in real-time
                    for log_line in container.logs(stream=True, follow=True):
                        if isinstance(log_line, bytes):
                            log_line = log_line.decode('utf-8')
                        
                        line = log_line.rstrip()
                        if line:
                            logger.info(f"xfs: {line}")
                            # Write to log file immediately and flush
                            log_file.write(log_line)
                            log_file.flush()
                
                # Wait for container to complete and get exit code
                result = container.wait()
                exit_code = result['StatusCode']
                
                # Check if extraction was successful
                if exit_code == 0:
                    logger.info(f"Extraction completed successfully for {firmware.file.name}")
                    extraction_succeeded = True
                else:
                    logger.warning(f"xfs container exited with code {exit_code} for {firmware.file.name}")
                    
                    # Even if xfs reported failure, check if files were actually extracted
                    # Check if rootfs.tar.gz was created
                    rootfs_archive = os.path.join(output_dir, "rootfs.tar.gz")
                    xfs_extract_dir = os.path.join(output_dir, "xfs-extract")
                    
                    if os.path.exists(rootfs_archive) or os.path.exists(xfs_extract_dir):
                        logger.info(f"Found extraction artifacts despite xfs container error")
                        extraction_succeeded = True
                    else:
                        logger.error(f"Extraction failed for {firmware.file.name}")
                        
                        # Get container logs for error analysis
                        error_logs = DockerUtils.get_container_logs(container.id, tail=50)
                        if error_logs:
                            logger.error(f"Container error logs: {error_logs}")
                            
                            # Provide additional context for common issues
                            if "permission denied" in error_logs.lower():
                                logger.error("Permission issue detected. Check file permissions.")
                            elif "not found" in error_logs.lower():
                                logger.error("xfs binary or Docker image not found. Check installation.")
                            elif "no space left" in error_logs.lower():
                                logger.error("Disk space issue detected.")
                
            except Exception as stream_error:
                logger.error(f"Error streaming container logs: {stream_error}")
                # Try to get final logs
                final_logs = DockerUtils.get_container_logs(container.id)
                if final_logs:
                    logger.info(f"Final container logs: {final_logs}")
                    with open(log_file_path, 'w') as log_file:
                        log_file.write(final_logs)
            
            if extraction_succeeded:
                # Post-process the extraction results
                rootfs_tar = self._post_extraction(output_dir, fw_file)
                self._notify_xformation_rootfs_extraction(firmware, rootfs_tar)
                
        except Exception as e:
            logger.error(f"Error during extraction process: {str(e)}")
    
    def _post_extraction(self, output_dir: str, fw_file: str) -> str:
        """
        Process the extraction results from xfs
        
        Args:
            output_dir: Path to the extraction output directory
            fw_file: Firmware file name

        Returns: 
            Relative path to rootfs.tar.gz from project root, or None if not found
        """
        try:
            # 1. Search for xfs_results.json in the output directory
            results_file = os.path.join(output_dir, "xfs_results.json")
            if not os.path.exists(results_file):
                logger.error(f"xfs_results.json not found in {output_dir}")
                return
            
            # 2. Read the results file to get extraction information
            try:
                with open(results_file, 'r') as f:
                    results = json.load(f)
                
                # Extract key information
                preferred_extractor = results.get('preferred_extractor')
                identified_rootfs = results.get('identified_rootfs')
                rootfs_archive = results.get('rootfs_archive')
                extracted_files = results.get('extracted_files')
                
                # If preferred_extractor is null, skip remaining steps
                if not preferred_extractor:
                    logger.warning("No Linux Rootfs found")
                    return
                
                # 3. Form absolute paths
                rootfs = os.path.join(output_dir, identified_rootfs) if identified_rootfs else None
                rootfs_tar = os.path.join(output_dir, rootfs_archive) if rootfs_archive else None
                extracted = os.path.join(output_dir, "xfs-extract", preferred_extractor) if extracted_files else None
                
                # Create artifacts directory in the firmware directory (parent of output_dir)
                # output_dir example: <project_root>/firmwares/DLink/DIR-880L/latest/dir880_extract
                # fw_dir example: <project_root>/firmwares/DLink/DIR-880L/latest
                # artifacts_dir example: <project_root>/firmwares/DLink/DIR-880L/latest/artifacts
                fw_dir = os.path.dirname(output_dir)  # Get the firmware directory (parent of output_dir)
                artifacts_dir = os.path.join(fw_dir, "artifacts")  # This is the artifacts directory
                os.makedirs(artifacts_dir, exist_ok=True)
                
                # 4. Create symbolic links
                # Link rootfs archive to artifacts directory
                if rootfs_tar and os.path.exists(rootfs_tar):
                    artifact_rootfs_tar = os.path.join(artifacts_dir, "rootfs.tar.gz")
                    self._create_symlink(rootfs_tar, artifact_rootfs_tar)
                
                # Link identified rootfs to artifacts directory
                if rootfs and os.path.exists(rootfs):
                    artifact_rootfs_dir = os.path.join(artifacts_dir, "rootfs")
                    self._create_symlink(rootfs, artifact_rootfs_dir)
                
                # Link extracted files to output directory
                if extracted and os.path.exists(extracted):
                    extracted_files_link = os.path.join(output_dir, "extracted_files")
                    self._create_symlink(extracted, extracted_files_link)
                    
                logger.info(f"Created symbolic links for extraction artifacts in {artifacts_dir} and {output_dir}")
                
                # Return relative path from project root instead of absolute path
                if rootfs_tar and os.path.exists(rootfs_tar):
                    # Convert absolute path to relative path from BASE_DIR
                    relative_rootfs_tar = os.path.relpath(rootfs_tar, settings.BASE_DIR)
                    logger.info(f"Returning relative rootfs path: {relative_rootfs_tar}")
                    return relative_rootfs_tar
                
                return None
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing xfs_results.json: {e}")
                return
            except Exception as e:
                logger.error(f"Error processing extraction results: {e}")
                return
            
        except Exception as e:
            logger.error(f"Error in post-extraction: {str(e)}")
    
    def _create_symlink(self, source, target):
        """
        Create a symbolic link, removing the target first if it exists
        
        Args:
            source: Source path
            target: Target path for the symlink
        """
        try:
            # Remove existing target if it exists
            if os.path.exists(target) or os.path.islink(target):
                if os.path.isdir(target) and not os.path.islink(target):
                    shutil.rmtree(target)
                else:
                    os.unlink(target)
            
            # Create the symlink
            os.symlink(source, target)
            logger.info(f"Created symlink from {source} to {target}")
            
        except Exception as e:
            logger.error(f"Failed to create symlink from {source} to {target}: {e}")
            
            # If symlink fails, try to copy instead
            try:
                if os.path.isdir(source):
                    shutil.copytree(source, target)
                else:
                    shutil.copy2(source, target)
                logger.info(f"Copied from {source} to {target} (symlink failed)")
            except Exception as copy_error:
                logger.error(f"Failed to copy from {source} to {target}: {copy_error}")
                            
        except Exception as e:
            logger.error(f"Error in post-processing: {str(e)}")
    
    def _notify_xformation_rootfs_extraction(self, firmware: Firmware, rootfs_tar_path: str):
        """
        Notify xFormation module when rootfs.tar.gz is successfully extracted
        """
        try:
            if rootfs_tar_path and os.path.exists(rootfs_tar_path):
                # Import xFormation service (only when needed to avoid circular imports)
                from modules.xFormation.services.device_discovery_service import DeviceDiscoveryService
                
                # Create or update EmulatedDevice record
                device = DeviceDiscoveryService.create_device_from_extraction(firmware.id, rootfs_tar_path)
                if device:
                    logger.info(f"Successfully notified xFormation about rootfs extraction for firmware {firmware.id}")
                else:
                    logger.warning(f"Failed to create xFormation device for firmware {firmware.id}")
            else:
                logger.debug(f"No rootfs.tar.gz to report to xFormation for firmware {firmware.id}")
                
        except ImportError:
            logger.debug("xFormation module not available - skipping notification")
        except Exception as e:
            logger.error(f"Error notifying xFormation about rootfs extraction: {e}")

# The _identify_rootfs method has been removed - rootfs identification now occurs in artifact_identifier.py
