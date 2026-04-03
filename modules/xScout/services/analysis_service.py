"""
Service for firmware analysis using the fw_binary_analysis analyzer
"""
import os
import sys
import json
import logging
import subprocess
import threading
import time
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

class FirmwareAnalysisService:
    """Service for analyzing firmware files"""
    
    def __init__(self):
        self.repository = FirmwareAnalysisRepository()
    

    
    def analyze_firmware(self, firmware_id: int) -> Optional[str]:
        """
        Start firmware analysis process
        
        Args:
            firmware_id: ID of the firmware to analyze
            
        Returns:
            Analysis ID if successful, None otherwise
        """
        try:
            # Get firmware details
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Check if firmware file exists
            if not os.path.exists(firmware.file.path):
                logger.error(f"Firmware file not found: {firmware.file.path}")
                return None
            
            # Create analysis record
            analysis = FirmwareAnalysisModel(
                firmware_id=firmware_id,
                file_path=firmware.file.path,
                status="pending",
                progress=0
            )
            
            # Save to MongoDB
            analysis_id = self.repository.save(analysis)
            
            if not analysis_id:
                logger.error(f"Failed to create analysis record for firmware {firmware_id}")
                return None
            
            # Start analysis in background - try Docker first, fall back to local if Docker fails
            threading.Thread(
                target=self._run_analysis_with_fallback,
                args=(analysis_id, firmware)
            ).start()
            
            return analysis_id
        
        except Firmware.DoesNotExist:
            logger.error(f"Firmware with ID {firmware_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error starting firmware analysis: {str(e)}")
            return None
    
    def _run_analysis_with_fallback(self, analysis_id: str, firmware: Firmware):
        """
        Try Docker analysis first, fall back to local execution if Docker fails
        
        Args:
            analysis_id: MongoDB document ID
            firmware: Firmware model instance
        """
        try:
            # Try Docker first
            logger.info(f"Attempting Docker analysis for {analysis_id}")
            self._run_docker_analysis(analysis_id, firmware)
        except Exception as e:
            logger.warning(f"Docker analysis failed for {analysis_id}: {str(e)}")
            logger.info(f"Falling back to local execution for {analysis_id}")
            try:
                self._run_local_analysis_process(analysis_id, firmware)
            except Exception as local_e:
                logger.error(f"Local analysis also failed for {analysis_id}: {str(local_e)}")
                self.repository.update_status(analysis_id, "failed", 0)
    
    def _run_docker_analysis(self, analysis_id: str, firmware: Firmware):
        """
        Run the firmware analysis process using Docker
        
        Args:
            analysis_id: MongoDB document ID
            firmware: Firmware model instance
        """
        try:
            # Check if Docker is available
            if not DockerUtils.is_docker_available():
                raise RuntimeError("Docker is not available")
            
            # Initialize progress tracker
            self.repository.update_status(analysis_id, "starting_container", 5)
            
            # Get MongoDB connection details from settings
            mongodb_settings = getattr(settings, 'MONGODB_CLIENT', {})
            mongodb_host = mongodb_settings.get('host', 'localhost')
            mongodb_port = mongodb_settings.get('port', 27017)
            mongodb_db = mongodb_settings.get('db', 'xendity_firmwares')
            
            # Determine MongoDB connection for container
            mongodb_host_for_container, network_mode = DockerUtils.determine_mongodb_connection(
                mongodb_host, mongodb_port
            )
            
            logger.info(f"Using MongoDB connection: {mongodb_host_for_container} on network: {network_mode}")
            
            # Build container configuration
            container_name = f"xscout-analysis-{analysis_id}"
            firmware_path = firmware.file.path
            firmware_basename = os.path.basename(firmware_path)
            firmware_directory = os.path.dirname(firmware_path)
            
            # Mount the entire firmware directory as read-write
            container_firmware_dir = "/firmware"
            container_firmware_path = f"{container_firmware_dir}/{firmware_basename}"
            
            # Output will be created in the same directory as firmware
            firmware_name = os.path.splitext(firmware_basename)[0]
            container_output_dir = f"{container_firmware_dir}/{firmware_name}_analysis"
            
            logger.info(f"Mounting firmware directory: {firmware_directory} -> {container_firmware_dir}")
            logger.info(f"Analysis output will be created at: {container_output_dir}")
            
            # Build environment variables
            environment = {
                'MONGODB_HOST': mongodb_host_for_container,
                'MONGODB_PORT': str(mongodb_port),
                'MONGODB_DB': mongodb_db,
                'MONGODB_COLLECTION': 'firmware_analysis',
                'OUTPUT_DIR': container_output_dir
            }
            
            # Get current user info
            user_id, group_id = DockerUtils.get_current_user_info()
            
            # Build volumes
            volumes = {
                firmware_directory: {
                    'bind': container_firmware_dir,
                    'mode': 'rw'
                }
            }
            
            # Build extra hosts if using host network
            extra_hosts = {}
            if network_mode == 'host':
                extra_hosts['host.docker.internal'] = 'host-gateway'
            
            # Build command
            command = [
                '--analysis-id', analysis_id,
                '--firmware-path', container_firmware_path
            ]
            
            # Run the Docker container
            success, container, error_msg = DockerUtils.run_container(
                image='xendity/fwbinary-analysis',
                command=command,
                environment=environment,
                volumes=volumes,
                network_mode=network_mode,
                name=container_name,
                remove=True,
                detach=True,
                user=f"{user_id}:{group_id}",
                extra_hosts=extra_hosts if extra_hosts else None
            )
            
            if not success:
                raise RuntimeError(f"Failed to start Docker container: {error_msg}")
            
            # Wait for container to complete
            success, exit_code = DockerUtils.wait_for_container(container_name)
            
            if not success or exit_code != 0:
                # Get container logs for debugging
                logs = DockerUtils.get_container_logs(container_name)
                error_msg = f"Docker container failed with exit code {exit_code}"
                if logs:
                    error_msg += f"\nLogs: {logs}"
                raise RuntimeError(error_msg)
            else:
                logger.info(f"Docker container completed successfully")
                # The container updates the analysis status directly in MongoDB
        
        except Exception as e:
            logger.error(f"Error running Docker analysis: {str(e)}")
            raise  # Re-raise the exception so fallback can catch it
    
    def _run_local_analysis_process(self, analysis_id: str, firmware: Firmware):
        """
        Run the firmware fw_binary_analysis process locally (fallback method)
        
        Args:
            analysis_id: MongoDB document ID
            firmware: Firmware model instance
        """
        try:
            # Initialize progress tracker
            self.repository.update_status(analysis_id, "running", 5)
            
            # Get the fw_binary_analysis script path
            script_path = os.path.join(
                settings.BASE_DIR,
                'modules',
                'xScout',
                'fw_binary_analysis',
                'fw_binary_analysis.py'
            )
            
            # Make script executable
            os.chmod(script_path, 0o755)
            
            # Get firmware path
            firmware_path = firmware.file.path
            
            # Create output directory
            firmware_name = os.path.splitext(os.path.basename(firmware_path))[0]
            output_dir = os.path.join(os.path.dirname(firmware_path), f"{firmware_name}_analysis")
            os.makedirs(output_dir, exist_ok=True)
            
            # Define output JSON path
            output_json = os.path.join(output_dir, "analysis_results.json")
            
            self.repository.update_status(analysis_id, "running", 10)
            
            # Run fw_binary_analysis with subprocess
            cmd = [
                sys.executable,
                script_path,
                firmware_path,
                "-o", output_json,
                "-s"  # Generate strategy
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Process output to track progress
            self.repository.update_status(analysis_id, "analyzing_file_format", 15)
            output_lines = []
            
            for line in iter(process.stdout.readline, ''):
                output_lines.append(line.rstrip())
                
                # Update progress based on output
                if "Checking file format" in line:
                    self.repository.update_status(analysis_id, "checking_file_format", 20)
                elif "Calculating hashes" in line:
                    self.repository.update_status(analysis_id, "calculating_hashes", 30)
                elif "Analyzing entropy" in line:
                    self.repository.update_status(analysis_id, "analyzing_entropy", 40)
                elif "Detecting encryption" in line:
                    self.repository.update_status(analysis_id, "detecting_encryption", 50)
                elif "Analyzing strings" in line:
                    self.repository.update_status(analysis_id, "analyzing_strings", 60)
                elif "Finding extraction points" in line:
                    self.repository.update_status(analysis_id, "finding_extraction_points", 70)
                elif "Analyzing metadata" in line:
                    self.repository.update_status(analysis_id, "analyzing_metadata", 80)
                elif "Generating byte pattern" in line:
                    self.repository.update_status(analysis_id, "generating_visualization", 90)
                elif "Analysis completed" in line:
                    self.repository.update_status(analysis_id, "completed", 95)
            
            # Wait for process to complete
            process.wait()
            
            # Check for errors
            if process.returncode != 0:
                error_output = process.stderr.read()
                logger.error(f"Analysis process failed: {error_output}")
                self.repository.update_status(analysis_id, "failed", 0)
                return
            
            # Load results from JSON file
            if os.path.exists(output_json):
                with open(output_json, 'r') as f:
                    analysis_results = json.load(f)
                
                # Load extraction strategy
                extraction_strategy = {}
                try:
                    # Generate strategy using analysis results
                    extraction_strategy = self._extract_strategy_from_results(analysis_results, output_lines)
                except Exception as e:
                    logger.error(f"Error extracting strategy: {str(e)}")
                
                # Update analysis record with results
                analysis = self.repository.find_by_id(analysis_id)
                if analysis:
                    logger.info(f"Updating analysis record {analysis_id} with results")
                    analysis.file_format = analysis_results.get('file_format', {})
                    analysis.hashes = analysis_results.get('hashes', {})
                    analysis.entropy = analysis_results.get('entropy', {})
                    analysis.encryption = analysis_results.get('encryption', {})
                    analysis.strings_analysis = analysis_results.get('strings_analysis', {})
                    analysis.extraction_points = analysis_results.get('extraction_points', {})
                    analysis.metadata = analysis_results.get('metadata', {})
                    analysis.visualization = analysis_results.get('visualization', {})
                    analysis.extraction_strategy = extraction_strategy
                    analysis.status = "completed"
                    analysis.progress = 100
                    
                    # Save updated analysis
                    result_id = self.repository.save(analysis)
                    if result_id:
                        logger.info(f"Analysis {analysis_id} completed and saved successfully")
                    else:
                        logger.error(f"Failed to save analysis results for {analysis_id}")
                else:
                    logger.error(f"Analysis record {analysis_id} not found for updating results")
            else:
                logger.error(f"Analysis output file not found: {output_json}")
                self.repository.update_status(analysis_id, "failed", 0)
        
        except Exception as e:
            logger.error(f"Error running analysis process: {str(e)}")
            self.repository.update_status(analysis_id, "failed", 0)
    
    def _extract_strategy_from_results(self, results: Dict[str, Any], output_lines: list) -> Dict[str, Any]:
        """
        Extract strategy information from analysis results and output
        
        Args:
            results: Analysis results dictionary
            output_lines: Output lines from analysis process
            
        Returns:
            Dictionary with extraction strategy
        """
        strategy = {
            'recommended_extractors': [],
            'format_flags': {},
            'special_handling': [],
            'confidence': 'unknown'
        }
        
        # Extract strategy information from output lines
        in_strategy_section = False
        for line in output_lines:
            if "EXTRACTION STRATEGY:" in line:
                in_strategy_section = True
                continue
            
            if in_strategy_section:
                if "Recommended extractors:" in line:
                    extractors = line.split("Recommended extractors:")[1].strip()
                    strategy['recommended_extractors'] = [e.strip() for e in extractors.split(",")]
                elif "Confidence:" in line:
                    strategy['confidence'] = line.split("Confidence:")[1].strip()
                elif "FORMAT FLAGS:" in line:
                    # Next lines will contain format flags
                    continue
                elif line.strip().startswith("SPECIAL HANDLING:"):
                    # Next lines will contain special handling
                    continue
                elif line.strip().startswith("-"):
                    # Special handling item
                    handling = line.strip()[2:].strip()
                    strategy['special_handling'].append(handling)
                elif "=" in line and not line.startswith("["):
                    # Format flag
                    parts = line.strip().split("=")
                    if len(parts) == 2:
                        flag = parts[0].strip()
                        value = parts[1].strip()
                        try:
                            strategy['format_flags'][flag] = int(value)
                        except ValueError:
                            strategy['format_flags'][flag] = value
                elif "No specialized format detected" in line:
                    strategy['format_flags']["DEFAULT_EXTRACTION"] = 1
                elif "Specialized format detected" in line:
                    # Already captured in format flags
                    pass
                elif line.startswith("[") or line.strip() == "":
                    # End of strategy section or empty line
                    in_strategy_section = False
        
        return strategy
    
    def get_analysis(self, analysis_id: str) -> Optional[FirmwareAnalysisModel]:
        """
        Get a firmware analysis by ID
        
        Args:
            analysis_id: MongoDB document ID
            
        Returns:
            FirmwareAnalysisModel instance if found, None otherwise
        """
        return self.repository.find_by_id(analysis_id)
    
    def get_latest_analysis_for_firmware(self, firmware_id: int) -> Optional[FirmwareAnalysisModel]:
        """
        Get the latest analysis for a firmware
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            FirmwareAnalysisModel instance if found, None otherwise
        """
        return self.repository.find_by_firmware_id(firmware_id)
    
    def list_analyses(self, limit: int = 100) -> list:
        """
        List all firmware analyses
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of FirmwareAnalysisModel instances
        """
        return self.repository.list_all(limit)
    
    def list_analyses_for_firmware(self, firmware_id: int) -> list:
        """
        List all analyses for a firmware
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            List of FirmwareAnalysisModel instances
        """
        return self.repository.list_all_by_firmware_id(firmware_id)
    
    def delete_analysis(self, analysis_id: str) -> bool:
        """
        Delete a firmware analysis
        
        Args:
            analysis_id: MongoDB document ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete the analysis
            result = self.repository.delete(analysis_id)
            
            if result:
                logger.info(f"Analysis {analysis_id} deleted successfully")
                return True
            else:
                logger.error(f"Failed to delete analysis {analysis_id}")
                return False
        except Exception as e:
            logger.error(f"Error deleting analysis: {str(e)}")
            return False 