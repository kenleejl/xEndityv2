"""
Service for firmware components analysis
"""
import os
import logging
import json
import traceback
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import glob

from django.conf import settings
from django.utils import timezone
from modules.xQuire.models import Firmware
from modules.xScout.components_analysis.artifact_identifier import ArtifactIdentifier
from modules.xScout.components_analysis.components_analysis import FirmwareAnalyzer
from modules.xScout.components_analysis.sbom import SBOMAnalyzer
from modules.xScout.components_analysis.vuln_checker import VulnerabilityChecker
from modules.xScout.services.security_analysis_service import SecurityAnalysisService

logger = logging.getLogger(__name__)

class ComponentsAnalysisService:
    """Service for analyzing firmware components"""
    
    def __init__(self):
        """Initialize the service."""
        self.security_service = SecurityAnalysisService()
    
    def get_extraction_path(self, firmware_id: int) -> str:
        """
        Get the extraction path for a firmware.
        
        Args:
            firmware_id: ID of the firmware
            
        Returns:
            Path to the extraction directory
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get the firmware file information
            fw_file = os.path.basename(firmware.file.path)
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(fw_file)[0]
            
            # Define extraction path
            extract_dir = os.path.join(fw_dir, f"{fw_name}_extract")
            
            return extract_dir
        except Firmware.DoesNotExist:
            logger.error(f"Firmware with ID {firmware_id} not found")
            raise ValueError(f"Firmware with ID {firmware_id} not found")
    
    def get_artifacts_path(self, firmware_id: int) -> str:
        """
        Get the artifacts path for a firmware.
        
        Args:
            firmware_id: ID of the firmware
            
        Returns:
            Path to the artifacts directory
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get the firmware directory
            fw_dir = os.path.dirname(firmware.file.path)
            
            # Define artifacts path
            artifacts_dir = os.path.join(fw_dir, "artifacts")
            
            return artifacts_dir
        except Firmware.DoesNotExist:
            logger.error(f"Firmware with ID {firmware_id} not found")
            raise ValueError(f"Firmware with ID {firmware_id} not found")
    
    def analyze_extracted_firmware(self, firmware_id: int) -> Dict[str, Any]:
        """
        Analyze an extracted firmware.
        
        Args:
            firmware_id: ID of the firmware to analyze
            
        Returns:
            Analysis results as a dictionary
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get extraction path
            extract_dir = self.get_extraction_path(firmware_id)
            if not os.path.exists(extract_dir):
                logger.error(f"Extraction directory not found: {extract_dir}")
                return {}
            
            # Get artifacts path
            artifacts_dir = self.get_artifacts_path(firmware_id)
            
            # Ensure the artifacts directory exists
            if not os.path.exists(artifacts_dir):
                logger.info(f"Creating artifacts directory: {artifacts_dir}")
                os.makedirs(artifacts_dir, exist_ok=True)
            
            # Ensure the rootfs directory exists in the artifacts directory
            rootfs_path = os.path.join(artifacts_dir, "rootfs")
            if not os.path.exists(rootfs_path):
                logger.info(f"Creating rootfs directory: {rootfs_path}")
                os.makedirs(rootfs_path, exist_ok=True)
            
            # Identify artifacts and copy them to a standardized location
            logger.info(f"Starting artifact identification from {extract_dir}")
            identifier = ArtifactIdentifier(extract_dir)
            logger.info("Calling identify_and_copy_all to copy artifacts")
            artifacts = identifier.identify_and_copy_all()
            
            # Log the copied artifacts
            for artifact_type, paths in artifacts.items():
                if paths:
                    if isinstance(paths, list):
                        logger.info(f"Copied {artifact_type}: {', '.join(str(p) for p in paths)}")
                    else:
                        logger.info(f"Copied {artifact_type}: {paths}")
            
            # Get the rootfs path from artifacts
            rootfs_path = os.path.join(artifacts_dir, "rootfs")
            kernel_binary = None  # We're not handling kernel binary analysis yet
            
            # Check if rootfs exists and has content
            if not os.path.exists(rootfs_path):
                logger.error(f"Rootfs not found at {rootfs_path}")
                return {
                    "artifacts": artifacts,
                    "error": "Rootfs not found. Please extract the firmware first."
                }
            
            # Check if rootfs has content
            rootfs_files = list(os.scandir(rootfs_path))
            if not rootfs_files:
                logger.error(f"Rootfs directory at {rootfs_path} is empty")
                return {
                    "artifacts": artifacts,
                    "error": "Rootfs directory is empty. Please extract the firmware again."
                }
            
            logger.info(f"Using rootfs_path: {rootfs_path} with {len(rootfs_files)} files/directories")
            if kernel_binary:
                logger.info(f"Using kernel_binary: {kernel_binary}")
            
            # Create firmware analyzer and run analysis
            logger.info("Creating FirmwareAnalyzer and starting analysis")
            analyzer = FirmwareAnalyzer(rootfs_path)  # Initialize with the rootfs path
            analysis_results = analyzer.analyze_all(
                kernel_binary=kernel_binary,
                rootfs_path=rootfs_path  # Pass the rootfs path explicitly
            )
            
            # Add artifact information to results
            analysis_results["artifacts"] = {
                "rootfs": identifier.found_artifacts.get("rootfs", []),
                "kernel": identifier.found_artifacts.get("kernel", []),
                "dtb": identifier.found_artifacts.get("dtb", []),
                "initramfs": identifier.found_artifacts.get("initramfs", []),
                "bootloader": identifier.found_artifacts.get("bootloader", []),
                "standardized_paths": artifacts  # This is already a clean dict
            }
            
            # Save analysis results to a file
            self._save_analysis_results(firmware, analysis_results)
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error analyzing extracted firmware: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {}
    
    def generate_sbom(self, firmware_id: int) -> Dict[str, Any]:
        """
        Generate SBOM (Software Bill of Materials) for extracted firmware
        
        Args:
            firmware_id: ID of the firmware
            
        Returns:
            SBOM analysis results
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get artifacts path
            artifacts_dir = self.get_artifacts_path(firmware_id)
            rootfs_path = os.path.join(artifacts_dir, "rootfs")
            
            # Check if rootfs exists
            if not os.path.exists(rootfs_path):
                error_msg = f"Rootfs not found at {rootfs_path}. Please extract and analyze the firmware first."
                logger.error(error_msg)
                return {"error": error_msg, "success": False}
            
            # Create SBOM analyzer
            logger.info(f"Starting SBOM generation for firmware {firmware_id}")
            sbom_analyzer = SBOMAnalyzer(rootfs_path, artifacts_dir)
            
            # Run SBOM analysis
            sbom_results = sbom_analyzer.analyze()
            
            # Save SBOM results to analysis file
            if sbom_results.get("success"):
                self._save_sbom_results(firmware, sbom_results)
            
            return sbom_results
            
        except Firmware.DoesNotExist:
            error_msg = f"Firmware with ID {firmware_id} not found"
            logger.error(error_msg)
            return {"error": error_msg, "success": False}
        except Exception as e:
            error_msg = f"Error generating SBOM: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {"error": error_msg, "success": False}
    
    def check_vulnerabilities(self, firmware_id: int) -> Dict[str, Any]:
        """
        Check vulnerabilities in extracted firmware using Grype
        
        Args:
            firmware_id: ID of the firmware
            
        Returns:
            Vulnerability analysis results
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get artifacts path
            artifacts_dir = self.get_artifacts_path(firmware_id)
            rootfs_path = os.path.join(artifacts_dir, "rootfs")
            sbom_file_path = os.path.join(artifacts_dir, "sbom.json")
            
            # Check if rootfs exists
            if not os.path.exists(rootfs_path):
                error_msg = f"Rootfs not found at {rootfs_path}. Please extract and analyze the firmware first."
                logger.error(error_msg)
                return {"error": error_msg, "success": False}
            
            # Check if SBOM exists
            if not os.path.exists(sbom_file_path):
                error_msg = f"SBOM file not found at {sbom_file_path}. Please generate SBOM first."
                logger.error(error_msg)
                return {"error": error_msg, "success": False}
            
            # Create vulnerability checker
            logger.info(f"Starting vulnerability analysis for firmware {firmware_id}")
            vuln_checker = VulnerabilityChecker(rootfs_path, artifacts_dir, sbom_file_path)
            
            # Run vulnerability analysis
            vuln_results = vuln_checker.analyze()
            
            # Save vulnerability results to analysis file
            if vuln_results.get("success"):
                self._save_vulnerability_results(firmware, vuln_results)
            
            return vuln_results
            
        except Firmware.DoesNotExist:
            error_msg = f"Firmware with ID {firmware_id} not found"
            logger.error(error_msg)
            return {"error": error_msg, "success": False}
        except Exception as e:
            error_msg = f"Error checking vulnerabilities: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {"error": error_msg, "success": False}
    
    def run_full_security_analysis(self, firmware_id: int) -> Dict[str, Any]:
        """
        Run full security analysis including SBOM generation and vulnerability checking
        
        Args:
            firmware_id: ID of the firmware
            
        Returns:
            Combined analysis results
        """
        try:
            logger.info(f"Starting full security analysis for firmware {firmware_id}")
            
            # First, generate SBOM
            logger.info("Step 1: Generating SBOM...")
            sbom_results = self.generate_sbom(firmware_id)
            
            if not sbom_results.get("success"):
                return {
                    "success": False,
                    "error": f"SBOM generation failed: {sbom_results.get('error', 'Unknown error')}",
                    "sbom_results": sbom_results
                }
            
            # Then, check vulnerabilities
            logger.info("Step 2: Checking vulnerabilities...")
            vuln_results = self.check_vulnerabilities(firmware_id)
            
            # Combine results
            combined_results = {
                "success": True,
                "sbom_results": sbom_results,
                "vulnerability_results": vuln_results,
                "analysis_complete": vuln_results.get("success", False)
            }
            
            # Save combined results
            firmware = Firmware.objects.get(pk=firmware_id)
            self._save_security_analysis_results(firmware, combined_results)
            
            # Store security analysis in MongoDB
            if vuln_results.get("success"):
                logger.info("Storing security analysis in MongoDB...")
                try:
                    doc_id = self.security_service.process_and_store_security_data(firmware_id)
                    if doc_id:
                        combined_results["mongodb_doc_id"] = doc_id
                        logger.info(f"Security analysis stored in MongoDB with ID: {doc_id}")
                    else:
                        logger.warning("Failed to store security analysis in MongoDB")
                except Exception as e:
                    logger.error(f"Error storing security analysis in MongoDB: {str(e)}")
            
            return combined_results
            
        except Exception as e:
            error_msg = f"Error running full security analysis: {str(e)}"
            logger.error(error_msg)
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {"error": error_msg, "success": False}
    
    def _save_analysis_results(self, firmware: Firmware, results: Dict[str, Any]) -> None:
        """
        Save analysis results to a file.
        
        Args:
            firmware: Firmware object
            results: Analysis results
        """
        try:
            # Get the firmware directory
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(os.path.basename(firmware.file.path))[0]
            
            # Create the analysis directory if it doesn't exist
            analysis_dir = os.path.join(fw_dir, f"{fw_name}_components_analysis")
            os.makedirs(analysis_dir, exist_ok=True)
            
            # Save the results to a JSON file
            timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(analysis_dir, f"components_analysis_{timestamp}.json")
            
            # Create a simplified copy that's serializable
            serializable_results = {}
            
            # Copy top-level items
            for key, value in results.items():
                if key == "artifacts":
                    # Handle artifacts specially to avoid circular references
                    serializable_results[key] = {
                        "rootfs": [str(p) for p in value.get("rootfs", [])],
                        "kernel": [str(p) for p in value.get("kernel", [])],
                        "dtb": [str(p) for p in value.get("dtb", [])],
                        "initramfs": [str(p) for p in value.get("initramfs", [])],
                        "bootloader": [str(p) for p in value.get("bootloader", [])],
                        "standardized_paths": {k: str(v) for k, v in value.get("standardized_paths", {}).items()}
                    }
                elif isinstance(value, dict):
                    # For other dictionaries, convert any Path objects to strings
                    serializable_results[key] = {}
                    for k, v in value.items():
                        if isinstance(v, (Path, type)):
                            serializable_results[key][k] = str(v)
                        else:
                            serializable_results[key][k] = v
                elif isinstance(value, list):
                    # For lists, convert any Path objects to strings
                    serializable_results[key] = []
                    for item in value:
                        if isinstance(item, (Path, type)):
                            serializable_results[key].append(str(item))
                        else:
                            serializable_results[key].append(item)
                elif isinstance(value, (Path, type)):
                    # Convert Path objects to strings
                    serializable_results[key] = str(value)
                else:
                    # Keep other values as is
                    serializable_results[key] = value
            
            with open(results_file, 'w') as f:
                json.dump(serializable_results, f, indent=4)
                
            logger.info(f"Saved analysis results to {results_file}")
        except Exception as e:
            logger.error(f"Error saving analysis results: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _save_sbom_results(self, firmware: Firmware, results: Dict[str, Any]) -> None:
        """
        Save SBOM results to a file.
        
        Args:
            firmware: Firmware object
            results: SBOM results
        """
        try:
            # Get the firmware directory
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(os.path.basename(firmware.file.path))[0]
            
            # Create the analysis directory if it doesn't exist
            analysis_dir = os.path.join(fw_dir, f"{fw_name}_components_analysis")
            os.makedirs(analysis_dir, exist_ok=True)
            
            # Save the SBOM results to a JSON file
            timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(analysis_dir, f"sbom_analysis_{timestamp}.json")
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
                
            logger.info(f"Saved SBOM results to {results_file}")
        except Exception as e:
            logger.error(f"Error saving SBOM results: {e}")
    
    def _save_vulnerability_results(self, firmware: Firmware, results: Dict[str, Any]) -> None:
        """
        Save vulnerability results to a file.
        
        Args:
            firmware: Firmware object
            results: Vulnerability results
        """
        try:
            # Get the firmware directory
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(os.path.basename(firmware.file.path))[0]
            
            # Create the analysis directory if it doesn't exist
            analysis_dir = os.path.join(fw_dir, f"{fw_name}_components_analysis")
            os.makedirs(analysis_dir, exist_ok=True)
            
            # Save the vulnerability results to a JSON file
            timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(analysis_dir, f"vulnerability_analysis_{timestamp}.json")
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
                
            logger.info(f"Saved vulnerability results to {results_file}")
        except Exception as e:
            logger.error(f"Error saving vulnerability results: {e}")
    
    def _save_security_analysis_results(self, firmware: Firmware, results: Dict[str, Any]) -> None:
        """
        Save combined security analysis results to a file.
        
        Args:
            firmware: Firmware object
            results: Combined security analysis results
        """
        try:
            # Get the firmware directory
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(os.path.basename(firmware.file.path))[0]
            
            # Create the analysis directory if it doesn't exist
            analysis_dir = os.path.join(fw_dir, f"{fw_name}_components_analysis")
            os.makedirs(analysis_dir, exist_ok=True)
            
            # Save the combined results to a JSON file
            timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
            results_file = os.path.join(analysis_dir, f"security_analysis_{timestamp}.json")
            
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
                
            logger.info(f"Saved security analysis results to {results_file}")
        except Exception as e:
            logger.error(f"Error saving security analysis results: {e}")
    
    def get_analysis_results(self, firmware_id: int) -> Optional[Dict[str, Any]]:
        """
        Get previously saved analysis results for a firmware.
        
        Args:
            firmware_id: ID of the firmware
            
        Returns:
            Analysis results dictionary or None if not found
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get the firmware directory
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(os.path.basename(firmware.file.path))[0]
            
            # Define analysis directory
            analysis_dir = os.path.join(fw_dir, f"{fw_name}_components_analysis")
            
            # Look for the most recent analysis results file
            if os.path.exists(analysis_dir):
                result_files = glob.glob(os.path.join(analysis_dir, "components_analysis_*.json"))
                
                if result_files:
                    # Sort by modification time (newest first)
                    result_files.sort(key=os.path.getmtime, reverse=True)
                    latest_file = result_files[0]
                    
                    # Load and return the results
                    with open(latest_file, 'r') as f:
                        return json.load(f)
            
            return None
        except Firmware.DoesNotExist:
            logger.error(f"Firmware with ID {firmware_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error getting analysis results: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
    
    def get_security_analysis_results(self, firmware_id: int) -> Optional[Dict[str, Any]]:
        """
        Get previously saved security analysis results for a firmware.
        
        Args:
            firmware_id: ID of the firmware
            
        Returns:
            Security analysis results dictionary or None if not found
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get the firmware directory
            fw_dir = os.path.dirname(firmware.file.path)
            fw_name = os.path.splitext(os.path.basename(firmware.file.path))[0]
            
            # Define analysis directory
            analysis_dir = os.path.join(fw_dir, f"{fw_name}_components_analysis")
            
            # Look for the most recent security analysis results file
            if os.path.exists(analysis_dir):
                result_files = glob.glob(os.path.join(analysis_dir, "security_analysis_*.json"))
                
                if result_files:
                    # Sort by modification time (newest first)
                    result_files.sort(key=os.path.getmtime, reverse=True)
                    latest_file = result_files[0]
                    
                    # Load and return the results
                    with open(latest_file, 'r') as f:
                        return json.load(f)
            
            return None
        except Firmware.DoesNotExist:
            logger.error(f"Firmware with ID {firmware_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error getting security analysis results: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
    
    def get_all_firmwares(self) -> List[Firmware]:
        """
        Get all firmwares.
        
        Returns:
            List of Firmware objects
        """
        return Firmware.objects.all() 