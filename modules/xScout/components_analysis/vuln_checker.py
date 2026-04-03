"""
Vulnerability checker using Grype
"""
from django.conf import settings
import json
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from modules.xScout.components_analysis.components_analysis import BaseAnalyzer
from modules.base.utils.docker_utils import DockerUtils

logger = logging.getLogger(__name__)

class VulnerabilityChecker(BaseAnalyzer):
    """Vulnerability checker using Grype to analyze SBOM files"""
    
    def __init__(self, rootfs_path: str, artifacts_dir: str, sbom_file_path: Optional[str] = None):
        """
        Initialize vulnerability checker
        
        Args:
            rootfs_path: Path to the extracted rootfs
            artifacts_dir: Path to the artifacts directory
            sbom_file_path: Optional path to existing SBOM file, defaults to artifacts_dir/sbom.json
        """
        super().__init__(rootfs_path)
        self.rootfs_path = Path(rootfs_path)
        self.artifacts_dir = Path(artifacts_dir)
        
        # Set SBOM file path
        if sbom_file_path:
            self.sbom_file_path = Path(sbom_file_path)
        else:
            self.sbom_file_path = self.artifacts_dir / "sbom.json"
        
        # Output paths for vulnerability reports
        self.vuln_output_path = self.artifacts_dir / "vulnerabilities.json"
        self.vuln_summary_path = self.artifacts_dir / "vulnerability_summary.json"
        
        # Ensure artifacts directory exists
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using Grype
        
        Returns:
            Dictionary containing vulnerability analysis results
        """
        logger.info(f"Starting vulnerability analysis for rootfs: {self.rootfs_path}")
        
        try:
            # Check if SBOM file exists
            if not self.sbom_file_path.exists():
                error_msg = f"SBOM file not found: {self.sbom_file_path}. Please generate SBOM first."
                logger.error(error_msg)
                return {"error": error_msg, "success": False}
            
            # Run vulnerability analysis using Grype
            vuln_data = self._run_grype_analysis()
            
            if vuln_data:
                # Save vulnerability data to file
                self._save_vulnerability_data(vuln_data)
                
                # Generate summary
                summary = self._generate_vulnerability_summary(vuln_data)
                
                # Save summary to file
                self._save_vulnerability_summary(summary)
                
                return {
                    "success": True,
                    "vulnerability_file": str(self.vuln_output_path),
                    "summary_file": str(self.vuln_summary_path),
                    "summary": summary
                }
            else:
                return {"error": "Failed to run vulnerability analysis", "success": False}
                
        except Exception as e:
            error_msg = f"Error during vulnerability analysis: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg, "success": False}
    
    def _run_grype_analysis(self) -> Optional[Dict[str, Any]]:
        """
        Run Grype vulnerability analysis on the SBOM file
        
        Returns:
            Vulnerability data as dictionary or None if failed
        """
        try:
            # Check if Docker is available
            if not DockerUtils.is_docker_available():
                logger.warning("Docker not available, cannot run Grype")
                return None
            
            # Get current user info for proper file permissions
            user_id, group_id = DockerUtils.get_current_user_info()
            
            # Create a cache directory for Grype in the artifacts directory
            grype_cache_dir = settings.BASE_DIR / ".grype_cache"
            grype_cache_dir.mkdir(exist_ok=True)
            
            # Set proper permissions on cache directory
            import os
            import stat
            try:
                # Make sure the cache directory is writable
                os.chmod(grype_cache_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                
                # Also create the grype subdirectory structure if it doesn't exist
                grype_db_dir = grype_cache_dir / "grype"
                grype_db_dir.mkdir(exist_ok=True)
                os.chmod(grype_db_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                
            except Exception as e:
                logger.warning(f"Could not set permissions on cache directory: {e}")
            
            logger.info(f"Created Grype cache directory: {grype_cache_dir}")
            
            # Prepare Docker volumes
            # Mount the artifacts directory as read-write so Grype can read SBOM and write results
            volumes = {
                str(self.artifacts_dir): {
                    'bind': '/workspace',
                    'mode': 'rw'
                }
            }
            
            # Try to mount cache directory if permissions allow
            try:
                # Test if we can write to the cache directory
                test_file = grype_cache_dir / "test_write"
                test_file.write_text("test")
                test_file.unlink()
                
                # If successful, add cache volume
                volumes[str(grype_cache_dir)] = {
                    'bind': '/.cache',
                    'mode': 'rw'
                }
                logger.info(f"Using cache directory: {grype_cache_dir}")
            except Exception as e:
                logger.warning(f"Cannot use cache directory due to permissions: {e}, running without cache")
            
            # Grype command to analyze the SBOM file and output JSON
            # Use the SBOM file as input and output vulnerabilities to JSON
            command = [
                'sbom:/workspace/sbom.json',
                '--output', 'json=/workspace/vulnerabilities.json'
            ]
            
            logger.info(f" Running Grype with command:{' '.join(command)}")
            logger.info(f"Analyzing SBOM file: {self.sbom_file_path}")
            logger.info(f"Output will be saved to: {self.vuln_output_path}")
            
            # Run Grype container
            success, result, error_msg = DockerUtils.run_container(
                image="anchore/grype:latest",
                command=command,
                volumes=volumes,
                # user=f"{user_id}:{group_id}",
                remove=True,
                detach=False  # Wait for completion
            )
            
            if success:
                logger.info("Grype vulnerability analysis completed successfully")
                
                # Check if vulnerability file was created
                if self.vuln_output_path.exists() and self.vuln_output_path.stat().st_size > 0:
                    try:
                        # Load and return the vulnerability data
                        with open(self.vuln_output_path, 'r') as f:
                            content = f.read().strip()
                            if content:
                                vuln_data = json.loads(content)
                                logger.info(f"Vulnerability file created successfully: {self.vuln_output_path}")
                                return vuln_data
                            else:
                                logger.error(f"Vulnerability file is empty: {self.vuln_output_path}")
                                return None
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in vulnerability file: {e}")
                        # Try to create empty valid structure
                        empty_structure = {
                            "matches": [],
                            "source": {"type": "image", "target": "sbom"},
                            "distro": {},
                            "descriptor": {"name": "grype", "version": "unknown"}
                        }
                        return empty_structure
                    except Exception as e:
                        logger.error(f"Error reading vulnerability file: {e}")
                        return None
                else:
                    logger.error(f"Vulnerability file was not created or is empty: {self.vuln_output_path}")
                    # Return empty structure so analysis can continue
                    return {
                        "matches": [],
                        "source": {"type": "image", "target": "sbom"},
                        "distro": {},
                        "descriptor": {"name": "grype", "version": "unknown"}
                    }
            else:
                logger.error(f"Grype analysis failed: {error_msg}")
                # For permission errors, return empty structure to continue
                if "permission denied" in error_msg.lower():
                    logger.warning("Permission denied error detected, returning empty vulnerability structure")
                    return {
                        "matches": [],
                        "source": {"type": "image", "target": "sbom"},
                        "distro": {},
                        "descriptor": {"name": "grype", "version": "unknown", "error": "permission_denied"}
                    }
                return None
                
        except Exception as e:
            logger.error(f"Error running Grype analysis: {str(e)}")
            return None
    
    def _save_vulnerability_data(self, vuln_data: Dict[str, Any]) -> None:
        """
        Save vulnerability data to JSON file (backup in case Docker didn't save it properly)
        
        Args:
            vuln_data: Vulnerability data dictionary
        """
        try:
            # Ensure the file exists and is properly formatted
            with open(self.vuln_output_path, 'w') as f:
                json.dump(vuln_data, f, indent=2)
            
            logger.info(f"Vulnerability data saved to: {self.vuln_output_path}")
        except Exception as e:
            logger.error(f"Error saving vulnerability data to file: {str(e)}")
    
    def _generate_vulnerability_summary(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of vulnerability findings
        
        Args:
            vuln_data: Vulnerability data dictionary
            
        Returns:
            Summary dictionary
        """
        try:
            summary = {
                "total_vulnerabilities": 0,
                "severity_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "negligible": 0,
                    "unknown": 0
                },
                "top_vulnerabilities": [],
                "affected_packages": {},
                "vulnerability_types": {},
                "scan_info": {}
            }
            
            # Extract matches (vulnerabilities)
            matches = vuln_data.get("matches", [])
            summary["total_vulnerabilities"] = len(matches)
            
            # Process each vulnerability
            for match in matches:
                vulnerability = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                
                # Count by severity
                severity = vulnerability.get("severity", "unknown").lower()
                if severity in summary["severity_counts"]:
                    summary["severity_counts"][severity] += 1
                else:
                    summary["severity_counts"]["unknown"] += 1
                
                # Track affected packages
                package_name = artifact.get("name", "unknown")
                package_version = artifact.get("version", "unknown")
                package_key = f"{package_name}@{package_version}"
                
                if package_key not in summary["affected_packages"]:
                    summary["affected_packages"][package_key] = {
                        "name": package_name,
                        "version": package_version,
                        "type": artifact.get("type", "unknown"),
                        "vulnerabilities": []
                    }
                
                # Add vulnerability to package
                vuln_info = {
                    "id": vulnerability.get("id", ""),
                    "severity": severity,
                    "description": vulnerability.get("description", ""),
                    "cvss_score": self._extract_cvss_score(vulnerability)
                }
                summary["affected_packages"][package_key]["vulnerabilities"].append(vuln_info)
                
                # Track vulnerability types
                vuln_id = vulnerability.get("id", "unknown")
                if vuln_id.startswith("CVE-"):
                    vuln_type = "CVE"
                elif vuln_id.startswith("GHSA-"):
                    vuln_type = "GitHub Security Advisory"
                else:
                    vuln_type = "Other"
                
                summary["vulnerability_types"][vuln_type] = summary["vulnerability_types"].get(vuln_type, 0) + 1
                
                # Add to top vulnerabilities (critical and high severity)
                if severity in ["critical", "high"] and len(summary["top_vulnerabilities"]) < 10:
                    summary["top_vulnerabilities"].append({
                        "id": vulnerability.get("id", ""),
                        "severity": severity,
                        "package": package_key,
                        "description": vulnerability.get("description", "")[:200] + "..." if len(vulnerability.get("description", "")) > 200 else vulnerability.get("description", ""),
                        "cvss_score": self._extract_cvss_score(vulnerability)
                    })
            
            # Sort top vulnerabilities by severity and CVSS score
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "unknown": 0}
            summary["top_vulnerabilities"].sort(
                key=lambda x: (severity_order.get(x["severity"], 0), x.get("cvss_score", 0)),
                reverse=True
            )
            
            # Extract scan information
            descriptor = vuln_data.get("descriptor", {})
            summary["scan_info"] = {
                "scanner_name": descriptor.get("name", "grype"),
                "scanner_version": descriptor.get("version", "unknown"),
                "scan_timestamp": descriptor.get("timestamp", ""),
                "database_built": vuln_data.get("distro", {}).get("prettyName", ""),
                "total_packages_scanned": len(set(match.get("artifact", {}).get("name", "") for match in matches))
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating vulnerability summary: {str(e)}")
            return {"error": f"Failed to generate summary: {str(e)}"}
    
    def _extract_cvss_score(self, vulnerability: Dict[str, Any]) -> float:
        """
        Extract CVSS score from vulnerability data
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            CVSS score as float, 0.0 if not found
        """
        try:
            # Try to get CVSS score from various possible locations
            cvss_data = vulnerability.get("cvss", [])
            if cvss_data and isinstance(cvss_data, list) and len(cvss_data) > 0:
                # Get the first CVSS score
                cvss_entry = cvss_data[0]
                if isinstance(cvss_entry, dict):
                    metrics = cvss_entry.get("metrics", {})
                    if isinstance(metrics, dict):
                        return float(metrics.get("baseScore", 0.0))
            
            # Alternative location for CVSS score
            if "cvss" in vulnerability and isinstance(vulnerability["cvss"], dict):
                return float(vulnerability["cvss"].get("baseScore", 0.0))
            
            return 0.0
        except (ValueError, TypeError, KeyError):
            return 0.0
    
    def _save_vulnerability_summary(self, summary: Dict[str, Any]) -> None:
        """
        Save vulnerability summary to JSON file
        
        Args:
            summary: Summary data dictionary
        """
        try:
            with open(self.vuln_summary_path, 'w') as f:
                json.dump(summary, f, indent=2)
            
            logger.info(f"Vulnerability summary saved to: {self.vuln_summary_path}")
        except Exception as e:
            logger.error(f"Error saving vulnerability summary: {str(e)}")
    
    def get_vulnerability_file_path(self) -> str:
        """
        Get the path to the generated vulnerability file
        
        Returns:
            Path to vulnerability JSON file
        """
        return str(self.vuln_output_path)
    
    def get_summary_file_path(self) -> str:
        """
        Get the path to the generated summary file
        
        Returns:
            Path to summary JSON file
        """
        return str(self.vuln_summary_path)
    
    def load_existing_vulnerabilities(self) -> Optional[Dict[str, Any]]:
        """
        Load existing vulnerability file if it exists
        
        Returns:
            Vulnerability data dictionary or None if file doesn't exist
        """
        try:
            if self.vuln_output_path.exists():
                with open(self.vuln_output_path, 'r') as f:
                    return json.load(f)
            return None
        except Exception as e:
            logger.error(f"Error loading existing vulnerabilities: {str(e)}")
            return None
    
    def load_existing_summary(self) -> Optional[Dict[str, Any]]:
        """
        Load existing vulnerability summary if it exists
        
        Returns:
            Summary data dictionary or None if file doesn't exist
        """
        try:
            if self.vuln_summary_path.exists():
                with open(self.vuln_summary_path, 'r') as f:
                    return json.load(f)
            return None
        except Exception as e:
            logger.error(f"Error loading existing summary: {str(e)}")
            return None
