"""
SBOM (Software Bill of Materials) analyzer using Syft
"""
from django.conf import settings
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from collections import defaultdict

from modules.xScout.components_analysis.components_analysis import BaseAnalyzer
from modules.base.utils.docker_utils import DockerUtils

logger = logging.getLogger(__name__)

class SBOMAnalyzer(BaseAnalyzer):
    """Analyzer for generating Software Bill of Materials using Syft"""
    
    def __init__(self, rootfs_path: str, artifacts_dir: str):
        """
        Initialize SBOM analyzer
        
        Args:
            rootfs_path: Path to the extracted rootfs
            artifacts_dir: Path to the artifacts directory where SBOM will be saved
        """
        super().__init__(rootfs_path)
        self.rootfs_path = Path(rootfs_path)
        self.artifacts_dir = Path(artifacts_dir)
        self.sbom_output_path = self.artifacts_dir / "sbom.json"
        
        # Ensure artifacts directory exists
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze the firmware rootfs and generate SBOM
        
        Returns:
            Dictionary containing SBOM analysis results
        """
        logger.info(f"Starting SBOM analysis for rootfs: {self.rootfs_path}")
        
        try:
            # Check if rootfs exists and is accessible
            if not self.rootfs_path.exists():
                error_msg = f"Rootfs path does not exist: {self.rootfs_path}"
                logger.error(error_msg)
                return {"error": error_msg, "success": False}
            
            # Generate SBOM using Syft
            sbom_data = self._generate_sbom()
            
            if sbom_data:
                # Save SBOM to artifacts directory
                self._save_sbom_to_file(sbom_data)
                
                # Extract summary information
                summary = self._extract_sbom_summary(sbom_data)
                
                return {
                    "success": True,
                    "sbom_file": str(self.sbom_output_path),
                    "summary": summary,
                    "total_packages": len(sbom_data.get("artifacts", [])) if isinstance(sbom_data, dict) else 0
                }
            else:
                return {"error": "Failed to generate SBOM", "success": False}
                
        except Exception as e:
            error_msg = f"Error during SBOM analysis: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg, "success": False}
    
    def _generate_sbom(self) -> Optional[Dict[str, Any]]:
        """
        Generate SBOM using Syft Docker container
        
        Returns:
            SBOM data as dictionary or None if failed
        """
        try:
            # Check if Docker is available
            if not DockerUtils.is_docker_available():
                logger.warning("Docker not available, cannot run Syft")
                return None
            
            # Get current user info for proper file permissions
            user_id, group_id = DockerUtils.get_current_user_info()
            
            # Create a cache directory for Grype in the artifacts directory
            syft_cache_dir = settings.BASE_DIR / ".syft_cache"
            syft_cache_dir.mkdir(exist_ok=True)
            logger.info(f"Created Grype cache directory: {syft_cache_dir}")
            

            # Prepare Docker volumes
            # Mount the rootfs as read-only and artifacts directory as read-write
            volumes = {
                str(self.rootfs_path): {
                    'bind': '/rootfs',
                    'mode': 'ro'
                },
                str(self.artifacts_dir): {
                    'bind': '/output',
                    'mode': 'rw'
                },
                str(syft_cache_dir): {
                    'bind': '/.cache',
                    'mode': 'rw'
                }
            }
            
            # Syft command to analyze the rootfs directory and output JSON
            command = [
                'dir:/rootfs',
                '--output', 'spdx-json=/output/sbom.json'
            ]
            
            logger.info(f"Running Syft with command: {' '.join(command)}")
            logger.info(f"Analyzing directory: {self.rootfs_path}")
            logger.info(f"Output will be saved to: {self.sbom_output_path}")
            
            # Run Syft container
            success, result, error_msg = DockerUtils.run_container(
                image="anchore/syft:latest",
                command=command,
                volumes=volumes,
                user=f"{user_id}:{group_id}",
                remove=True,
                detach=False  # Wait for completion
            )
            
            if success:
                logger.info("Syft analysis completed successfully")
                
                # Check if SBOM file was created
                if self.sbom_output_path.exists():
                    # Load and return the SBOM data
                    with open(self.sbom_output_path, 'r') as f:
                        sbom_data = json.load(f)
                    
                    logger.info(f"SBOM file created successfully: {self.sbom_output_path}")
                    return sbom_data
                else:
                    logger.error(f"SBOM file was not created: {self.sbom_output_path}")
                    return None
            else:
                logger.error(f"Syft analysis failed: {error_msg}")
                return None
                
        except Exception as e:
            logger.error(f"Error running Syft analysis: {str(e)}")
            return None
    
    def _save_sbom_to_file(self, sbom_data: Dict[str, Any]) -> None:
        """
        Save SBOM data to JSON file (backup in case Docker didn't save it properly)
        
        Args:
            sbom_data: SBOM data dictionary
        """
        try:
            # Ensure the file exists and is properly formatted
            with open(self.sbom_output_path, 'w') as f:
                json.dump(sbom_data, f, indent=2)
            
            logger.info(f"SBOM data saved to: {self.sbom_output_path}")
        except Exception as e:
            logger.error(f"Error saving SBOM to file: {str(e)}")
    
    def _parse_package_type_from_spdxid(self, spdxid: str) -> str:
        """
        Parse package type from SPDXID
        
        Args:
            spdxid: SPDXID string (e.g., "SPDXRef-Package-binary-name-hash")
            
        Returns:
            Package type (e.g., "binary", "linux-kernel-module", etc.)
        """
        try:
            # SPDXID format: SPDXRef-Package-{type}-{name}-{hash}
            # Note: kernel modules are "SPDXRef-Package-linux-kernel-module-*"
            parts = spdxid.split("-")
            if len(parts) >= 4 and parts[0] == "SPDXRef" and parts[1] == "Package":
                # Handle multi-word types like "linux-kernel-module"
                if parts[2] == "linux" and len(parts) >= 5 and parts[3] == "kernel" and parts[4] == "module":
                    return "linux-kernel-module"
                return parts[2]
            return "unknown"
        except Exception:
            return "unknown"
    
    def _is_kernel_module(self, pkg_type: str, source_info: str, locations: list = None) -> bool:
        """
        Determine if a package is a kernel module
        
        Args:
            pkg_type: Package type from SPDXID
            source_info: Source information string
            locations: List of file locations
            
        Returns:
            True if package is a kernel module
        """
        # Check if already identified as kernel module
        if pkg_type == "linux-kernel-module":
            return True
        
        # Check if type is "linux" and has .ko files
        if pkg_type == "linux":
            # Check sourceInfo for .ko files
            if source_info and ".ko" in source_info:
                return True
            # Check locations for .ko files
            if locations:
                for loc in locations:
                    if loc.endswith(".ko"):
                        return True
        
        return False
    
    def _extract_purl_info(self, external_refs: list) -> Dict[str, str]:
        """
        Extract PURL information from externalRefs
        
        Args:
            external_refs: List of external references
            
        Returns:
            Dictionary with PURL information
        """
        purl_info = {
            "has_purl": False,
            "purl": None,
            "purl_type": None,
            "purl_namespace": None,
            "purl_name": None,
            "purl_version": None
        }
        
        try:
            for ref in external_refs:
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator", "")
                    purl_info["has_purl"] = True
                    purl_info["purl"] = purl
                    
                    # Parse PURL: pkg:{type}/{namespace}/{name}@{version}
                    # or pkg:{type}/{name}@{version}
                    if purl.startswith("pkg:"):
                        purl_clean = purl[4:]  # Remove "pkg:"
                        
                        # Extract type
                        if "/" in purl_clean:
                            purl_type, rest = purl_clean.split("/", 1)
                            purl_info["purl_type"] = purl_type
                            
                            # Extract version if present
                            if "@" in rest:
                                name_part, version = rest.rsplit("@", 1)
                                purl_info["purl_version"] = version
                            else:
                                name_part = rest
                            
                            # Check for namespace
                            if "/" in name_part:
                                namespace, name = name_part.rsplit("/", 1)
                                purl_info["purl_namespace"] = namespace
                                purl_info["purl_name"] = name
                            else:
                                purl_info["purl_name"] = name_part
                    
                    break
        except Exception as e:
            logger.debug(f"Error parsing PURL: {str(e)}")
        
        return purl_info
    
    def _extract_locations_from_sourceinfo(self, source_info: str) -> list:
        """
        Extract file locations from sourceInfo string
        
        Args:
            source_info: Source information string
            
        Returns:
            List of file paths
        """
        locations = []
        try:
            # sourceInfo typically contains paths after "paths:" or "files:"
            if not source_info:
                return locations
            
            # Look for common patterns in sourceInfo
            import re
            # Pattern: /path/to/file.ext
            path_pattern = r'(/[\w\-./]+\.\w+)'
            matches = re.findall(path_pattern, source_info)
            locations.extend(matches)
            
        except Exception as e:
            logger.debug(f"Error extracting locations from sourceInfo: {str(e)}")
        
        return locations
    
    def _extract_sbom_summary(self, sbom_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract enhanced summary information from SBOM data (SPDX format)
        
        Args:
            sbom_data: SBOM data dictionary in SPDX 2.3 format
            
        Returns:
            Enhanced summary dictionary with package details
        """
        try:
            summary = {
                "total_packages": 0,
                "package_types": {},
                "suppliers": {},
                "purl_types": {},
                "versioned_packages": 0,
                "unversioned_packages": 0,
                "binary_count": 0,
                "kernel_module_count": 0,
                "has_purl_count": 0,
                "top_suppliers": [],
                "location_samples": [],
                "license_info": {}
            }
            
            # Extract packages from SPDX format
            packages = sbom_data.get("packages", [])
            summary["total_packages"] = len(packages)
            
            # Track suppliers for top suppliers list
            supplier_counts = defaultdict(int)
            
            # Analyze each package
            for package in packages:
                # Extract package type from SPDXID
                spdxid = package.get("SPDXID", "")
                pkg_type = self._parse_package_type_from_spdxid(spdxid)
                
                # Check if this is a kernel module (by type or .ko files)
                source_info = package.get("sourceInfo", "")
                is_kernel_module = self._is_kernel_module(pkg_type, source_info)
                
                # Use the more specific type for counting
                if is_kernel_module:
                    effective_type = "linux-kernel-module"
                    summary["kernel_module_count"] += 1
                else:
                    effective_type = pkg_type
                    if pkg_type == "binary":
                        summary["binary_count"] += 1
                
                summary["package_types"][effective_type] = summary["package_types"].get(effective_type, 0) + 1
                
                # Extract supplier information
                supplier = package.get("supplier", "NOASSERTION")
                if supplier and supplier != "NOASSERTION":
                    # Clean up supplier format (e.g., "Organization: Axis Communications")
                    supplier_clean = supplier.replace("Organization: ", "").replace("Person: ", "")
                    if supplier_clean:
                        summary["suppliers"][supplier_clean] = summary["suppliers"].get(supplier_clean, 0) + 1
                        supplier_counts[supplier_clean] += 1
                
                # Check version information
                version = package.get("versionInfo", "")
                if version and version not in ["UNKNOWN", "NOASSERTION", ""]:
                    summary["versioned_packages"] += 1
                else:
                    summary["unversioned_packages"] += 1
                
                # Extract PURL information
                external_refs = package.get("externalRefs", [])
                purl_info = self._extract_purl_info(external_refs)
                if purl_info["has_purl"]:
                    summary["has_purl_count"] += 1
                    purl_type = purl_info["purl_type"]
                    if purl_type:
                        summary["purl_types"][purl_type] = summary["purl_types"].get(purl_type, 0) + 1
                
                # Extract location samples (limit to avoid huge summaries)
                if len(summary["location_samples"]) < 20:
                    source_info = package.get("sourceInfo", "")
                    locations = self._extract_locations_from_sourceinfo(source_info)
                    for loc in locations[:2]:  # Max 2 per package
                        if loc not in summary["location_samples"]:
                            summary["location_samples"].append(loc)
                
                # Track license information
                license_declared = package.get("licenseDeclared", "NOASSERTION")
                if license_declared and license_declared != "NOASSERTION":
                    summary["license_info"][license_declared] = summary["license_info"].get(license_declared, 0) + 1
            
            # Get top 10 suppliers
            summary["top_suppliers"] = [
                {"name": supplier, "count": count}
                for supplier, count in sorted(supplier_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
            
            # Add document information
            summary["spdx_version"] = sbom_data.get("spdxVersion", "")
            summary["document_name"] = sbom_data.get("name", "")
            creation_info = sbom_data.get("creationInfo", {})
            summary["creation_date"] = creation_info.get("created", "")
            summary["creators"] = creation_info.get("creators", [])
            
            # Mark if location samples were truncated
            if len(summary["location_samples"]) >= 20:
                summary["locations_truncated"] = True
            
            return summary
            
        except Exception as e:
            logger.error(f"Error extracting SBOM summary: {str(e)}")
            return {"error": f"Failed to extract summary: {str(e)}"}
    
    def get_sbom_file_path(self) -> str:
        """
        Get the path to the generated SBOM file
        
        Returns:
            Path to SBOM JSON file
        """
        return str(self.sbom_output_path)
    
    def load_existing_sbom(self) -> Optional[Dict[str, Any]]:
        """
        Load existing SBOM file if it exists
        
        Returns:
            SBOM data dictionary or None if file doesn't exist
        """
        try:
            if self.sbom_output_path.exists():
                with open(self.sbom_output_path, 'r') as f:
                    return json.load(f)
            return None
        except Exception as e:
            logger.error(f"Error loading existing SBOM: {str(e)}")
            return None


