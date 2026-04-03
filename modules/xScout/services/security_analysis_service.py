"""
Security Analysis Service for processing and storing SBOM and vulnerability data
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from modules.xQuire.models import Firmware
from modules.xScout.models.repositories import SecurityAnalysisRepository
from modules.xScout.models.mongo_models import SecurityAnalysisModel

logger = logging.getLogger(__name__)

class SecurityAnalysisService:
    """Service for managing security analysis data (SBOM + Vulnerabilities)"""
    
    def __init__(self):
        """Initialize the security analysis service"""
        self.security_repo = SecurityAnalysisRepository()
    
    def process_and_store_security_data(self, firmware_id: int) -> Optional[str]:
        """
        Process SBOM and vulnerability files and store in MongoDB
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            Document ID if successful, None otherwise
        """
        try:
            # Get firmware
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Get file paths - check both possible locations
            fw_name = os.path.splitext(os.path.basename(firmware.file.name))[0]
            fw_dir = os.path.dirname(firmware.file.path)
            
            # Try the main artifacts directory first (new location)
            artifacts_dir = os.path.join(fw_dir, "artifacts")
            sbom_path = os.path.join(artifacts_dir, "sbom.json")
            vuln_path = os.path.join(artifacts_dir, "vulnerabilities.json")
            vuln_summary_path = os.path.join(artifacts_dir, "vulnerability_summary.json")
            
            # If not found, try the extract directory artifacts (old location)
            if not all([os.path.exists(sbom_path), os.path.exists(vuln_path), os.path.exists(vuln_summary_path)]):
                artifacts_dir = os.path.join(fw_dir, f"{fw_name}_extract", "artifacts")
                sbom_path = os.path.join(artifacts_dir, "sbom.json")
                vuln_path = os.path.join(artifacts_dir, "vulnerabilities.json")
                vuln_summary_path = os.path.join(artifacts_dir, "vulnerability_summary.json")
            
            # Check if files exist
            if not all([os.path.exists(sbom_path), os.path.exists(vuln_path), os.path.exists(vuln_summary_path)]):
                logger.warning(f"Missing security analysis files for firmware {firmware_id}")
                logger.warning(f"Checked paths: {sbom_path}, {vuln_path}, {vuln_summary_path}")
                return None
            
            logger.info(f"Found security analysis files at: {artifacts_dir}")
            
            # Load and process data
            sbom_data = self._process_sbom_data(sbom_path)
            vulnerability_data = self._process_vulnerability_data(vuln_path, vuln_summary_path)
            
            # Enrich vulnerabilities with SBOM package information
            vulnerabilities = vulnerability_data.get('vulnerabilities', [])
            enriched_vulnerabilities = self._enrich_vulnerabilities_with_sbom(vulnerabilities, sbom_data)
            vulnerability_data['vulnerabilities'] = enriched_vulnerabilities
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(vulnerability_data)
            
            # Create security summary
            security_summary = self._create_security_summary(sbom_data, vulnerability_data, risk_score)
            
            # Create SecurityAnalysisModel
            security_analysis = SecurityAnalysisModel(
                firmware_id=firmware_id,
                firmware_info={
                    'manufacturer': firmware.model.manufacturer.name,
                    'model': firmware.model.model_number,
                    'version': firmware.version,
                    'file_name': os.path.basename(firmware.file.name)
                },
                sbom_data=sbom_data,
                vulnerability_data=vulnerability_data,
                security_summary=security_summary,
                risk_score=risk_score,
                analysis_date=datetime.now()
            )
            
            # Save to MongoDB
            doc_id = self.security_repo.save(security_analysis)
            
            if doc_id:
                logger.info(f"Stored security analysis for firmware {firmware_id} with ID: {doc_id}")
                return doc_id
            else:
                logger.error(f"Failed to store security analysis for firmware {firmware_id}")
                return None
                
        except Firmware.DoesNotExist:
            logger.error(f"Firmware with ID {firmware_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error processing security data for firmware {firmware_id}: {str(e)}")
            return None
    
    def _parse_package_type_from_spdxid(self, spdxid: str) -> str:
        """Parse package type from SPDXID"""
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
                    if loc and loc.endswith(".ko"):
                        return True
        
        return False
    
    def _extract_purl_from_refs(self, external_refs: list) -> str:
        """Extract PURL from externalRefs"""
        try:
            for ref in external_refs:
                if ref.get("referenceType") == "purl":
                    return ref.get("referenceLocator", "")
        except Exception:
            pass
        return ""
    
    def _extract_cpe_from_refs(self, external_refs: list) -> list:
        """Extract CPEs from externalRefs"""
        cpes = []
        try:
            for ref in external_refs:
                if ref.get("referenceType") == "cpe23Type":
                    cpes.append(ref.get("referenceLocator", ""))
        except Exception:
            pass
        return cpes
    
    def _extract_locations_from_sourceinfo(self, source_info: str) -> list:
        """Extract file locations from sourceInfo string"""
        import re
        locations = []
        try:
            if not source_info:
                return locations
            # Pattern: /path/to/file.ext
            path_pattern = r'(/[\w\-./]+\.\w+)'
            matches = re.findall(path_pattern, source_info)
            locations.extend(matches)
        except Exception:
            pass
        return locations
    
    def _process_sbom_data(self, sbom_path: str) -> Dict[str, Any]:
        """
        Process SBOM JSON file into structured data (handles both SPDX and Syft formats)
        
        Args:
            sbom_path: Path to SBOM JSON file
            
        Returns:
            Processed SBOM data
        """
        try:
            with open(sbom_path, 'r') as f:
                sbom_raw = json.load(f)
            
            packages = []
            
            # Detect format and extract packages
            if 'spdxVersion' in sbom_raw:
                # SPDX format
                logger.info("Processing SBOM in SPDX format")
                for package in sbom_raw.get('packages', []):
                    # Extract package type from SPDXID
                    pkg_type = self._parse_package_type_from_spdxid(package.get('SPDXID', ''))
                    
                    # Extract supplier/vendor
                    supplier = package.get('supplier', 'NOASSERTION')
                    if supplier and supplier != 'NOASSERTION':
                        supplier = supplier.replace('Organization: ', '').replace('Person: ', '')
                    else:
                        supplier = ''
                    
                    # Extract PURL and CPEs from externalRefs
                    external_refs = package.get('externalRefs', [])
                    purl = self._extract_purl_from_refs(external_refs)
                    cpes = self._extract_cpe_from_refs(external_refs)
                    
                    # Extract locations from sourceInfo
                    source_info = package.get('sourceInfo', '')
                    locations = self._extract_locations_from_sourceinfo(source_info)
                    
                    # Get version info
                    version = package.get('versionInfo', '')
                    if version in ['UNKNOWN', 'NOASSERTION']:
                        version = ''
                    
                    # Determine if this is a kernel module (by SPDXID or .ko files)
                    is_kernel_module = self._is_kernel_module(pkg_type, source_info, locations)
                    effective_type = "linux-kernel-module" if is_kernel_module else pkg_type
                    
                    packages.append({
                        'name': package.get('name', ''),
                        'version': version,
                        'type': effective_type,
                        'supplier': supplier,
                        'locations': locations,
                        'cpes': cpes,
                        'purl': purl,
                        'license_declared': package.get('licenseDeclared', ''),
                        'license_concluded': package.get('licenseConcluded', ''),
                        'source_info': source_info
                    })
                
                # Extract metadata
                creation_info = sbom_raw.get('creationInfo', {})
                scan_date = creation_info.get('created', '')
                creators = creation_info.get('creators', [])
                scanner_name = next((c.replace('Tool: ', '') for c in creators if 'Tool:' in c), 'syft')
                scanner_version = scanner_name.split('-')[-1] if '-' in scanner_name else ''
                
                return {
                    'scan_date': scan_date,
                    'scanner_name': scanner_name,
                    'scanner_version': scanner_version,
                    'total_packages': len(packages),
                    'packages': packages,
                    'spdx_version': sbom_raw.get('spdxVersion', ''),
                    'document_name': sbom_raw.get('name', '')
                }
                
            else:
                # Legacy Syft JSON format
                logger.info("Processing SBOM in legacy Syft JSON format")
                for artifact in sbom_raw.get('artifacts', []):
                    packages.append({
                        'name': artifact.get('name', ''),
                        'version': artifact.get('version', ''),
                        'type': artifact.get('type', ''),
                        'supplier': '',
                        'locations': [loc.get('path', '') for loc in artifact.get('locations', [])],
                        'cpes': [cpe.get('cpe', '') for cpe in artifact.get('cpes', [])],
                        'purl': artifact.get('purl', ''),
                        'language': artifact.get('language', ''),
                        'licenses': artifact.get('licenses', []),
                        'source_info': ''
                    })
                
                return {
                    'scan_date': sbom_raw.get('descriptor', {}).get('timestamp', ''),
                    'scanner_name': sbom_raw.get('descriptor', {}).get('name', ''),
                    'scanner_version': sbom_raw.get('descriptor', {}).get('version', ''),
                    'total_packages': len(packages),
                    'packages': packages,
                    'distro_info': sbom_raw.get('distro', {}),
                    'source_info': sbom_raw.get('source', {})
                }
            
        except Exception as e:
            logger.error(f"Error processing SBOM data: {str(e)}")
            logger.exception(e)
            return {}
    
    def _process_vulnerability_data(self, vuln_path: str, vuln_summary_path: str) -> Dict[str, Any]:
        """
        Process vulnerability JSON files into structured data with enhanced metrics
        
        Args:
            vuln_path: Path to vulnerabilities JSON file
            vuln_summary_path: Path to vulnerability summary JSON file
            
        Returns:
            Processed vulnerability data with EPSS, risk scores, and detailed metrics
        """
        try:
            # Load summary data
            with open(vuln_summary_path, 'r') as f:
                summary = json.load(f)
            
            # Load detailed vulnerability data
            with open(vuln_path, 'r') as f:
                vuln_raw = json.load(f)
            
            # Process vulnerabilities
            vulnerabilities = []
            for match in vuln_raw.get('matches', []):
                vuln = match.get('vulnerability', {})
                artifact = match.get('artifact', {})
                match_details = match.get('matchDetails', [{}])[0] if match.get('matchDetails') else {}
                
                # Extract CVSS score and detailed metrics
                cvss_score = 0.0
                cvss_vector = ''
                exploitability_score = 0.0
                impact_score = 0.0
                cvss_version = ''
                
                if vuln.get('cvss'):
                    for cvss_entry in vuln['cvss']:
                        if isinstance(cvss_entry, dict) and 'metrics' in cvss_entry:
                            metrics = cvss_entry.get('metrics', {})
                            cvss_score = float(metrics.get('baseScore', 0.0))
                            exploitability_score = float(metrics.get('exploitabilityScore', 0.0))
                            impact_score = float(metrics.get('impactScore', 0.0))
                            cvss_vector = cvss_entry.get('vector', '')
                            cvss_version = cvss_entry.get('version', '')
                            break
                
                # Extract EPSS (Exploit Prediction Scoring System)
                epss_probability = 0.0
                epss_percentile = 0.0
                epss_date = ''
                
                if vuln.get('epss'):
                    epss_data = vuln['epss'][0] if isinstance(vuln['epss'], list) else vuln['epss']
                    if isinstance(epss_data, dict):
                        epss_probability = float(epss_data.get('epss', 0.0)) * 100
                        epss_percentile = float(epss_data.get('percentile', 0.0))
                        epss_date = epss_data.get('date', '')
                
                # Extract risk score (Grype's calculated risk)
                risk_score = float(vuln.get('risk', 0.0))
                
                # Extract fix information (enhanced)
                fix_info = vuln.get('fix', {})
                fix_available = fix_info.get('state') == 'fixed'
                fix_versions = fix_info.get('versions', [])
                fix_state = fix_info.get('state', 'unknown')
                
                # Extract suggested version from matchDetails
                suggested_version = ''
                version_constraint = ''
                if match_details:
                    fix_detail = match_details.get('fix', {})
                    suggested_version = fix_detail.get('suggestedVersion', '')
                    found_info = match_details.get('found', {})
                    version_constraint = found_info.get('versionConstraint', '')
                
                # Extract CPEs and PURL from artifact
                artifact_cpes = artifact.get('cpes', [])
                artifact_purl = artifact.get('purl', '')
                artifact_type = artifact.get('type', 'UnknownPackage')
                artifact_id = artifact.get('id', '')
                
                # Parse CVSS vector components
                attack_vector = ''
                attack_complexity = ''
                privileges_required = ''
                user_interaction = ''
                
                if cvss_vector:
                    # Parse CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                    vector_parts = cvss_vector.split('/')
                    for part in vector_parts:
                        if ':' in part:
                            key, value = part.split(':', 1)
                            if key == 'AV':
                                attack_vector = {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}.get(value, value)
                            elif key == 'AC':
                                attack_complexity = {'L': 'Low', 'H': 'High'}.get(value, value)
                            elif key == 'PR':
                                privileges_required = {'N': 'None', 'L': 'Low', 'H': 'High'}.get(value, value)
                            elif key == 'UI':
                                user_interaction = {'N': 'None', 'R': 'Required'}.get(value, value)
                
                # Extract CVE year for age analysis
                cve_id = vuln.get('id', '')
                cve_year = 0
                if cve_id.startswith('CVE-'):
                    try:
                        cve_year = int(cve_id.split('-')[1])
                    except (IndexError, ValueError):
                        pass
                
                vulnerabilities.append({
                    # Basic information
                    'cve_id': cve_id,
                    'severity': vuln.get('severity', '').lower(),
                    'description': vuln.get('description', ''),
                    'urls': vuln.get('urls', []),
                    'data_source': vuln.get('dataSource', ''),
                    'namespace': vuln.get('namespace', ''),
                    
                    # Package information
                    'package': f"{artifact.get('name', '')}@{artifact.get('version', '')}",
                    'package_name': artifact.get('name', ''),
                    'package_version': artifact.get('version', ''),
                    'artifact_type': artifact_type,
                    'artifact_id': artifact_id,
                    'artifact_purl': artifact_purl,
                    'artifact_cpes': artifact_cpes,
                    
                    # CVSS metrics
                    'cvss_score': cvss_score,
                    'cvss_version': cvss_version,
                    'cvss_vector': cvss_vector,
                    'exploitability_score': exploitability_score,
                    'impact_score': impact_score,
                    'attack_vector': attack_vector,
                    'attack_complexity': attack_complexity,
                    'privileges_required': privileges_required,
                    'user_interaction': user_interaction,
                    
                    # EPSS metrics
                    'epss_probability': epss_probability,
                    'epss_percentile': epss_percentile,
                    'epss_date': epss_date,
                    
                    # Risk assessment
                    'risk_score': risk_score,
                    'cve_year': cve_year,
                    
                    # Fix information
                    'fix_available': fix_available,
                    'fix_versions': fix_versions,
                    'fix_state': fix_state,
                    'suggested_version': suggested_version,
                    'version_constraint': version_constraint,
                    
                    # Related data
                    'related_vulnerabilities': match.get('relatedVulnerabilities', []),
                    'advisories': vuln.get('advisories', [])
                })
            
            return {
                'scan_date': vuln_raw.get('descriptor', {}).get('timestamp', ''),
                'scanner_name': vuln_raw.get('descriptor', {}).get('name', ''),
                'scanner_version': vuln_raw.get('descriptor', {}).get('version', ''),
                'total_count': summary.get('total_vulnerabilities', 0),
                'severity_counts': summary.get('severity_counts', {}),
                'vulnerability_types': summary.get('vulnerability_types', {}),
                'vulnerabilities': vulnerabilities,
                'top_vulnerabilities': summary.get('top_vulnerabilities', []),
                'affected_packages': summary.get('affected_packages', {}),
                'scan_info': summary.get('scan_info', {})
            }
            
        except Exception as e:
            logger.error(f"Error processing vulnerability data: {str(e)}")
            logger.exception(e)
            return {}
    
    def _enrich_vulnerabilities_with_sbom(self, vulnerabilities: list, sbom_data: Dict[str, Any]) -> list:
        """
        Enrich vulnerability data with SBOM package information
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            sbom_data: Processed SBOM data with packages
            
        Returns:
            Enriched list of vulnerabilities with SBOM package metadata
        """
        try:
            # Create package lookup dictionary by name
            packages_by_name = {}
            for pkg in sbom_data.get('packages', []):
                pkg_name = pkg.get('name', '')
                if pkg_name:
                    if pkg_name not in packages_by_name:
                        packages_by_name[pkg_name] = []
                    packages_by_name[pkg_name].append(pkg)
            
            # Enrich each vulnerability
            enriched_vulnerabilities = []
            for vuln in vulnerabilities:
                pkg_name = vuln.get('package_name', '')
                
                # Find matching SBOM package
                sbom_packages = packages_by_name.get(pkg_name, [])
                
                # Try to find exact version match, or use first match
                sbom_pkg = None
                pkg_version = vuln.get('package_version', '')
                for candidate in sbom_packages:
                    if candidate.get('version') == pkg_version:
                        sbom_pkg = candidate
                        break
                
                # If no exact match, use first package with same name
                if not sbom_pkg and sbom_packages:
                    sbom_pkg = sbom_packages[0]
                
                # Enrich vulnerability with SBOM data
                if sbom_pkg:
                    vuln['sbom_package_type'] = sbom_pkg.get('type', 'unknown')
                    vuln['sbom_locations'] = sbom_pkg.get('locations', [])
                    vuln['sbom_supplier'] = sbom_pkg.get('supplier', '')
                    vuln['sbom_license'] = sbom_pkg.get('license_declared', '')
                    vuln['sbom_source_info'] = sbom_pkg.get('source_info', '')
                    vuln['sbom_found'] = True
                else:
                    vuln['sbom_package_type'] = vuln.get('artifact_type', 'unknown')
                    vuln['sbom_locations'] = []
                    vuln['sbom_supplier'] = ''
                    vuln['sbom_license'] = ''
                    vuln['sbom_source_info'] = ''
                    vuln['sbom_found'] = False
                
                enriched_vulnerabilities.append(vuln)
            
            return enriched_vulnerabilities
            
        except Exception as e:
            logger.error(f"Error enriching vulnerabilities with SBOM data: {str(e)}")
            return vulnerabilities
    
    def _calculate_risk_score(self, vulnerability_data: Dict[str, Any]) -> float:
        """
        Calculate a risk score (0-100) based on vulnerabilities
        
        Args:
            vulnerability_data: Processed vulnerability data
            
        Returns:
            Risk score between 0 and 100
        """
        try:
            severity_counts = vulnerability_data.get('severity_counts', {})
            
            # Weighted scoring
            critical = severity_counts.get('critical', 0)
            high = severity_counts.get('high', 0)
            medium = severity_counts.get('medium', 0)
            low = severity_counts.get('low', 0)
            
            # Calculate base score (weighted by severity)
            base_score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
            
            # Normalize to 0-100 scale (cap at 100)
            risk_score = min(base_score, 100)
            
            # Adjust for CVSS scores if available
            vulnerabilities = vulnerability_data.get('vulnerabilities', [])
            if vulnerabilities:
                avg_cvss = sum(v.get('cvss_score', 0) for v in vulnerabilities) / len(vulnerabilities)
                cvss_factor = avg_cvss / 10.0  # Normalize CVSS to 0-1
                risk_score = min(risk_score * (1 + cvss_factor * 0.5), 100)
            
            return round(risk_score, 2)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 0.0
    
    def _create_security_summary(self, sbom_data: Dict[str, Any], 
                                vulnerability_data: Dict[str, Any], 
                                risk_score: float) -> Dict[str, Any]:
        """
        Create a security summary with key metrics
        
        Args:
            sbom_data: Processed SBOM data
            vulnerability_data: Processed vulnerability data
            risk_score: Calculated risk score
            
        Returns:
            Security summary dictionary
        """
        try:
            packages = sbom_data.get('packages', [])
            vulnerabilities = vulnerability_data.get('vulnerabilities', [])
            
            # Package statistics
            package_types = {}
            for pkg in packages:
                pkg_type = pkg.get('type', 'unknown')
                package_types[pkg_type] = package_types.get(pkg_type, 0) + 1
            
            # Vulnerability statistics
            vuln_by_package = {}
            for vuln in vulnerabilities:
                pkg_name = vuln.get('package_name', 'unknown')
                if pkg_name not in vuln_by_package:
                    vuln_by_package[pkg_name] = {'count': 0, 'severities': {}}
                vuln_by_package[pkg_name]['count'] += 1
                severity = vuln.get('severity', 'unknown')
                vuln_by_package[pkg_name]['severities'][severity] = \
                    vuln_by_package[pkg_name]['severities'].get(severity, 0) + 1
            
            # Most vulnerable packages
            most_vulnerable = sorted(
                vuln_by_package.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:10]
            
            return {
                'risk_score': risk_score,
                'total_packages': len(packages),
                'total_vulnerabilities': len(vulnerabilities),
                'package_types': package_types,
                'vulnerability_by_package': dict(most_vulnerable),
                'has_critical_vulns': vulnerability_data.get('severity_counts', {}).get('critical', 0) > 0,
                'has_high_vulns': vulnerability_data.get('severity_counts', {}).get('high', 0) > 0,
                'fix_available_count': sum(1 for v in vulnerabilities if v.get('fix_available')),
                'avg_cvss_score': round(
                    sum(v.get('cvss_score', 0) for v in vulnerabilities) / len(vulnerabilities)
                    if vulnerabilities else 0, 2
                )
            }
            
        except Exception as e:
            logger.error(f"Error creating security summary: {str(e)}")
            return {}
    
    def get_security_analysis(self, firmware_id: int) -> Optional[SecurityAnalysisModel]:
        """
        Get security analysis for a firmware
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            SecurityAnalysisModel instance if found, None otherwise
        """
        return self.security_repo.find_by_firmware_id(firmware_id)
    
    def list_all_security_analyses(self, limit: int = 100) -> List[SecurityAnalysisModel]:
        """
        List all security analyses
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of SecurityAnalysisModel instances
        """
        return self.security_repo.list_all(limit)
    
    def find_by_cve(self, cve_id: str) -> List[SecurityAnalysisModel]:
        """
        Find all firmwares affected by a specific CVE
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of SecurityAnalysisModel instances
        """
        return self.security_repo.find_vulnerabilities_by_cve(cve_id)
    
    def find_by_package(self, package_name: str, package_version: str = None) -> List[SecurityAnalysisModel]:
        """
        Find all firmwares containing a specific package
        
        Args:
            package_name: Name of the package
            package_version: Version of the package (optional)
            
        Returns:
            List of SecurityAnalysisModel instances
        """
        return self.security_repo.find_by_package(package_name, package_version)
    
    def get_security_dashboard_data(self) -> Dict[str, Any]:
        """
        Get aggregated data for security dashboard
        
        Returns:
            Dictionary with dashboard metrics
        """
        try:
            # Get overall summary from repository
            summary = self.security_repo.get_security_summary()
            
            # Get recent analyses
            recent_analyses = self.security_repo.list_all(limit=10)
            
            # Calculate additional metrics
            high_risk_count = sum(1 for analysis in recent_analyses if analysis.risk_score and analysis.risk_score > 70)
            medium_risk_count = sum(1 for analysis in recent_analyses if analysis.risk_score and 30 <= analysis.risk_score <= 70)
            low_risk_count = sum(1 for analysis in recent_analyses if analysis.risk_score and analysis.risk_score < 30)
            
            return {
                'overview': summary,
                'recent_analyses': [
                    {
                        'firmware_info': analysis.firmware_info,
                        'risk_score': analysis.risk_score,
                        'total_vulnerabilities': analysis.get_total_vulnerabilities(),
                        'critical_vulnerabilities': analysis.get_critical_vulnerabilities(),
                        'high_vulnerabilities': analysis.get_high_vulnerabilities(),
                        'analysis_date': analysis.analysis_date
                    }
                    for analysis in recent_analyses
                ],
                'risk_distribution': {
                    'high_risk': high_risk_count,
                    'medium_risk': medium_risk_count,
                    'low_risk': low_risk_count
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {str(e)}")
            return {}
    
    def get_comprehensive_stats(self, limit: int = 100) -> Dict[str, Any]:
        """
        Get comprehensive security statistics for dashboard
        
        Args:
            limit: Maximum number of analyses to include in calculations
            
        Returns:
            Dictionary with comprehensive statistics
        """
        try:
            all_analyses = self.security_repo.list_all(limit)
            
            if not all_analyses:
                return {
                    'total_security_analyses': 0,
                    'total_firmwares': 0,
                    'high_risk_firmwares': 0,
                    'medium_risk_firmwares': 0,
                    'low_risk_firmwares': 0,
                    'total_vulnerabilities': 0,
                    'critical_vulnerabilities': 0,
                    'high_vulnerabilities': 0,
                    'total_packages': 0,
                    'avg_risk_score': 0,
                    'risk_percentages': {
                        'high_risk_percentage': 0,
                        'medium_risk_percentage': 0,
                        'low_risk_percentage': 0
                    }
                }
            
            # Calculate risk categories
            high_risk_firmwares = [a for a in all_analyses if a.risk_score and a.risk_score > 70]
            medium_risk_firmwares = [a for a in all_analyses if a.risk_score and 30 <= a.risk_score <= 70]
            low_risk_firmwares = [a for a in all_analyses if a.risk_score and a.risk_score < 30]
            
            # Calculate averages and totals
            total_firmwares = len(all_analyses)
            analyses_with_risk = [a for a in all_analyses if a.risk_score is not None]
            avg_risk_score = (
                sum(a.risk_score for a in analyses_with_risk) / len(analyses_with_risk)
                if analyses_with_risk else 0
            )
            
            # Calculate percentages for risk distribution
            high_risk_percentage = (len(high_risk_firmwares) / total_firmwares * 100) if total_firmwares > 0 else 0
            medium_risk_percentage = (len(medium_risk_firmwares) / total_firmwares * 100) if total_firmwares > 0 else 0
            low_risk_percentage = (len(low_risk_firmwares) / total_firmwares * 100) if total_firmwares > 0 else 0
            
            return {
                'total_security_analyses': len(all_analyses),
                'total_firmwares': total_firmwares,
                'high_risk_firmwares': len(high_risk_firmwares),
                'medium_risk_firmwares': len(medium_risk_firmwares),
                'low_risk_firmwares': len(low_risk_firmwares),
                'total_vulnerabilities': sum(a.get_total_vulnerabilities() for a in all_analyses),
                'critical_vulnerabilities': sum(a.get_critical_vulnerabilities() for a in all_analyses),
                'high_vulnerabilities': sum(a.get_high_vulnerabilities() for a in all_analyses),
                'total_packages': sum(a.get_total_packages() for a in all_analyses),
                'avg_risk_score': round(avg_risk_score, 1),
                'risk_percentages': {
                    'high_risk_percentage': round(high_risk_percentage, 1),
                    'medium_risk_percentage': round(medium_risk_percentage, 1),
                    'low_risk_percentage': round(low_risk_percentage, 1)
                }
            }
            
        except Exception as e:
            logger.error(f"Error calculating comprehensive stats: {str(e)}")
            return {}
    
    def get_dashboard_data_with_stats(self, limit: int = 100) -> Dict[str, Any]:
        """
        Get combined dashboard data with comprehensive statistics
        
        Args:
            limit: Maximum number of analyses to process
            
        Returns:
            Combined dashboard data and statistics
        """
        try:
            dashboard_data = self.get_security_dashboard_data()
            comprehensive_stats, all_analyses = self.get_comprehensive_stats(limit)
            
            return {
                'dashboard_data': dashboard_data,
                'stats': comprehensive_stats,
                'security_analyses': all_analyses[:20],  # Show top 20 most recent
                'has_analyses': len(all_analyses) > 0,
                'total_count': len(all_analyses)
            }
            
        except Exception as e:
            logger.error(f"Error getting combined dashboard data: {str(e)}")
            return {
                'dashboard_data': {},
                'stats': {},
                'security_analyses': [],
                'has_analyses': False,
                'total_count': 0,
                'error': str(e)
            }
    
    def compare_firmwares(self, firmware_ids: List[int]) -> Dict[str, Any]:
        """
        Compare security analysis between multiple firmwares
        
        Args:
            firmware_ids: List of firmware IDs to compare
            
        Returns:
            Comparison data dictionary
        """
        try:
            analyses = []
            for fw_id in firmware_ids:
                analysis = self.security_repo.find_by_firmware_id(fw_id)
                if analysis:
                    analyses.append(analysis)
            
            if len(analyses) < 2:
                return {'error': 'At least 2 firmware analyses are required for comparison'}
            
            # Find common vulnerabilities
            all_cves = []
            firmware_cves = {}
            
            for analysis in analyses:
                fw_key = f"{analysis.firmware_info.get('manufacturer', '')} {analysis.firmware_info.get('model', '')}"
                cves = [v.get('cve_id', '') for v in analysis.vulnerability_data.get('vulnerabilities', [])]
                firmware_cves[fw_key] = set(cves)
                all_cves.extend(cves)
            
            # Find common and unique CVEs
            common_cves = set(all_cves)
            for fw_cves in firmware_cves.values():
                common_cves = common_cves.intersection(fw_cves)
            
            # Find common packages
            all_packages = []
            firmware_packages = {}
            
            for analysis in analyses:
                fw_key = f"{analysis.firmware_info.get('manufacturer', '')} {analysis.firmware_info.get('model', '')}"
                packages = [f"{p.get('name', '')}@{p.get('version', '')}" for p in analysis.sbom_data.get('packages', [])]
                firmware_packages[fw_key] = set(packages)
                all_packages.extend(packages)
            
            common_packages = set(all_packages)
            for fw_packages in firmware_packages.values():
                common_packages = common_packages.intersection(fw_packages)
            
            return {
                'firmwares': [
                    {
                        'info': analysis.firmware_info,
                        'risk_score': analysis.risk_score,
                        'total_vulnerabilities': analysis.get_total_vulnerabilities(),
                        'total_packages': analysis.get_total_packages(),
                        'severity_counts': analysis.vulnerability_data.get('severity_counts', {})
                    }
                    for analysis in analyses
                ],
                'common_vulnerabilities': list(common_cves),
                'common_packages': list(common_packages),
                'unique_vulnerabilities': {
                    fw_key: list(fw_cves - common_cves)
                    for fw_key, fw_cves in firmware_cves.items()
                },
                'unique_packages': {
                    fw_key: list(fw_packages - common_packages)
                    for fw_key, fw_packages in firmware_packages.items()
                }
            }
            
        except Exception as e:
            logger.error(f"Error comparing firmwares: {str(e)}")
            return {'error': str(e)}
    
    def delete_security_analysis(self, firmware_id: int) -> bool:
        """
        Delete security analysis for a firmware
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate firmware_id before proceeding
            if not firmware_id or firmware_id <= 0:
                logger.error(f"Invalid firmware_id provided for deletion: {firmware_id}")
                return False
            
            logger.info(f"SecurityAnalysisService: Requesting deletion for firmware_id {firmware_id}")
            result = self.security_repo.delete(firmware_id)
            logger.info(f"SecurityAnalysisService: Deletion result for firmware_id {firmware_id}: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error in SecurityAnalysisService delete for firmware {firmware_id}: {str(e)}")
            return False 