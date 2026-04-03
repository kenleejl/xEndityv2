"""
MongoDB models for xScout module to store firmware analysis results
"""
from bson import ObjectId
from datetime import datetime
from typing import Dict, List, Any, Optional

class FirmwareAnalysisModel:
    """MongoDB model for firmware analysis results"""
    
    COLLECTION_NAME = 'firmware_analysis'
    
    def __init__(self, 
                 firmware_id: int = None,
                 file_path: str = None,
                 file_format: Dict[str, Any] = None,
                 hashes: Dict[str, str] = None,
                 entropy: Dict[str, Any] = None,
                 encryption: Dict[str, Any] = None,
                 strings_analysis: Dict[str, Any] = None,
                 extraction_points: Dict[str, Any] = None,
                 metadata: Dict[str, Any] = None,
                 visualization: Dict[str, Any] = None,
                 extraction_strategy: Dict[str, Any] = None,
                 status: str = 'pending',
                 progress: int = 0,
                 analysis_date: datetime = None,
                 _id: str = None):
        """
        Initialize a new FirmwareAnalysis document
        
        Args:
            firmware_id: The Django Firmware model ID from xQuire
            file_path: Path to the firmware file
            file_format: Information about file format
            hashes: File hashes (md5, sha1, sha256)
            entropy: Entropy analysis results
            encryption: Encryption detection results
            strings_analysis: String analysis results
            extraction_points: Extraction points found
            metadata: File metadata
            visualization: Visualization data
            extraction_strategy: Generated extraction strategy
            status: Analysis status (pending, running, completed, failed)
            progress: Analysis progress (0-100)
            analysis_date: When the analysis was performed
            _id: MongoDB ObjectId (string representation)
        """
        self.firmware_id = firmware_id
        self.file_path = file_path
        self.file_format = file_format or {}
        self.hashes = hashes or {}
        self.entropy = entropy or {}
        self.encryption = encryption or {}
        self.strings_analysis = strings_analysis or {}
        self.extraction_points = extraction_points or {}
        self.metadata = metadata or {}
        self.visualization = visualization or {}
        self.extraction_strategy = extraction_strategy or {}
        self.status = status
        self.progress = progress
        self.analysis_date = analysis_date or datetime.now()
        self._id = str(ObjectId()) if _id is None else _id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FirmwareAnalysisModel':
        """
        Create a FirmwareAnalysis instance from a dictionary
        
        Args:
            data: Dictionary containing document data
            
        Returns:
            FirmwareAnalysisModel instance
        """
        if '_id' in data and not isinstance(data['_id'], str):
            data['_id'] = str(data['_id'])
            
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the instance to a dictionary for MongoDB storage
        
        Returns:
            Dictionary representation of the instance
        """
        return {
            '_id': self._id,
            'firmware_id': self.firmware_id,
            'file_path': self.file_path,
            'file_format': self.file_format,
            'hashes': self.hashes,
            'entropy': self.entropy,
            'encryption': self.encryption,
            'strings_analysis': self.strings_analysis,
            'extraction_points': self.extraction_points,
            'metadata': self.metadata,
            'visualization': self.visualization,
            'extraction_strategy': self.extraction_strategy,
            'status': self.status,
            'progress': self.progress,
            'analysis_date': self.analysis_date
        }
    
    @property
    def id(self) -> str:
        """Get the document ID"""
        return self._id


class SecurityAnalysisModel:
    """MongoDB model for security analysis results (SBOM + Vulnerabilities)"""
    
    COLLECTION_NAME = 'security_analysis'
    
    def __init__(self,
                 firmware_id: int = None,
                 firmware_info: Dict[str, Any] = None,
                 sbom_data: Dict[str, Any] = None,
                 vulnerability_data: Dict[str, Any] = None,
                 security_summary: Dict[str, Any] = None,
                 risk_score: float = None,
                 analysis_date: datetime = None,
                 _id: str = None):
        """
        Initialize a new SecurityAnalysis document
        
        Args:
            firmware_id: The Django Firmware model ID from xQuire
            firmware_info: Basic firmware information (brand, model, version)
            sbom_data: Processed SBOM data
            vulnerability_data: Processed vulnerability data
            security_summary: Summary statistics and metrics
            risk_score: Calculated risk score (0-100)
            analysis_date: When the analysis was performed
            _id: MongoDB ObjectId (string representation)
        """
        self.firmware_id = firmware_id
        self.firmware_info = firmware_info or {}
        self.sbom_data = sbom_data or {}
        self.vulnerability_data = vulnerability_data or {}
        self.security_summary = security_summary or {}
        self.risk_score = risk_score
        self.analysis_date = analysis_date or datetime.now()
        self._id = str(ObjectId()) if _id is None else _id
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityAnalysisModel':
        """
        Create a SecurityAnalysis instance from a dictionary
        
        Args:
            data: Dictionary containing document data
            
        Returns:
            SecurityAnalysisModel instance
        """
        if '_id' in data and not isinstance(data['_id'], str):
            data['_id'] = str(data['_id'])
            
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the instance to a dictionary for MongoDB storage
        
        Returns:
            Dictionary representation of the instance
        """
        return {
            '_id': self._id,
            'firmware_id': self.firmware_id,
            'firmware_info': self.firmware_info,
            'sbom_data': self.sbom_data,
            'vulnerability_data': self.vulnerability_data,
            'security_summary': self.security_summary,
            'risk_score': self.risk_score,
            'analysis_date': self.analysis_date
        }
    
    @property
    def id(self) -> str:
        """Get the document ID"""
        return self._id
    
    def get_total_packages(self) -> int:
        """Get total number of packages in SBOM"""
        return len(self.sbom_data.get('packages', []))
    
    def get_total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities"""
        return self.vulnerability_data.get('total_count', 0)
    
    def get_critical_vulnerabilities(self) -> int:
        """Get number of critical vulnerabilities"""
        return self.vulnerability_data.get('severity_counts', {}).get('critical', 0)
    
    def get_high_vulnerabilities(self) -> int:
        """Get number of high severity vulnerabilities"""
        return self.vulnerability_data.get('severity_counts', {}).get('high', 0) 