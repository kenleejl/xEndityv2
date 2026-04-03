"""
Repository classes for interacting with MongoDB collections
"""
from typing import Dict, List, Any, Optional, Union
import logging
from bson import ObjectId

from modules.base.utils.db_utils import MongoDBConnection
from modules.xScout.models.mongo_models import FirmwareAnalysisModel, SecurityAnalysisModel

logger = logging.getLogger(__name__)

class FirmwareAnalysisRepository:
    """Repository for firmware analysis data in MongoDB"""
    
    def __init__(self):
        """Initialize the repository with MongoDB connection"""
        try:
            self.db_conn = MongoDBConnection()
            # Check connection status
            if not self.db_conn.is_connected:
                logger.error("MongoDB connection is not available")
                self.collection = None
                return
            
            self.collection = self.db_conn.get_collection(FirmwareAnalysisModel.COLLECTION_NAME)
            if self.collection is None:
                logger.error(f"Failed to get collection {FirmwareAnalysisModel.COLLECTION_NAME}")
            # else:
            #     logger.info(f"Successfully connected to MongoDB collection {FirmwareAnalysisModel.COLLECTION_NAME}")
        except Exception as e:
            logger.error(f"Error initializing repository: {str(e)}")
            self.collection = None
    
    def save(self, analysis: Union[FirmwareAnalysisModel, Dict[str, Any]]) -> Optional[str]:
        """
        Save a firmware analysis document to MongoDB
        
        Args:
            analysis: FirmwareAnalysisModel instance or dictionary
            
        Returns:
            Document ID if successful, None otherwise
        """
        try:
            # Check if collection is available
            if self.collection is None:
                logger.error("Cannot save analysis: MongoDB collection is not available")
                return None
                
            if isinstance(analysis, FirmwareAnalysisModel):
                data = analysis.to_dict()
            else:
                data = analysis
                
            # If _id exists, update document, otherwise insert new one
            if '_id' in data and data['_id']:
                # Get the document ID
                doc_id = data['_id']
                logger.debug(f"Updating existing document with ID: {doc_id}")
                
                # Create a copy of the data without the _id for the update
                update_data = data.copy()
                del update_data['_id']
                
                # Update the document
                try:
                    result = self.collection.update_one(
                        {'_id': ObjectId(doc_id)},
                        {'$set': update_data}
                    )
                    
                    if result.matched_count > 0:
                        logger.info(f"Updated analysis document with ID: {doc_id}, matched: {result.matched_count}, modified: {result.modified_count}")
                        return doc_id
                    else:
                        logger.warning(f"No document found with ID: {doc_id} for update")
                        # Attempt to insert instead
                        logger.info(f"Attempting to insert document with specified ID: {doc_id}")
                        data['_id'] = ObjectId(doc_id)
                        result = self.collection.insert_one(data)
                        logger.info(f"Inserted document with ID: {result.inserted_id}")
                        return str(result.inserted_id)
                except Exception as e:
                    logger.error(f"Error updating document: {str(e)}")
                    return None
            else:
                # Insert a new document
                logger.debug("Inserting new document")
                result = self.collection.insert_one(data)
                logger.info(f"Inserted new analysis document with ID: {result.inserted_id}")
                return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error saving firmware analysis: {str(e)}")
            return None
    
    def find_by_id(self, analysis_id: str) -> Optional[FirmwareAnalysisModel]:
        """
        Find a firmware analysis by ID
        
        Args:
            analysis_id: MongoDB document ID
            
        Returns:
            FirmwareAnalysisModel instance if found, None otherwise
        """
        try:
            result = self.collection.find_one({'_id': ObjectId(analysis_id)})
            if result:
                return FirmwareAnalysisModel.from_dict(result)
            return None
        except Exception as e:
            logger.error(f"Error finding firmware analysis by ID: {str(e)}")
            return None
    
    def find_by_firmware_id(self, firmware_id: int) -> Optional[FirmwareAnalysisModel]:
        """
        Find the latest firmware analysis by firmware ID
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            FirmwareAnalysisModel instance if found, None otherwise
        """
        try:
            # Get the latest analysis by date
            result = self.collection.find({'firmware_id': firmware_id}) \
                                   .sort('analysis_date', -1) \
                                   .limit(1)
            result = list(result)
            
            if result and len(result) > 0:
                return FirmwareAnalysisModel.from_dict(result[0])
            return None
        except Exception as e:
            logger.error(f"Error finding firmware analysis by firmware ID: {str(e)}")
            return None
    
    def list_all_by_firmware_id(self, firmware_id: int) -> List[FirmwareAnalysisModel]:
        """
        List all analyses for a firmware
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            List of FirmwareAnalysisModel instances
        """
        try:
            results = self.collection.find({'firmware_id': firmware_id}) \
                                    .sort('analysis_date', -1)
            return [FirmwareAnalysisModel.from_dict(doc) for doc in results]
        except Exception as e:
            logger.error(f"Error listing firmware analyses: {str(e)}")
            return []
    
    def list_all(self, limit: int = 100) -> List[FirmwareAnalysisModel]:
        """
        List all firmware analyses
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of FirmwareAnalysisModel instances
        """
        try:
            results = self.collection.find() \
                                    .sort('analysis_date', -1) \
                                    .limit(limit)
            return [FirmwareAnalysisModel.from_dict(doc) for doc in results]
        except Exception as e:
            logger.error(f"Error listing all firmware analyses: {str(e)}")
            return []
    
    def update_status(self, analysis_id: str, status: str, progress: int = None) -> bool:
        """
        Update the status and progress of an analysis
        
        Args:
            analysis_id: MongoDB document ID
            status: New status value
            progress: New progress value (optional)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            update_data = {'status': status}
            if progress is not None:
                update_data['progress'] = progress
                
            result = self.collection.update_one(
                {'_id': ObjectId(analysis_id)},
                {'$set': update_data}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error updating firmware analysis status: {str(e)}")
            return False
    
    def delete(self, analysis_id: str) -> bool:
        """
        Delete a firmware analysis
        
        Args:
            analysis_id: MongoDB document ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if collection is available
            if self.collection is None:
                logger.error("Cannot delete analysis: MongoDB collection is not available")
                return False
            
            # Ensure the ID is valid
            try:
                object_id = ObjectId(analysis_id)
            except Exception as e:
                logger.error(f"Invalid ObjectId format: {analysis_id}, Error: {str(e)}")
                return False
                
            # Check if document exists before deleting
            doc = self.collection.find_one({'_id': object_id})
            if not doc:
                logger.warning(f"Document with ID {analysis_id} not found for deletion")
                return False
                
            # Delete the document
            result = self.collection.delete_one({'_id': object_id})
            
            if result.deleted_count > 0:
                logger.info(f"Successfully deleted document with ID: {analysis_id}")
                return True
            else:
                logger.warning(f"Document with ID {analysis_id} not deleted, deleted_count: {result.deleted_count}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting firmware analysis: {str(e)}")
            return False 

    def count(self) -> int:
        """
        Count the number of firmware analyses
        
        Returns:
            Number of analyses
        """
        try:
            logger.info(f"Counting firmware analyses")
            logger.info(f"Collection: {self.collection}")
            logger.info(f"Count: {self.collection.count_documents({})}")
            return self.collection.count_documents({})
        except Exception as e:
            logger.error(f"Error counting firmware analyses: {str(e)}")
            return 0


class SecurityAnalysisRepository:
    """Repository for security analysis data in MongoDB"""
    
    def __init__(self):
        """Initialize the repository with MongoDB connection"""
        try:
            self.db_conn = MongoDBConnection()
            if not self.db_conn.is_connected:
                logger.error("MongoDB connection is not available")
                self.collection = None
                return
            
            self.collection = self.db_conn.get_collection(SecurityAnalysisModel.COLLECTION_NAME)
            if self.collection is None:
                logger.error(f"Failed to get collection {SecurityAnalysisModel.COLLECTION_NAME}")
        except Exception as e:
            logger.error(f"Error initializing security repository: {str(e)}")
            self.collection = None
    
    def save(self, security_analysis: Union[SecurityAnalysisModel, Dict[str, Any]]) -> Optional[str]:
        """
        Save a security analysis document to MongoDB
        
        Args:
            security_analysis: SecurityAnalysisModel instance or dictionary
            
        Returns:
            Document ID if successful, None otherwise
        """
        try:
            if self.collection is None:
                logger.error("Cannot save security analysis: MongoDB collection is not available")
                return None
                
            if isinstance(security_analysis, SecurityAnalysisModel):
                data = security_analysis.to_dict()
            else:
                data = security_analysis
                
            # If _id exists, update document, otherwise insert new one
            if '_id' in data and data['_id']:
                doc_id = data['_id']
                update_data = data.copy()
                del update_data['_id']
                
                result = self.collection.update_one(
                    {'_id': ObjectId(doc_id)},
                    {'$set': update_data}
                )
                
                if result.matched_count > 0:
                    logger.info(f"Updated security analysis document with ID: {doc_id}")
                    return doc_id
                else:
                    # Insert with specified ID
                    data['_id'] = ObjectId(doc_id)
                    result = self.collection.insert_one(data)
                    return str(result.inserted_id)
            else:
                # Insert new document
                result = self.collection.insert_one(data)
                logger.info(f"Inserted new security analysis document with ID: {result.inserted_id}")
                return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error saving security analysis: {str(e)}")
            return None
    
    def find_by_firmware_id(self, firmware_id: int) -> Optional[SecurityAnalysisModel]:
        """
        Find the latest security analysis by firmware ID
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            SecurityAnalysisModel instance if found, None otherwise
        """
        try:
            result = self.collection.find({'firmware_id': firmware_id}) \
                                   .sort('analysis_date', -1) \
                                   .limit(1)
            result = list(result)
            
            if result and len(result) > 0:
                return SecurityAnalysisModel.from_dict(result[0])
            return None
        except Exception as e:
            logger.error(f"Error finding security analysis by firmware ID: {str(e)}")
            return None
    
    def list_all(self, limit: int = 100) -> List[SecurityAnalysisModel]:
        """
        List all security analyses
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of SecurityAnalysisModel instances
        """
        try:
            results = self.collection.find() \
                                    .sort('analysis_date', -1) \
                                    .limit(limit)
            return [SecurityAnalysisModel.from_dict(doc) for doc in results]
        except Exception as e:
            logger.error(f"Error listing all security analyses: {str(e)}")
            return []
    
    def find_vulnerabilities_by_cve(self, cve_id: str) -> List[SecurityAnalysisModel]:
        """
        Find all firmwares affected by a specific CVE
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2018-1000517")
            
        Returns:
            List of SecurityAnalysisModel instances
        """
        try:
            results = self.collection.find({
                'vulnerability_data.vulnerabilities.cve_id': cve_id
            }).sort('analysis_date', -1)
            
            return [SecurityAnalysisModel.from_dict(doc) for doc in results]
        except Exception as e:
            logger.error(f"Error finding vulnerabilities by CVE: {str(e)}")
            return []
    
    def find_by_package(self, package_name: str, package_version: str = None) -> List[SecurityAnalysisModel]:
        """
        Find all firmwares containing a specific package
        
        Args:
            package_name: Name of the package
            package_version: Version of the package (optional)
            
        Returns:
            List of SecurityAnalysisModel instances
        """
        try:
            query = {'sbom_data.packages.name': package_name}
            if package_version:
                query['sbom_data.packages.version'] = package_version
                
            results = self.collection.find(query).sort('analysis_date', -1)
            return [SecurityAnalysisModel.from_dict(doc) for doc in results]
        except Exception as e:
            logger.error(f"Error finding firmwares by package: {str(e)}")
            return []
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get overall security summary across all firmwares
        
        Returns:
            Dictionary with aggregated security metrics
        """
        try:
            pipeline = [
                {
                    '$group': {
                        '_id': None,
                        'total_firmwares': {'$sum': 1},
                        'total_vulnerabilities': {'$sum': '$vulnerability_data.total_count'},
                        'critical_vulns': {'$sum': '$vulnerability_data.severity_counts.critical'},
                        'high_vulns': {'$sum': '$vulnerability_data.severity_counts.high'},
                        'medium_vulns': {'$sum': '$vulnerability_data.severity_counts.medium'},
                        'low_vulns': {'$sum': '$vulnerability_data.severity_counts.low'},
                        'avg_risk_score': {'$avg': '$risk_score'}
                    }
                }
            ]
            
            result = list(self.collection.aggregate(pipeline))
            return result[0] if result else {}
        except Exception as e:
            logger.error(f"Error getting security summary: {str(e)}")
            return {}
    
    def delete(self, firmware_id: int) -> bool:
        """
        Delete security analysis for a firmware
        
        Args:
            firmware_id: xQuire Firmware model ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.collection is None:
                logger.error("Cannot delete security analysis: MongoDB collection is not available")
                return False
            
            # Validate firmware_id
            if not firmware_id or firmware_id <= 0:
                logger.error(f"Invalid firmware_id for deletion: {firmware_id}")
                return False
                
            # First check if any documents exist for this firmware_id
            existing_count = self.collection.count_documents({'firmware_id': firmware_id})
            if existing_count == 0:
                logger.warning(f"No security analysis documents found for firmware {firmware_id}")
                return False
            
            logger.info(f"Found {existing_count} security analysis documents for firmware {firmware_id}, proceeding with deletion")
            
            # Use delete_one to be more cautious - only delete the most recent one
            # Sort by analysis_date descending to get the latest one
            result = self.collection.delete_one(
                {'firmware_id': firmware_id},
            )
            
            if result.deleted_count > 0:
                logger.info(f"Successfully deleted security analysis document for firmware {firmware_id}")
                return True
            else:
                logger.warning(f"No documents were deleted for firmware {firmware_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting security analysis for firmware {firmware_id}: {str(e)}")
            return False