import logging
from pymongo import MongoClient
from django.conf import settings

logger = logging.getLogger(__name__)

class MongoDBConnection:
    """MongoDB connection handler"""
    
    _instance = None
    _client = None
    _db = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one connection is created"""
        if cls._instance is None:
            cls._instance = super(MongoDBConnection, cls).__new__(cls)
            try:
                # Get MongoDB settings from Django settings
                mongodb_settings = settings.MONGODB_CLIENT
                cls._client = MongoClient(
                    host=mongodb_settings.get('host', 'localhost'),
                    port=mongodb_settings.get('port', 27017)
                )
                cls._db = cls._client[mongodb_settings.get('db', 'xendity_firmwares')]
                # logger.info("MongoDB connection established")
            except Exception as e:
                logger.error(f"Failed to connect to MongoDB: {str(e)}")
                cls._client = None
                cls._db = None
        return cls._instance
    
    @property
    def db(self):
        """Get the MongoDB database instance"""
        return self._db
    
    @property
    def client(self):
        """Get the MongoDB client instance"""
        return self._client
    
    @property
    def is_connected(self):
        """Check if the MongoDB connection is available"""
        return self._db is not None and self._client is not None
    
    def get_collection(self, collection_name):
        """Get a MongoDB collection by name"""
        if self._db is None:
            logger.error("MongoDB connection not available")
            return None
        return self._db[collection_name]
    
    def close(self):
        """Close the MongoDB connection"""
        if self._client is not None:
            self._client.close()
            logger.info("MongoDB connection closed")


def save_firmware_metadata(metadata):
    """
    Save firmware metadata to MongoDB
    
    Args:
        metadata: Dictionary with firmware metadata
    
    Returns:
        str: MongoDB ObjectID or None on error
    """
    try:
        conn = MongoDBConnection()
        firmwares_collection = conn.get_collection('firmwares')
        if firmwares_collection is None:
            return None
            
        result = firmwares_collection.insert_one(metadata)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error saving firmware metadata: {str(e)}")
        return None


def get_firmware_by_hash(hash_value, hash_type='md5'):
    """
    Get firmware by its hash value
    
    Args:
        hash_value: The hash value to look for
        hash_type: Type of hash (md5, sha256, etc.)
    
    Returns:
        dict: Firmware metadata or None if not found
    """
    try:
        conn = MongoDBConnection()
        firmwares_collection = conn.get_collection('firmwares')
        if firmwares_collection is None:
            return None
            
        query = {f"hashes.{hash_type}": hash_value}
        return firmwares_collection.find_one(query)
    except Exception as e:
        logger.error(f"Error searching firmware by hash: {str(e)}")
        return None 