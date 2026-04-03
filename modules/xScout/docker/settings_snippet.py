# MongoDB settings for xScout firmware analysis
# Add this to your Django settings.py file

# MongoDB connection settings
MONGODB_HOST = os.environ.get('MONGODB_HOST', 'localhost')
MONGODB_PORT = int(os.environ.get('MONGODB_PORT', '27017'))
MONGODB_DB = os.environ.get('MONGODB_DB', 'xendity')
MONGODB_USER = os.environ.get('MONGODB_USER', '')
MONGODB_PASSWORD = os.environ.get('MONGODB_PASSWORD', '')
MONGODB_AUTH_SOURCE = os.environ.get('MONGODB_AUTH_SOURCE', 'admin')

# Docker settings
XSCOUT_USE_DOCKER = os.environ.get('XSCOUT_USE_DOCKER', 'true').lower() == 'true'
XSCOUT_DOCKER_IMAGE = os.environ.get('XSCOUT_DOCKER_IMAGE', 'xendity/firmware-analysis')

# Firmware analysis settings
FIRMWARE_UPLOAD_DIR = os.path.join(MEDIA_ROOT, 'firmware')
os.makedirs(FIRMWARE_UPLOAD_DIR, exist_ok=True) 