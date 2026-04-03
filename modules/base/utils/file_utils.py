import os
import hashlib
import magic
import shutil
from pathlib import Path
from django.conf import settings

def calculate_md5(file_path):
    """Calculate MD5 hash for a file"""
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        # Read file in chunks to handle large files
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def calculate_sha256(file_path):
    """Calculate SHA256 hash for a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        # Read file in chunks to handle large files
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def get_file_mime_type(file_path):
    """Determine the file's MIME type"""
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except Exception:
        return None

def get_file_type(file_path):
    """Get a human-readable file type description"""
    try:
        mime = magic.Magic()
        return mime.from_file(file_path)
    except Exception:
        return None

def ensure_directory_exists(directory_path):
    """Create directory if it doesn't exist"""
    Path(directory_path).mkdir(parents=True, exist_ok=True)
    return directory_path

def sanitize_string(input_string, allowed_chars=""):
    """
    Sanitize a string by replacing non-alphanumeric characters with underscores.
    
    Args:
        input_string: The string to sanitize
        allowed_chars: Additional characters to allow (besides alphanumeric)
    
    Returns:
        Sanitized string with invalid characters replaced by underscores
    """
    return "".join(c if c.isalnum() or c in allowed_chars else "_" for c in input_string)

def get_storage_path(manufacturer, device_type, model_number, version, filename):
    """Generate storage path for firmware files based on metadata"""
    # Sanitize folder names
    manufacturer_safe = sanitize_string(manufacturer)
    device_type_safe = sanitize_string(device_type)
    model_number_safe = sanitize_string(model_number, "-_")
    version_safe = sanitize_string(version, ".-_")
    
    base_dir = os.path.join(settings.FIRMWARE_ROOT, manufacturer_safe, device_type_safe, model_number_safe, version_safe)
    ensure_directory_exists(base_dir)
    return os.path.join(base_dir, filename) 