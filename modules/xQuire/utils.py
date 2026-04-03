import requests
import logging
import os
import re
import hashlib
import shutil
import zipfile
import tarfile
import tempfile
import subprocess
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from django.conf import settings
from django.core.files.base import ContentFile
from modules.base.utils.file_utils import sanitize_string

# Set up logger
logger = logging.getLogger('xquire')

# Import py7zr for handling 7z archives
try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False
    logger.warning("py7zr is not installed. 7z archive support will be limited.")

class WebScraper:
    """
    Base class for scraping firmware from manufacturer websites
    """
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def get_page(self, url):
        """Get page content and parse with BeautifulSoup"""
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
            logger.error(f"Error fetching {url}: {str(e)}")
            return None
    
    def download_file(self, url, path):
        """Download a file from url to path"""
        try:
            response = self.session.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Calculate MD5 hash while downloading
            md5_hash = hashlib.md5()
            with open(path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        md5_hash.update(chunk)
            
            return {
                'success': True,
                'path': path,
                'md5': md5_hash.hexdigest()
            }
        except Exception as e:
            logger.error(f"Error downloading {url}: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

class AsusWebScraper(WebScraper):
    """Class for scraping ASUS firmware"""
    def __init__(self):
        super().__init__('http://files.wl500g.info/asus/')
    
    def get_firmware_list(self):
        """Get list of available firmware files"""
        soup = self.get_page(self.base_url)
        if not soup:
            return []
        
        firmware_files = []
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and (href.endswith('.trx') or href.endswith('.bin') or href.endswith('.img')):
                firmware_files.append({
                    'url': urljoin(self.base_url, href),
                    'filename': href,
                    'model': self._extract_model(href),
                    'version': self._extract_version(href)
                })
        
        return firmware_files
    
    def _extract_model(self, filename):
        """Extract model number from filename"""
        # Try to match ASUS model patterns (e.g. RT-AX88U, GT-AX11000)
        model_pattern = r'(RT-[A-Z0-9]+|GT-[A-Z0-9]+)'
        match = re.search(model_pattern, filename)
        if match:
            return match.group(1)
        return None
    
    def _extract_version(self, filename):
        """Extract version from filename"""
        # Try to match ASUS version pattern (e.g. 3.0.0.4_388_21140)
        version_pattern = r'(\d+\.\d+\.\d+\.\d+[_-]\d+[_-]\d+)'
        match = re.search(version_pattern, filename)
        if match:
            return match.group(1)
        return None

class AxisWebScraper(WebScraper):
    """Class for scraping AXIS firmware"""
    def __init__(self):
        super().__init__('https://www.axis.com/ftp/pub_soft/firmware/')
    
    def get_firmware_list(self):
        """Get list of available firmware files"""
        soup = self.get_page(self.base_url)
        if not soup:
            return []
        
        # This is a placeholder - implementing a proper Axis scraper
        # would require understanding their site structure
        return []

class DLinkWebScraper(WebScraper):
    """Class for scraping D-Link firmware"""
    def __init__(self):
        super().__init__('https://ftp.dlink.ru/pub/Router/')
    
    def get_firmware_list(self):
        """Get list of available firmware files"""
        soup = self.get_page(self.base_url)
        if not soup:
            return []
        
        # This is a placeholder - implementing a proper D-Link scraper
        # would require understanding their site structure
        return []

def get_scraper_for_manufacturer(manufacturer_name):
    """Get the appropriate scraper based on manufacturer name"""
    manufacturer_name = manufacturer_name.lower()
    
    if 'asus' in manufacturer_name:
        return AsusWebScraper()
    elif 'axis' in manufacturer_name:
        return AxisWebScraper()
    elif 'dlink' in manufacturer_name or 'd-link' in manufacturer_name:
        return DLinkWebScraper()
    
    return None

def calculate_md5(file_path):
    """Calculate MD5 hash for a file"""
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        # Read file in chunks to handle large files
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def extract_model_version(filename):
    """Try to extract model and version from filename"""
    # Common patterns for router firmware
    model_patterns = [
        r'(RT-[A-Z0-9]+)',  # ASUS routers
        r'(DIR-[0-9]+)',    # D-Link routers
        r'(WRT[0-9]+)',     # Linksys routers
        r'([A-Z0-9]+-[A-Z0-9]+)' # Generic pattern
    ]
    
    version_patterns = [
        r'_(\d+\.\d+\.\d+\.\d+)_',  # ASUS style: 3.0.0.4
        r'_v(\d+\.\d+\.\d+)',       # Common style: v1.2.3
        r'_([0-9]+\.[0-9]+)',       # Simple style: 1.0
        r'-([0-9]+\.[0-9]+)'        # Dash style: -1.0
    ]
    
    model = None
    for pattern in model_patterns:
        match = re.search(pattern, filename)
        if match:
            model = match.group(1)
            break
    
    version = None
    for pattern in version_patterns:
        match = re.search(pattern, filename)
        if match:
            version = match.group(1)
            break
    
    return model, version

def extract_archive(archive_path, extract_dir):
    """
    Extract an archive file (zip, tar, tar.gz, etc.) to the specified directory
    
    Args:
        archive_path: Path to the archive file
        extract_dir: Directory to extract files to
    
    Returns:
        dict: Result with success status and additional info
    """
    try:
        # Create the extraction directory if it doesn't exist
        os.makedirs(extract_dir, exist_ok=True)
        
        # Get the file extension
        file_lower = archive_path.lower()
        _, ext = os.path.splitext(file_lower)
        
        # Handle .zip files
        if ext == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # Validate all paths before extraction to prevent path traversal attacks
                extract_dir_abs = os.path.abspath(extract_dir)
                for member in zip_ref.namelist():
                    # Skip directories
                    if member.endswith('/'):
                        continue
                    
                    # Normalize the member path to prevent directory traversal
                    # Remove leading slashes and resolve any relative path components
                    normalized_member = os.path.normpath(member.lstrip('/'))
                    
                    # Check for dangerous path components
                    if '..' in normalized_member.split(os.sep) or normalized_member.startswith('/'):
                        logger.error(f"Potentially unsafe path in ZIP archive: {member}")
                        return {'success': False, 'message': f'Potentially unsafe path in ZIP archive: {member}'}
                    
                    # Construct the full member path
                    member_path = os.path.join(extract_dir, normalized_member)
                    member_path_abs = os.path.abspath(member_path)
                    
                    # Ensure the resolved path is within the extraction directory
                    try:
                        os.path.relpath(member_path_abs, extract_dir_abs)
                        if not member_path_abs.startswith(extract_dir_abs + os.sep) and member_path_abs != extract_dir_abs:
                            logger.error(f"Path traversal attempt detected in ZIP archive: {member}")
                            return {'success': False, 'message': f'Path traversal attempt detected in ZIP archive: {member}'}
                    except ValueError:
                        # relpath raises ValueError if paths are on different drives (Windows)
                        logger.error(f"Invalid path in ZIP archive: {member}")
                        return {'success': False, 'message': f'Invalid path in ZIP archive: {member}'}
                
                # Extract files one by one with safe path handling
                for member in zip_ref.namelist():
                    if not member.endswith('/'):  # Skip directories, they'll be created automatically
                        normalized_member = os.path.normpath(member.lstrip('/'))
                        if '..' not in normalized_member.split(os.sep) and not normalized_member.startswith('/'):
                            safe_path = os.path.join(extract_dir, normalized_member)
                            # Create parent directories if they don't exist
                            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                            # Extract the file
                            with zip_ref.open(member) as source, open(safe_path, 'wb') as target:
                                shutil.copyfileobj(source, target)
            return {'success': True, 'message': 'ZIP file extracted successfully'}
        
        # Handle .tar, .tar.gz, .tgz, .tar.bz2, etc.
        elif ext in ['.tar', '.tgz'] or file_lower.endswith('.tar.gz') or file_lower.endswith('.tar.bz2'):
            with tarfile.open(archive_path) as tar_ref:
                extract_dir_abs = os.path.abspath(extract_dir)
                
                # Validate all paths before extraction to prevent path traversal attacks
                for member in tar_ref.getmembers():
                    # Skip if it's a directory (will be created automatically)
                    if member.isdir():
                        continue
                    
                    # Normalize the member path
                    normalized_name = os.path.normpath(member.name.lstrip('/'))
                    
                    # Check for dangerous path components
                    if '..' in normalized_name.split(os.sep) or normalized_name.startswith('/') or member.name.startswith('/'):
                        logger.error(f"Potentially unsafe path in TAR archive: {member.name}")
                        return {'success': False, 'message': f'Potentially unsafe path in TAR archive: {member.name}'}
                    
                    # Construct the full member path and check it's within extraction directory
                    member_path = os.path.join(extract_dir, normalized_name)
                    member_path_abs = os.path.abspath(member_path)
                    
                    if not member_path_abs.startswith(extract_dir_abs + os.sep) and member_path_abs != extract_dir_abs:
                        logger.error(f"Path traversal attempt detected in TAR archive: {member.name}")
                        return {'success': False, 'message': f'Path traversal attempt detected in TAR archive: {member.name}'}
                
                # Use safe extraction
                def safe_extract(tar, path=".", members=None):
                    """Safely extract tar members to prevent path traversal"""
                    for member in tar.getmembers():
                        if member.isdir():
                            continue
                        normalized_name = os.path.normpath(member.name.lstrip('/'))
                        if '..' not in normalized_name.split(os.sep) and not normalized_name.startswith('/'):
                            member.name = normalized_name  # Update the member name to the safe path
                            tar.extract(member, path)
                
                safe_extract(tar_ref, extract_dir)
            return {'success': True, 'message': 'TAR file extracted successfully'}
        
        # Handle .7z files using py7zr if available
        elif ext == '.7z':
            if PY7ZR_AVAILABLE:
                with py7zr.SevenZipFile(archive_path, mode='r') as z:
                    extract_dir_abs = os.path.abspath(extract_dir)
                    
                    # Get list of files and validate paths before extraction
                    for info in z.list():
                        filename = info.filename
                        
                        # Skip directories
                        if filename.endswith('/'):
                            continue
                            
                        # Normalize the path
                        normalized_name = os.path.normpath(filename.lstrip('/'))
                        
                        # Check for dangerous path components
                        if '..' in normalized_name.split(os.sep) or normalized_name.startswith('/'):
                            logger.error(f"Potentially unsafe path in 7z archive: {filename}")
                            return {'success': False, 'message': f'Potentially unsafe path in 7z archive: {filename}'}
                        
                        # Verify the path stays within extraction directory
                        member_path = os.path.join(extract_dir, normalized_name)
                        member_path_abs = os.path.abspath(member_path)
                        
                        if not member_path_abs.startswith(extract_dir_abs + os.sep) and member_path_abs != extract_dir_abs:
                            logger.error(f"Path traversal attempt detected in 7z archive: {filename}")
                            return {'success': False, 'message': f'Path traversal attempt detected in 7z archive: {filename}'}
                    
                    # Safe extraction using py7zr
                    z.extractall(extract_dir)
                return {'success': True, 'message': '7z file extracted successfully using py7zr'}
            else:
                # Fallback to command line if py7zr is not available
                # Note: Command line 7z extraction may be vulnerable to path traversal
                # It's recommended to install py7zr for safer extraction
                logger.warning("Using command line 7z extraction - path traversal protection is limited")
                try:
                    result = subprocess.run(['7z', 'x', '-o' + extract_dir, archive_path], 
                                          capture_output=True, text=True, check=True)
                    return {'success': True, 'message': '7z file extracted successfully using 7z command (limited path traversal protection)'}
                except subprocess.CalledProcessError as e:
                    return {'success': False, 'message': f'Error extracting 7z file: {e.stderr}'}
                except FileNotFoundError:
                    return {'success': False, 'message': '7z command not found and py7zr not installed. Please install py7zr with pip.'}
        
        # Unsupported archive type
        else:
            return {'success': False, 'message': f'Unsupported archive type: {ext}'}
            
    except Exception as e:
        logger.error(f"Error extracting archive {archive_path}: {str(e)}")
        return {'success': False, 'message': str(e)}

def process_firmware_archive(firmware, archive_path):
    """
    Process a firmware archive file:
    1. Extract the archive to a temporary directory
    2. Move all extracted files to the firmware directory
    3. Update the firmware record with the extracted files
    
    Args:
        firmware: Firmware model instance
        archive_path: Path to the archive file
    
    Returns:
        dict: Result with success status and additional info
    """
    try:
        # Get the target directory for this firmware
        manufacturer_name = sanitize_string(firmware.model.manufacturer.name)
        model_number = sanitize_string(firmware.model.model_number, "-_")
        version_safe = sanitize_string(firmware.version, ".-_")
        firmware_dir = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number, version_safe)
        
        # Create a temporary directory for extraction
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract the archive
            extract_result = extract_archive(archive_path, temp_dir)
            if not extract_result['success']:
                return extract_result
            
            # Create the firmware directory if it doesn't exist
            os.makedirs(firmware_dir, exist_ok=True)
            
            # Move all extracted files to the firmware directory
            extracted_files = []
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    src_file = os.path.join(root, file)
                    # Get the relative path from the temp_dir
                    rel_path = os.path.relpath(src_file, temp_dir)
                    # Create the destination path
                    dst_file = os.path.join(firmware_dir, rel_path)
                    # Create parent directories if needed
                    os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                    # Move the file
                    shutil.copy2(src_file, dst_file)
                    extracted_files.append(rel_path)
        
        return {
            'success': True, 
            'message': f'Archive processed successfully. Extracted {len(extracted_files)} files.',
            'extracted_files': extracted_files
        }
    
    except Exception as e:
        logger.error(f"Error processing firmware archive {archive_path}: {str(e)}")
        return {'success': False, 'message': str(e)} 