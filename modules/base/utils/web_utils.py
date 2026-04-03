import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import random

logger = logging.getLogger(__name__)

def download_file(url, path, timeout=30, chunk_size=8192, headers=None):
    """
    Download a file from a URL to a specified path
    
    Args:
        url: The URL to download from
        path: The path to save the file to
        timeout: Connection timeout in seconds
        chunk_size: Size of chunks to download at a time
        headers: Custom headers to send with the request
    
    Returns:
        dict: Result with success status and additional info
    """
    # Common browser User-Agents
    user_agents = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'
    
    # Default headers that mimic a browser request
    default_headers = {
        'User-Agent': user_agents,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
        'DNT': '1',  # Do Not Track
    }
    
    # Use custom headers if provided, otherwise use defaults
    request_headers = default_headers
    if headers:
        request_headers.update(headers)
    
    try:
        # Get the domain for the Referer header
        parsed_url = urlparse(url)
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Add referer header from the same domain to avoid anti-scraping measures
        if 'Referer' not in request_headers:
            request_headers['Referer'] = domain
        
        logger.info(f"Downloading file from {url}")
        
        with requests.get(url, stream=True, timeout=timeout, headers=request_headers) as response:
            response.raise_for_status()
            with open(path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
            return {
                'success': True,
                'path': path,
                'content_type': response.headers.get('content-type'),
                'content_length': response.headers.get('content-length'),
            }
    except Exception as e:
        logger.error(f"Error downloading {url}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def get_page_content(url, timeout=30, user_agent=None):
    """
    Get HTML content from a URL
    
    Args:
        url: The URL to fetch
        timeout: Connection timeout in seconds
        user_agent: Custom User-Agent header
    
    Returns:
        BeautifulSoup object or None on error
    """
    headers = {}
    if user_agent:
        headers['User-Agent'] = user_agent
    else:
        headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return None

def extract_links(soup, base_url=None, file_extensions=None):
    """
    Extract links from a BeautifulSoup object
    
    Args:
        soup: BeautifulSoup object
        base_url: Base URL to resolve relative links
        file_extensions: List of file extensions to filter by
    
    Returns:
        list: List of extracted URLs
    """
    if not soup:
        return []
    
    links = []
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        
        # Skip empty hrefs and javascript links
        if not href or href.startswith('javascript:'):
            continue
            
        # Resolve URL if base_url provided
        if base_url:
            href = urljoin(base_url, href)
        
        # Filter by extensions if provided
        if file_extensions:
            if any(href.lower().endswith(ext.lower()) for ext in file_extensions):
                links.append(href)
        else:
            links.append(href)
            
    return links 