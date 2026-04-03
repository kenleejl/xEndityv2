import os
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db.models import Q
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import HttpResponse, Http404, JsonResponse
from django.urls import reverse
from django.core.paginator import Paginator
from django.core.cache import cache
import shutil
import threading
import uuid
import tempfile
import time

from .models import DeviceType, Manufacturer, FirmwareModel, Firmware
from .forms import FirmwareUploadForm, FirmwareWebDownloadForm, FirmwareSearchForm
from modules.base.utils.file_utils import calculate_md5, calculate_sha256, get_file_mime_type, sanitize_string
from modules.base.utils.web_utils import download_file
from .utils import process_firmware_archive

logger = logging.getLogger(__name__)

def index(request):
    """Main xQuire dashboard view with integrated search and firmware list"""
    search_form = FirmwareSearchForm(request.GET)
    
    # Start with all firmware
    firmware_queryset = Firmware.objects.all().order_by('-upload_date')
    
    # Apply filters if form is valid
    if search_form.is_valid():
        # Apply search query if provided
        search_query = search_form.cleaned_data.get('search_query')
        if search_query:
            firmware_queryset = firmware_queryset.filter(
                Q(model__manufacturer__name__icontains=search_query) |
                Q(model__model_number__icontains=search_query) |
                Q(model__device_type__name__icontains=search_query) |
                Q(version__icontains=search_query) |
                Q(notes__icontains=search_query)
            )
        
        # Apply additional filters
        filters = search_form.get_filters()
        if filters:
            firmware_queryset = firmware_queryset.filter(**filters)
    
    # Paginate the results
    paginator = Paginator(firmware_queryset, 10)  # Show 10 firmwares per page
    page_number = request.GET.get('page')
    firmware_list = paginator.get_page(page_number)
    
    context = {
        'firmware_count': Firmware.objects.count(),
        'manufacturer_count': Manufacturer.objects.count(),
        'device_type_count': DeviceType.objects.count(),
        'model_count': FirmwareModel.objects.count(),
        'firmware_list': firmware_list,
        'search_form': search_form,
        'manufacturers': Manufacturer.objects.all(),
        'device_types': DeviceType.objects.all(),
    }
    return render(request, 'xquire/index.html', context)

@login_required
def firmware_detail(request, pk):
    """Display details of a specific firmware"""
    firmware = get_object_or_404(Firmware, pk=pk)
    
    # Process extracted assets to create proper download URLs
    extracted_assets_with_urls = []
    if firmware.extracted_assets:
        for asset_path in firmware.extracted_assets:
            # Extract just the filename and create a download URL
            filename = os.path.basename(asset_path)
            from urllib.parse import quote
            encoded_filename = quote(filename)
            download_url = reverse('xquire:serve_firmware_file', args=[encoded_filename])
            extracted_assets_with_urls.append({
                'path': asset_path,
                'filename': filename,
                'download_url': download_url
            })
    
    context = {
        'firmware': firmware,
        'extracted_assets_with_urls': extracted_assets_with_urls
    }
    return render(request, 'xquire/firmware_detail.html', context)

@login_required
def upload_firmware(request):
    """Upload a firmware file manually"""
    if request.method == 'POST':
        form = FirmwareUploadForm(request.POST, request.FILES)
        if form.is_valid():
            # Get form data
            manufacturer = form.cleaned_data['manufacturer']
            device_type = form.cleaned_data['device_type']
            model_number = form.cleaned_data['model_number']
            version = form.cleaned_data['version']
            file = form.cleaned_data['file']
            notes = form.cleaned_data['notes']
            
            # Get or create firmware model
            firmware_model, created = FirmwareModel.objects.get_or_create(
                manufacturer=manufacturer,
                device_type=device_type,
                model_number=model_number,
                defaults={'description': ''}
            )
            
            # Create firmware object
            firmware = Firmware(
                model=firmware_model,
                version=version,
                file=file,
                notes=notes
            )
            
            # Save the firmware object to get the file path
            firmware.save()
            
            # Calculate file size
            firmware.file_size = firmware.file.size
            
            # Calculate hashes using the actual file path in FIRMWARE_ROOT
            manufacturer_name = sanitize_string(manufacturer.name)
            model_number_safe = sanitize_string(model_number, "-_")
            version_safe = sanitize_string(version, ".-_")
            file_path = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number_safe, version_safe, os.path.basename(firmware.file.name))
            firmware.md5 = calculate_md5(file_path)
            firmware.sha256 = calculate_sha256(file_path)
            
            # Check if this is an archive file that needs to be extracted
            file_lower = firmware.file.name.lower()
            is_archive = (file_lower.endswith('.zip') or 
                         file_lower.endswith('.7z') or 
                         file_lower.endswith('.tar') or 
                         file_lower.endswith('.tar.gz') or 
                         file_lower.endswith('.tgz') or 
                         file_lower.endswith('.tar.bz2'))
            
            if is_archive:
                # Process the archive file
                result = process_firmware_archive(firmware, file_path)
                if result['success']:
                    # Save extracted files information
                    if 'extracted_files' in result and result['extracted_files']:
                        firmware.extracted_assets = result['extracted_files']
                else:
                    logger.warning(f"Could not extract archive: {result['message']}")
            
            # Save again with the hash values and extracted files info
            firmware.save()
            
            # Check if this is an AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': f"Firmware '{firmware.model} {firmware.version}' uploaded successfully.",
                    'redirect_url': reverse('xquire:firmware_detail', args=[firmware.pk])
                })
            else:
                messages.success(request, f"Firmware '{firmware.model} {firmware.version}' uploaded successfully.")
                return redirect('xquire:firmware_detail', pk=firmware.pk)
        else:
            # Handle form errors for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                errors = {}
                for field, error_list in form.errors.items():
                    errors[field] = error_list[0] if error_list else ''
                return JsonResponse({
                    'success': False,
                    'errors': errors,
                    'message': 'Please correct the errors below.'
                })
    else:
        form = FirmwareUploadForm()
    
    return render(request, 'xquire/upload_firmware.html', {'form': form})

def download_firmware_background(download_id, url, firmware_model, version, notes, temp_path, filename):
    """Background function to download firmware file"""
    try:
        # Update status to downloading
        cache.set(f'download_{download_id}_status', 'downloading', timeout=3600)
        cache.set(f'download_{download_id}_message', 'Downloading firmware from remote server...', timeout=3600)
        cache.set(f'download_{download_id}_url', url, timeout=3600)
        
        # Download the file
        download_result = download_file(url, temp_path)
        
        if not download_result['success']:
            cache.set(f'download_{download_id}_status', 'failed', timeout=3600)
            cache.set(f'download_{download_id}_error', download_result['error'], timeout=3600)
            return
        
        # Update status to processing
        cache.set(f'download_{download_id}_message', 'Processing downloaded file...', timeout=3600)
        
        # Create the firmware object
        firmware = Firmware(
            model=firmware_model,
            version=version,
            source_url=url,
            notes=notes
        )
        
        # Save the file to our custom storage
        from django.core.files import File
        with open(temp_path, 'rb') as f:
            firmware.file.save(filename, File(f))
        
        # Calculate file size
        firmware.file_size = firmware.file.size
        
        # Calculate hashes using the actual file path in FIRMWARE_ROOT
        manufacturer_name = sanitize_string(firmware_model.manufacturer.name)
        model_number_safe = sanitize_string(firmware_model.model_number, "-_")
        version_safe = sanitize_string(version, ".-_")
        file_path = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number_safe, version_safe, os.path.basename(firmware.file.name))
        firmware.md5 = calculate_md5(file_path)
        firmware.sha256 = calculate_sha256(file_path)
        
        # Check if this is an archive file that needs to be extracted
        file_lower = firmware.file.name.lower()
        is_archive = (file_lower.endswith('.zip') or 
                     file_lower.endswith('.7z') or 
                     file_lower.endswith('.tar') or 
                     file_lower.endswith('.tar.gz') or 
                     file_lower.endswith('.tgz') or 
                     file_lower.endswith('.tar.bz2'))
        
        if is_archive:
            cache.set(f'download_{download_id}_message', 'Extracting archive files...', timeout=3600)
            # Process the archive file
            result = process_firmware_archive(firmware, file_path)
            
            # Save extracted files information
            if result['success'] and 'extracted_files' in result and result['extracted_files']:
                firmware.extracted_assets = result['extracted_files']
        
        # Save the firmware object with hash values and extracted files info
        firmware.save()
        
        # Clean up the temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
        
        # Update status to completed
        cache.set(f'download_{download_id}_status', 'completed', timeout=3600)
        cache.set(f'download_{download_id}_firmware_id', firmware.pk, timeout=3600)
        cache.set(f'download_{download_id}_redirect_url', reverse('xquire:firmware_detail', args=[firmware.pk]), timeout=3600)
        
    except Exception as e:
        logger.error(f"Error downloading firmware: {str(e)}")
        cache.set(f'download_{download_id}_status', 'failed', timeout=3600)
        cache.set(f'download_{download_id}_error', str(e), timeout=3600)
        
        # Clean up the temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)

@login_required
def download_firmware(request):
    """Download firmware from a URL"""
    if request.method == 'POST':
        form = FirmwareWebDownloadForm(request.POST)
        if form.is_valid():
            # Get form data
            manufacturer = form.cleaned_data['manufacturer']
            device_type = form.cleaned_data['device_type']
            model_number = form.cleaned_data['model_number']
            version = form.cleaned_data['version']
            url = form.cleaned_data['url']
            notes = form.cleaned_data['notes']
            
            # Get or create firmware model
            firmware_model, created = FirmwareModel.objects.get_or_create(
                manufacturer=manufacturer,
                device_type=device_type,
                model_number=model_number,
                defaults={'description': ''}
            )
            
            # Check if this is an AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                # Generate download ID
                download_id = str(uuid.uuid4())
                
                # Create a temporary filename
                from urllib.parse import urlparse
                
                # Extract filename from URL or generate one
                url_path = urlparse(url).path
                orig_filename = os.path.basename(url_path)
                if not orig_filename:
                    orig_filename = f"{manufacturer.name}_{model_number}_{version}.bin"
                
                # Create a unique filename
                unique_id = uuid.uuid4().hex[:8]
                filename = f"{manufacturer.name}_{model_number}_{version}_{unique_id}_{orig_filename}"
                
                # Create temporary file path
                temp_dir = tempfile.gettempdir()
                temp_path = os.path.join(temp_dir, filename)
                
                # Initialize download status
                cache.set(f'download_{download_id}_status', 'starting', timeout=3600)
                cache.set(f'download_{download_id}_message', 'Initializing download...', timeout=3600)
                
                # Start background download
                download_thread = threading.Thread(
                    target=download_firmware_background,
                    args=(download_id, url, firmware_model, version, notes, temp_path, filename)
                )
                download_thread.daemon = True
                download_thread.start()
                
                return JsonResponse({
                    'success': True,
                    'download_id': download_id,
                    'message': 'Download started successfully.'
                })
            else:
                # Handle non-AJAX requests (fallback to old behavior)
                # Create a temporary filename
                from urllib.parse import urlparse
                
                # Extract filename from URL or generate one
                url_path = urlparse(url).path
                orig_filename = os.path.basename(url_path)
                if not orig_filename:
                    orig_filename = f"{manufacturer.name}_{model_number}_{version}.bin"
                
                # Create a unique filename
                unique_id = uuid.uuid4().hex[:8]
                filename = f"{manufacturer.name}_{model_number}_{version}_{unique_id}_{orig_filename}"
                
                # Download the file to a temporary location
                temp_dir = tempfile.gettempdir()
                temp_path = os.path.join(temp_dir, filename)
                
                try:
                    # Download the file
                    download_result = download_file(url, temp_path)
                    
                    if not download_result['success']:
                        messages.error(request, f"Failed to download firmware: {download_result['error']}")
                        return render(request, 'xquire/download_firmware.html', {'form': form})
                    
                    # Create the firmware object
                    firmware = Firmware(
                        model=firmware_model,
                        version=version,
                        source_url=url,
                        notes=notes
                    )
                    
                    # Save the file to our custom storage
                    from django.core.files import File
                    with open(temp_path, 'rb') as f:
                        firmware.file.save(filename, File(f))
                    
                    # Calculate file size
                    firmware.file_size = firmware.file.size
                    
                    # Calculate hashes using the actual file path in FIRMWARE_ROOT
                    manufacturer_name = sanitize_string(manufacturer.name)
                    model_number_safe = sanitize_string(model_number, "-_")
                    version_safe = sanitize_string(version, ".-_")
                    file_path = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number_safe, version_safe, os.path.basename(firmware.file.name))
                    firmware.md5 = calculate_md5(file_path)
                    firmware.sha256 = calculate_sha256(file_path)
                    
                    # Check if this is an archive file that needs to be extracted
                    file_lower = firmware.file.name.lower()
                    is_archive = (file_lower.endswith('.zip') or 
                                 file_lower.endswith('.7z') or 
                                 file_lower.endswith('.tar') or 
                                 file_lower.endswith('.tar.gz') or 
                                 file_lower.endswith('.tgz') or 
                                 file_lower.endswith('.tar.bz2'))
                    
                    if is_archive:
                        # Process the archive file
                        result = process_firmware_archive(firmware, file_path)
                        
                        # Save extracted files information
                        if result['success'] and 'extracted_files' in result and result['extracted_files']:
                            firmware.extracted_assets = result['extracted_files']
                            messages.info(request, f"Extracted {len(result['extracted_files'])} files from archive.")
                        elif result['success']:
                            messages.info(request, result['message'])
                        else:
                            messages.warning(request, f"Could not extract archive: {result['message']}")
                    
                    # Save the firmware object with hash values and extracted files info
                    firmware.save()
                    
                    # Clean up the temporary file
                    os.remove(temp_path)
                    
                    messages.success(request, f"Firmware '{firmware.model} {firmware.version}' downloaded successfully.")
                    return redirect('xquire:firmware_detail', pk=firmware.pk)
                    
                except Exception as e:
                    logger.error(f"Error downloading firmware: {str(e)}")
                    messages.error(request, f"Error downloading firmware: {str(e)}")
                    return render(request, 'xquire/download_firmware.html', {'form': form})
        else:
            # Handle form errors for AJAX requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                errors = {}
                for field, error_list in form.errors.items():
                    errors[field] = error_list[0] if error_list else ''
                return JsonResponse({
                    'success': False,
                    'errors': errors,
                    'message': 'Please correct the errors below.'
                })
    else:
        form = FirmwareWebDownloadForm()
    
    return render(request, 'xquire/download_firmware.html', {'form': form})


@login_required
def download_status(request, download_id):
    """Check the status of a download"""
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return JsonResponse({'error': 'AJAX request required'}, status=400)
    
    status = cache.get(f'download_{download_id}_status', 'unknown')
    message = cache.get(f'download_{download_id}_message', '')
    url = cache.get(f'download_{download_id}_url', '')
    error = cache.get(f'download_{download_id}_error', '')
    firmware_id = cache.get(f'download_{download_id}_firmware_id', None)
    redirect_url = cache.get(f'download_{download_id}_redirect_url', '')
    
    response_data = {
        'status': status,
        'message': message,
        'url': url,
    }
    
    if status == 'failed' and error:
        response_data['error'] = error
    elif status == 'completed':
        response_data['firmware_id'] = firmware_id
        response_data['redirect_url'] = redirect_url
        # Clean up cache entries for completed downloads
        cache.delete(f'download_{download_id}_status')
        cache.delete(f'download_{download_id}_message')
        cache.delete(f'download_{download_id}_url')
        cache.delete(f'download_{download_id}_firmware_id')
        cache.delete(f'download_{download_id}_redirect_url')
    
    return JsonResponse(response_data)

def cancel_download(request, download_id):
    """Cancel a download"""
    if request.method != 'POST' or request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return JsonResponse({'error': 'Invalid request'}, status=400)
    
    # Update status to cancelled
    cache.set(f'download_{download_id}_status', 'cancelled', timeout=60)  # Short timeout for cleanup
    
    # Clean up cache entries
    cache.delete(f'download_{download_id}_message')
    cache.delete(f'download_{download_id}_url')
    cache.delete(f'download_{download_id}_error')
    
    return JsonResponse({'success': True, 'message': 'Download cancelled'})

class FirmwareDetailView(DetailView):
    """Detail view for a specific firmware"""
    model = Firmware
    template_name = 'xquire/firmware_detail.html'
    context_object_name = 'firmware'

def scrape_manufacturer_website(request, manufacturer_id):
    """
    Scrape manufacturer website for firmware downloads
    Placeholder for future web scraping functionality
    """
    manufacturer = get_object_or_404(Manufacturer, id=manufacturer_id)
    
    # Placeholder function - to be expanded with proper scraping logic
    messages.info(request, f'Web scraping for {manufacturer.name} not yet implemented')
    return redirect('xquire:index')

@login_required
def serve_firmware_file(request, filename):
    """
    Serve a firmware file from the FIRMWARE_ROOT directory
    This function provides a secure way to serve firmware files with authentication
    """
    # Check if user is authenticated (you may want to add more specific permissions)
    if not request.user.is_authenticated:
        raise Http404("File not found")
    
    # URL decode the filename to handle special characters
    from urllib.parse import unquote
    decoded_filename = unquote(filename)
    
    # Try to find the firmware object by filename
    try:
        firmware = Firmware.objects.get(file__endswith=decoded_filename)
        
        # Get sanitized manufacturer, model and version names
        manufacturer_name = sanitize_string(firmware.model.manufacturer.name)
        model_number = sanitize_string(firmware.model.model_number, "-_")
        version_safe = sanitize_string(firmware.version, ".-_")
        
        # Construct the full path to the file with version
        file_path = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number, version_safe, decoded_filename)
        
        # Check if the file exists
        if not os.path.exists(file_path):
            # Fallback to the old path structure without version
            file_path = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number, decoded_filename)
            if not os.path.exists(file_path):
                # Try the oldest path structure
                file_path = os.path.join(settings.FIRMWARE_ROOT, decoded_filename)
                if not os.path.exists(file_path):
                    raise Http404("File not found")
    except Firmware.DoesNotExist:
        # If we can't find the firmware object, try to find the file directly
        # This is a fallback for files that might have been extracted from archives
        for root, dirs, files in os.walk(settings.FIRMWARE_ROOT):
            if decoded_filename in files:
                file_path = os.path.join(root, decoded_filename)
                break
        else:
            raise Http404("File not found")
    
    # Determine the content type
    content_type = get_file_mime_type(file_path) or 'application/octet-stream'
    
    # Open the file and serve it
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{decoded_filename}"'
        return response

def delete_firmware(request, pk):
    """Delete a firmware file"""
    firmware = get_object_or_404(Firmware, pk=pk)
    
    if request.method == 'POST':
        # Get the file path and directory
        file_path = None
        dir_path = None
        if firmware.file:
            # Get sanitized manufacturer, model and version names
            manufacturer_name = sanitize_string(firmware.model.manufacturer.name)
            model_number = sanitize_string(firmware.model.model_number, "-_")
            version_safe = sanitize_string(firmware.version, ".-_")
            
            # Get paths
            file_name = os.path.basename(firmware.file.name)
            file_path = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number, version_safe, file_name)
            dir_path = os.path.join(settings.FIRMWARE_ROOT, manufacturer_name, model_number, version_safe)
        
        # Delete the firmware object from the database
        firmware_name = str(firmware)
        firmware.delete()
        
        # Delete the physical file if it exists
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                
                # Check if directory is empty and delete if it is
                if dir_path and os.path.exists(dir_path):
                    # Check if directory is empty (except for hidden files)
                    has_visible_files = False
                    for item in os.listdir(dir_path):
                        if not item.startswith('.'):
                            has_visible_files = True
                            break
                    
                    if not has_visible_files:
                        try:
                            # Remove the directory
                            shutil.rmtree(dir_path)
                            logger.info(f"Removed empty directory: {dir_path}")
                        except OSError as e:
                            logger.warning(f"Could not remove directory {dir_path}: {e}")
            except OSError as e:
                logger.error(f"Error deleting firmware file: {e}")
                messages.warning(request, f"The firmware record was deleted, but there was an error deleting the physical file: {e}")
                return redirect('xquire:index')
        
        messages.success(request, f"Firmware '{firmware_name}' was successfully deleted.")
        return redirect('xquire:index')
    
    # If not POST, show confirmation page
    return render(request, 'xquire/firmware_confirm_delete.html', {'firmware': firmware})
