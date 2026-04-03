from django.db import models
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
import os
from modules.base.utils.file_utils import sanitize_string
from urllib.parse import quote

# Create your models here.

class DeviceType(models.Model):
    """Type of device (router, switch, camera, etc.)"""
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Device Type"
        verbose_name_plural = "Device Types"
        app_label = "modules_xQuire"

class Manufacturer(models.Model):
    """Manufacturer of devices that use firmware"""
    name = models.CharField(max_length=100)
    website = models.URLField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Manufacturer"
        verbose_name_plural = "Manufacturers"
        app_label = "modules_xQuire"

class FirmwareModel(models.Model):
    """Model of a device that can have firmware"""
    manufacturer = models.ForeignKey(Manufacturer, on_delete=models.CASCADE)
    device_type = models.ForeignKey(DeviceType, on_delete=models.CASCADE)
    model_number = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.manufacturer} {self.model_number}"
    
    class Meta:
        verbose_name = "Firmware Model"
        verbose_name_plural = "Firmware Models"
        app_label = "modules_xQuire"

def firmware_file_path(instance, filename):
    """
    Custom function to determine the file path for firmware files
    This ensures files are saved to FIRMWARE_ROOT
    and organizes files by manufacturer, model, and version
    """
    # Create a path structure: manufacturer/model/version/filename
    manufacturer_name = instance.model.manufacturer.name
    model_number = instance.model.model_number
    version = instance.version
    
    # Sanitize folder names to avoid issues with filesystem
    manufacturer_name = sanitize_string(manufacturer_name)
    model_number = sanitize_string(model_number, "-_")
    version_safe = sanitize_string(version, ".-_")
    
    # Return the relative path within FIRMWARE_ROOT
    return f"{manufacturer_name}/{model_number}/{version_safe}/{filename}"

class Firmware(models.Model):
    """Firmware file and metadata"""
    model = models.ForeignKey(FirmwareModel, on_delete=models.CASCADE)
    version = models.CharField(max_length=50)
    file = models.FileField(upload_to=firmware_file_path, storage=None)  # storage will be set in apps.py
    md5 = models.CharField(max_length=32, blank=True, null=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True)
    file_size = models.BigIntegerField(blank=True, null=True)
    upload_date = models.DateTimeField(auto_now_add=True)
    source_url = models.URLField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    extracted_assets = models.JSONField(blank=True, null=True, help_text="List of files extracted from archive")
    
    def __str__(self):
        return f"{self.model} - {self.version}"
    
    def get_absolute_url(self):
        return reverse('xquire:firmware_detail', args=[str(self.id)])
    
    def get_download_url(self):
        """Get the URL for downloading this firmware file"""
        if self.file:
            # Extract just the filename from the full path
            # The file.name might contain directory paths, so we need to get just the basename
            filename = os.path.basename(str(self.file.name))
            # URL encode the filename to handle special characters
            encoded_filename = quote(filename)
            return reverse('xquire:serve_firmware_file', args=[encoded_filename])
        return None
    
    class Meta:
        verbose_name = "Firmware"
        verbose_name_plural = "Firmwares"
        app_label = "modules_xQuire"
