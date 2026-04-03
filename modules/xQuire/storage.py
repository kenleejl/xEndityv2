import os
from django.core.files.storage import FileSystemStorage
from django.conf import settings

class FirmwareStorage(FileSystemStorage):
    """
    Custom storage class for firmware files that uses FIRMWARE_ROOT
    """
    def __init__(self, *args, **kwargs):
        kwargs['location'] = settings.FIRMWARE_ROOT
        # Create the directory if it doesn't exist
        os.makedirs(settings.FIRMWARE_ROOT, exist_ok=True)
        super().__init__(*args, **kwargs)
    
    def url(self, name):
        """
        Return a URL for accessing the file via the web.
        For security reasons, we might want to implement more secure access methods
        for firmware files rather than direct URLs.
        """
        # This is a simplified implementation - in production you might want
        # to implement a more secure way to serve these files
        return f"/firmwares/{name}" 