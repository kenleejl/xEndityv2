from django.apps import AppConfig


class XQuireConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'modules.xQuire'
    label = 'modules_xQuire'
    verbose_name = 'xQuire - Firmware Management'
    
    def ready(self):
        """
        Set up the custom storage for the Firmware model
        """
        from .storage import FirmwareStorage
        from .models import Firmware
        
        # Set the storage on the FileField
        Firmware._meta.get_field('file').storage = FirmwareStorage()
