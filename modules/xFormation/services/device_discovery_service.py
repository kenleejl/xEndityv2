"""
Device Discovery Service for xFormation

Optimized device discovery that avoids filesystem scanning on every page load
"""

import os
import logging
from django.conf import settings
from django.utils import timezone
from modules.xQuire.models import Firmware
from modules.xFormation.models import EmulatedDevice

logger = logging.getLogger(__name__)

class DeviceDiscoveryService:
    """Optimized service for managing device discovery and rootfs tracking"""
    
    @staticmethod
    def create_device_from_extraction(firmware_id: int, rootfs_path: str) -> EmulatedDevice:
        """
        Called by xScout after successful extraction
        Creates EmulatedDevice immediately when rootfs.tar.gz is found
        
        Args:
            firmware_id: ID of the firmware that was extracted
            rootfs_path: Relative path from project root to the discovered rootfs.tar.gz
            
        Returns:
            EmulatedDevice instance or None if error
        """
        try:
            firmware = Firmware.objects.get(pk=firmware_id)
            
            # Check if device already exists
            existing_device = EmulatedDevice.objects.filter(firmware=firmware).first()
            if existing_device:
                # Update existing device with rootfs info
                existing_device.rootfs_path = rootfs_path
                existing_device.has_rootfs = True
                existing_device.rootfs_discovered_at = timezone.now()
                existing_device.save()
                logger.info(f"Updated existing device with rootfs: {existing_device}")
                return existing_device
            
            # Create device name
            device_name = f"{firmware.model.manufacturer.name} {firmware.model.model_number} v{firmware.version}"
            
            # Create EmulatedDevice with rootfs
            device = EmulatedDevice.objects.create(
                firmware=firmware,
                name=device_name,
                rootfs_path=rootfs_path,
                has_rootfs=True,
                rootfs_discovered_at=timezone.now(),
                initialization_status='not_initialized'
            )
            
            logger.info(f"Created new emulated device with rootfs: {device}")
            return device
            
        except Firmware.DoesNotExist:
            logger.error(f"Firmware {firmware_id} not found")
            return None
        except Exception as e:
            logger.error(f"Error creating device from extraction {firmware_id}: {e}")
            return None
    
    @staticmethod
    def get_all_devices_with_status() -> dict:
        """
        Fast lookup from database - no filesystem operations
        Returns device categorization for the index page
        
        Returns:
            dict: {
                'with_rootfs': [devices_with_rootfs],
                'without_rootfs': [firmware_without_rootfs],
                'total_firmware': count,
                'initialized_devices': [initialized_devices],
                'available_devices': [devices_needing_init],
                'initializing_devices': [devices_initializing],
                'failed_devices': [devices_failed]
            }
        """
        try:
            # Get all devices with rootfs (fast database query)
            devices_with_rootfs = EmulatedDevice.objects.filter(has_rootfs=True).select_related(
                'firmware__model__manufacturer', 'firmware__model__device_type'
            )
            
            # Get firmware IDs that have devices
            firmware_with_devices = set(devices_with_rootfs.values_list('firmware_id', flat=True))
            
            # Get all firmware without EmulatedDevice records (these need scanning)
            firmware_without_devices = Firmware.objects.exclude(
                id__in=firmware_with_devices
            ).select_related('model__manufacturer', 'model__device_type')
            
            # Categorize devices by initialization status
            initialized_devices = [d for d in devices_with_rootfs if d.initialization_status == 'initialized']
            available_devices = [d for d in devices_with_rootfs if d.initialization_status == 'not_initialized']
            initializing_devices = [d for d in devices_with_rootfs if d.initialization_status == 'initializing']
            failed_devices = [d for d in devices_with_rootfs if d.initialization_status == 'init_failed']
            
            total_firmware = Firmware.objects.count()
            
            result = {
                'with_rootfs': list(devices_with_rootfs),
                'without_rootfs': list(firmware_without_devices),
                'total_firmware': total_firmware,
                'initialized_devices': initialized_devices,
                'available_devices': available_devices,
                'initializing_devices': initializing_devices,
                'failed_devices': failed_devices
            }
            
            logger.info(f"Device status: {len(devices_with_rootfs)} with rootfs, {len(firmware_without_devices)} without, {total_firmware} total firmware")
            return result
            
        except Exception as e:
            logger.error(f"Error getting device status: {e}")
            return {
                'with_rootfs': [],
                'without_rootfs': [],
                'total_firmware': 0,
                'initialized_devices': [],
                'available_devices': [],
                'initializing_devices': [],
                'failed_devices': []
            }
    
    @staticmethod
    def scan_all_firmware_for_rootfs() -> dict:
        """
        One-time scan of all firmware to find existing rootfs.tar.gz files
        This should be run as a management command after system setup
        
        Returns:
            dict: {'found': [devices], 'missing': [firmware_ids], 'errors': [error_messages]}
        """
        found_devices = []
        missing_firmware = []
        errors = []
        
        # Get all firmware that don't have EmulatedDevice records yet
        firmware_without_devices = Firmware.objects.exclude(
            id__in=EmulatedDevice.objects.values_list('firmware_id', flat=True)
        )
        
        logger.info(f"Scanning {firmware_without_devices.count()} firmware files for rootfs.tar.gz")
        
        for firmware in firmware_without_devices:
            try:
                rootfs_path = DeviceDiscoveryService._find_rootfs_path(firmware)
                if rootfs_path:
                    device = DeviceDiscoveryService.create_device_from_extraction(firmware.id, rootfs_path)
                    if device:
                        found_devices.append(device)
                else:
                    missing_firmware.append(firmware.id)
                    
            except Exception as e:
                error_msg = f"Error scanning firmware {firmware.id}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        logger.info(f"Scan complete: {len(found_devices)} devices found, {len(missing_firmware)} firmware without rootfs")
        return {
            'found': found_devices,
            'missing': missing_firmware,
            'errors': errors
        }
    
    @staticmethod
    def _find_rootfs_path(firmware: Firmware) -> str:
        """
        Find the rootfs.tar.gz file for a firmware using xScout extraction pattern
        
        Args:
            firmware: Firmware instance
            
        Returns:
            Relative path from project root to rootfs.tar.gz or None if not found
        """
        # Get the firmware file path
        firmware_file_path = firmware.file.path
        firmware_dir = os.path.dirname(firmware_file_path)
        fw_name = os.path.splitext(os.path.basename(firmware_file_path))[0]
        
        # Primary location based on xScout extraction pattern
        extraction_dir = os.path.join(firmware_dir, f"{fw_name}_extract")
        primary_path = os.path.join(extraction_dir, 'rootfs.tar.gz')
        
        if os.path.exists(primary_path):
            relative_path = os.path.relpath(primary_path, settings.BASE_DIR)
            logger.info(f"Found rootfs.tar.gz at primary location: {relative_path}")
            return relative_path
        
        # Fallback locations for compatibility
        fallback_paths = [
            os.path.join(firmware_dir, 'artifacts', 'rootfs.tar.gz'),
            os.path.join(firmware_dir, 'rootfs.tar.gz'),
        ]
        
        for path in fallback_paths:
            if os.path.exists(path):
                relative_path = os.path.relpath(path, settings.BASE_DIR)
                logger.info(f"Found rootfs.tar.gz at fallback location: {relative_path}")
                return relative_path
        
        # Last resort: walk the directory tree
        for root, dirs, files in os.walk(firmware_dir):
            for file in files:
                if file == 'rootfs.tar.gz':
                    full_path = os.path.join(root, file)
                    relative_path = os.path.relpath(full_path, settings.BASE_DIR)
                    logger.info(f"Found rootfs.tar.gz at: {relative_path}")
                    return relative_path
        
        logger.debug(f"No rootfs.tar.gz found in firmware directory: {firmware_dir}")
        return None
    
    @staticmethod
    def refresh_device_status(device: EmulatedDevice) -> EmulatedDevice:
        """
        Refresh the status of a device by checking its files
        
        Args:
            device: EmulatedDevice to refresh
            
        Returns:
            Updated EmulatedDevice
        """
        try:
            # Convert relative path to absolute for file existence check
            if device.rootfs_path.startswith('/'):
                # Handle legacy absolute paths for backward compatibility
                absolute_rootfs_path = device.rootfs_path
            else:
                # Convert relative path to absolute
                absolute_rootfs_path = os.path.join(settings.BASE_DIR, device.rootfs_path)
            
            # Check if rootfs still exists
            if not os.path.exists(absolute_rootfs_path):
                logger.warning(f"Rootfs path no longer exists for device {device.id}: {device.rootfs_path}")
                return device
            
            # Check if penguin project exists and is valid
            if device.penguin_project_path and os.path.exists(device.penguin_project_path):
                config_path = os.path.join(device.penguin_project_path, 'config.yaml')
                if os.path.exists(config_path):
                    device.config_yaml_path = config_path
                    if device.initialization_status == 'not_initialized':
                        device.initialization_status = 'initialized'
                else:
                    device.initialization_status = 'init_failed'
            
            device.save()
            return device
            
        except Exception as e:
            logger.error(f"Error refreshing device status {device.id}: {e}")
            return device


