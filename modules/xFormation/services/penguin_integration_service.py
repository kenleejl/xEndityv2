"""
Penguin Integration Service for xFormation

Handles penguin init and run operations using Docker API or subprocess
"""

import os
import subprocess
import threading
import logging
import tempfile
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from modules.xFormation.models import EmulatedDevice
from modules.base.utils.ansi_utils import convert_ansi_to_html
from pathlib import Path

logger = logging.getLogger(__name__)

class PenguinIntegrationService:
    """Service for integrating with penguin emulation tool"""
    
    # Configuration
    PENGUIN_COMMAND = getattr(settings, 'PENGUIN_COMMAND', 'penguin')
    USE_DOCKER_API = getattr(settings, 'XFORMATION_USE_DOCKER_API', True)  # Use Docker API by default
    
    @staticmethod
    def initialize_device(device: EmulatedDevice) -> bool:
        """
        Initialize a device using penguin init
        
        Uses Docker API by default, falls back to subprocess if disabled
        
        Args:
            device: EmulatedDevice to initialize
            
        Returns:
            True if successful, False otherwise
        """
        # Route to appropriate implementation
        if PenguinIntegrationService.USE_DOCKER_API:
            return PenguinIntegrationService._initialize_device_docker(device)
        else:
            return PenguinIntegrationService._initialize_device_subprocess(device)
    
    @staticmethod
    def _initialize_device_docker(device: EmulatedDevice) -> bool:
        """
        Initialize a device using Docker API
        
        Args:
            device: EmulatedDevice to initialize
            
        Returns:
            True if successful, False otherwise
        """
        try:
            from .docker_penguin_service import DockerPenguinService
            
            # Update status to initializing
            device.initialization_status = 'initializing'
            device.save()

            firmware_base_path = Path(device.rootfs_path).parent
            
            logger.info(f"Running penguin init via Docker API")
            logger.info(f"Base path: {firmware_base_path}")
            
            # Run penguin init via Docker
            success, stdout, stderr = DockerPenguinService.run_penguin_init(
                firmware_base_path=str(firmware_base_path),
                rootfs_filename='rootfs.tar.gz',
                force=True
            )
            
            # Store the initialization log with ANSI to HTML conversion
            raw_log_content = f"Command: penguin init rootfs.tar.gz --force\n\nOUTPUT:\n{stdout}\n\nERROR:\n{stderr}"
            html_log_content = convert_ansi_to_html(raw_log_content)
            device.initialization_log = html_log_content
            
            if success:
                # Success
                device.initialization_status = 'initialized'
                
                # The actual penguin project is in the rootfs directory
                project_path = firmware_base_path / 'projects' / 'rootfs'
                device.penguin_project_path = str(project_path)
                
                # Check if device.penguin_project_path folder exists
                if not os.path.exists(device.penguin_project_path):
                    logger.error(f"Penguin project path does not exist: {device.penguin_project_path}")
                    device.initialization_status = 'init_failed'
                    error_msg = f"Penguin project path does not exist: {device.penguin_project_path}"
                    device.initialization_log = convert_ansi_to_html(error_msg)
                    device.save()
                    return False
                
                device.config_yaml_path = str(firmware_base_path / 'projects' / 'rootfs' / 'config.yaml')
                
                # Check if device.config_yaml_path file exists
                if not os.path.exists(device.config_yaml_path):
                    logger.error(f"Config yaml path does not exist: {device.config_yaml_path}")
                    device.initialization_status = 'init_failed'
                    error_msg = f"Config yaml path does not exist: {device.config_yaml_path}"
                    device.initialization_log = convert_ansi_to_html(error_msg)
                    device.save()
                    return False
                
                logger.info(f"Successfully initialized device {device.id} via Docker")
                logger.info(f"Penguin project path: {device.penguin_project_path}")
                logger.info(f"Config yaml path: {device.config_yaml_path}")
            else:
                # Failed
                device.initialization_status = 'init_failed'
                logger.error(f"Failed to initialize device {device.id}: {stderr}")
            
            device.save()
            return success
            
        except Exception as e:
            device.initialization_status = 'init_failed'
            error_msg = f"Error during Docker initialization: {str(e)}"
            device.initialization_log = convert_ansi_to_html(error_msg)
            device.save()
            logger.error(f"Error initializing device {device.id} via Docker: {e}")
            return False
    
    @staticmethod
    def _initialize_device_subprocess(device: EmulatedDevice) -> bool:
        """
        Initialize a device using subprocess (legacy method)
        
        Args:
            device: EmulatedDevice to initialize
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Update status to initializing
            device.initialization_status = 'initializing'
            device.save()

            firmware_base_path = Path(device.rootfs_path).parent
            
            # Run penguin init
            cmd = [
                PenguinIntegrationService.PENGUIN_COMMAND,
                'init',
                'rootfs.tar.gz',
                '--force'
            ]
            logger.info(f"Running penguin init via subprocess")
            logger.info(f"CWD: {firmware_base_path}")
            logger.info(f"Command: {' '.join(cmd)}")
            
            # Run the command and capture output
            result = subprocess.run(
                cmd,
                cwd=firmware_base_path,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Store the initialization log with ANSI to HTML conversion
            raw_log_content = f"Command: {' '.join(cmd)}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}\n\nReturn code: {result.returncode}"
            html_log_content = convert_ansi_to_html(raw_log_content)
            device.initialization_log = html_log_content
            
            if result.returncode == 0:
                # Success
                device.initialization_status = 'initialized'
                # The actual penguin project is in the rootfs directory
                
                project_path = firmware_base_path / 'projects' / 'rootfs'
                device.penguin_project_path = str(project_path)
                # Check if device.penguin_project_path folder exists
                if not os.path.exists(device.penguin_project_path):
                    logger.error(f"Penguin project path does not exist: {device.penguin_project_path}")
                    device.initialization_status = 'init_failed'
                    error_msg = f"Penguin project path does not exist: {device.penguin_project_path}"
                    device.initialization_log = convert_ansi_to_html(error_msg)
                    device.save()
                    return False
                
                device.config_yaml_path = str(firmware_base_path / 'projects' / 'rootfs' / 'config.yaml')
                # Check if device.config_yaml_path file exists
                if not os.path.exists(device.config_yaml_path):
                    logger.error(f"Config yaml path does not exist: {device.config_yaml_path}")
                    device.initialization_status = 'init_failed'
                    error_msg = f"Config yaml path does not exist: {device.config_yaml_path}"
                    device.initialization_log = convert_ansi_to_html(error_msg)
                    device.save()
                    return False
                
                logger.info(f"Successfully initialized device {device.id}")
                logger.info(f"Penguin project path: {device.penguin_project_path}")
                logger.info(f"Config yaml path: {device.config_yaml_path}")
            else:
                # Failed
                device.initialization_status = 'init_failed'
                logger.error(f"Failed to initialize device {device.id}: {result.stderr}")
            
            device.save()
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            device.initialization_status = 'init_failed'
            device.initialization_log = convert_ansi_to_html("Initialization timed out after 5 minutes")
            device.save()
            logger.error(f"Penguin init timed out for device {device.id}")
            return False
        except Exception as e:
            device.initialization_status = 'init_failed'
            error_msg = f"Error during initialization: {str(e)}"
            device.initialization_log = convert_ansi_to_html(error_msg)
            device.save()
            logger.error(f"Error initializing device {device.id}: {e}")
            return False
    
    @staticmethod
    def initialize_device_async(device: EmulatedDevice):
        """
        Initialize device asynchronously in a separate thread
        
        Args:
            device: EmulatedDevice to initialize
        """
        def init_worker():
            PenguinIntegrationService.initialize_device(device)
        
        thread = threading.Thread(target=init_worker, daemon=True)
        thread.start()
        logger.info(f"Started async initialization for device {device.id}")
    
    @staticmethod
    def validate_penguin_installation() -> bool:
        """
        Check if penguin is properly installed and accessible
        
        Returns:
            True if penguin is available, False otherwise
        """
        try:
            result = subprocess.run(
                [PenguinIntegrationService.PENGUIN_COMMAND, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"Penguin version: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"Penguin command failed: {result.stderr}")
                return False
                
        except FileNotFoundError:
            logger.error("Penguin command not found. Please ensure penguin is installed and in PATH")
            return False
        except Exception as e:
            logger.error(f"Error checking penguin installation: {e}")
            return False
    
    @staticmethod
    def get_device_config(device: EmulatedDevice) -> dict:
        """
        Read and parse the penguin config for a device
        
        Args:
            device: EmulatedDevice to get config for
            
        Returns:
            Dictionary containing config data, empty dict if error
        """
        try:
            logger.info(f"Config path: {device.config_yaml_path}")
            if not os.path.isfile(device.config_yaml_path):
                logger.warning(f"Config file not found for device {device.id}")
                return {}
            
            try:
                import yaml
            except ImportError:
                logger.error("PyYAML not installed. Please install it: pip install PyYAML")
                return {}
                
            with open(device.config_yaml_path, 'r') as f:
                config = yaml.safe_load(f)
            
            return config or {}
            
        except Exception as e:
            logger.error(f"Error reading config for device {device.id}: {e}")
            return {}
    
    @staticmethod
    def update_device_config(device: EmulatedDevice, config_updates: dict) -> bool:
        """
        Update the penguin config for a device
        
        Args:
            device: EmulatedDevice to update config for
            config_updates: Dictionary of config updates
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.isfile(device.config_yaml_path):
                logger.error(f"Config file not found for device {device.id}")
                return False
            
            try:
                import yaml
            except ImportError:
                logger.error("PyYAML not installed. Please install it: pip install PyYAML")
                return False
            
            # Read current config
            with open(device.config_yaml_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            # Apply updates (deep merge)
            def deep_update(base_dict, update_dict):
                for key, value in update_dict.items():
                    if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                        deep_update(base_dict[key], value)
                    else:
                        base_dict[key] = value
            
            deep_update(config, config_updates)
            
            # Write updated config
            with open(device.config_yaml_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            logger.info(f"Updated config for device {device.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating config for device {device.id}: {e}")
            return False
    
    @staticmethod
    def get_project_status(device: EmulatedDevice) -> dict:
        """
        Get status information about a penguin project
        
        Args:
            device: EmulatedDevice to check status for
            
        Returns:
            Dictionary with status information (paths relative to project root for display)
        """
        from django.conf import settings
        
        status = {
            'project_exists': False,
            'config_exists': False,
            'base_dir_exists': False,
            'project_path': None,
            'config_path': None,
        }
        
        try:
            if device.penguin_project_path and os.path.exists(device.penguin_project_path):
                status['project_exists'] = True
                # Convert absolute project path to relative for display
                status['project_path'] = os.path.relpath(device.penguin_project_path, settings.BASE_DIR)
                
                # Check for config.yaml using the stored path
                if device.config_yaml_path and os.path.exists(device.config_yaml_path):
                    status['config_exists'] = True
                    # Convert absolute config path to relative for display
                    status['config_path'] = os.path.relpath(device.config_yaml_path, settings.BASE_DIR)
                
                # Check for base directory
                base_dir = os.path.join(device.penguin_project_path, 'base')
                if os.path.exists(base_dir):
                    status['base_dir_exists'] = True
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting project status for device {device.id}: {e}")
            return status
