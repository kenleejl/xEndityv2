# xFormation Module

**Device Emulation Management for xEndity Platform**

xFormation is the firmware emulation module that bridges xScout (firmware extraction) with penguin (device emulation). It manages the entire lifecycle from rootfs.tar.gz files to running emulated device instances.

## Features

### 🔧 Core Functionality
- **Device Discovery**: Automatically discovers firmware extractions from xScout
- **Penguin Integration**: Seamless integration with penguin emulation tool
- **Multi-Instance Management**: Support for up to 5 concurrent emulation instances (configurable)
- **Live Output Monitoring**: Real-time output streaming from emulation instances
- **Web Interface Detection**: Automatic detection and health monitoring of web interfaces
- **Resource Management**: Configurable CPU and memory limits per instance

### 🖥️ User Interface
- **Dashboard View**: Overview of all devices and running instances
- **Device Management**: Initialize, configure, and manage emulated devices
- **Instance Control**: Start, stop, and monitor emulation instances
- **Live Console**: Real-time output viewing with auto-scroll and download capabilities
- **Status Monitoring**: Real-time status updates and health checks

### 🛡️ Honeypot Deployment
- **Package Export**: Export tested emulations as standalone honeypot packages
- **Multi-Platform Support**: Docker containers, cloud deployments, air-gapped systems
- **Intelligence Gathering**: Comprehensive logging and attack pattern analysis
- **Threat Detection**: Real-time monitoring and alerting capabilities

## Installation

### Prerequisites
- Python 3.8+
- Django 3.2+
- penguin emulation tool
- PyYAML (`pip install PyYAML`)
- psutil (`pip install psutil`)
- requests (`pip install requests`)

### Setup
1. Ensure penguin is installed and accessible in PATH
2. Run migrations: `python manage.py migrate`
3. Create superuser: `python manage.py createsuperuser`
4. Configure settings (optional):
   ```python
   # In settings.py
   XFORMATION_MAX_INSTANCES = 5
   XFORMATION_PROJECTS_DIR = '/path/to/projects'
   XFORMATION_LOGS_DIR = '/path/to/logs'
   PENGUIN_COMMAND = 'penguin'  # or full path
   ```

## Usage

### 1. Device Discovery
Devices are automatically discovered from xScout firmware extractions. The system looks for `rootfs.tar.gz` files in:
- `firmwares/Manufacturer/Model/Version/artifacts/rootfs.tar.gz`
- `firmwares/Manufacturer/Model/Version/*_extract/rootfs.tar.gz`

### 2. Device Initialization
1. Navigate to xFormation dashboard
2. Click "Initialize" on an available device
3. Wait for penguin init to complete (2-5 minutes)
4. Device is now ready for emulation

### 3. Running Emulation
1. Click "Run" on an initialized device
2. Configure instance settings (name, CPU, memory)
3. Monitor live output and web interface status
4. Access web interfaces when available

### 4. Instance Management
- **View Live Output**: Real-time console output with auto-scroll
- **Health Monitoring**: Automatic web interface health checks
- **Resource Monitoring**: CPU and memory usage tracking
- **Log Management**: Download full logs for analysis

## API Endpoints

### Device Management
- `GET /xformation/api/device/<id>/status/` - Get device status
- `POST /xformation/device/<id>/initialize/` - Initialize device
- `POST /xformation/device/<id>/start/` - Start instance

### Instance Management
- `GET /xformation/api/instance/<id>/status/` - Get instance status
- `GET /xformation/api/instance/<id>/output/` - Get live output
- `POST /xformation/instance/<id>/stop/` - Stop instance

## Configuration

### Instance Limits
```python
# Maximum concurrent instances
XFORMATION_MAX_INSTANCES = 5

# Default resource limits
XFORMATION_DEFAULT_CPU_LIMIT = 2.0
XFORMATION_DEFAULT_MEMORY_LIMIT = '1g'
```

### Directory Paths
```python
# Penguin projects directory
XFORMATION_PROJECTS_DIR = '/tmp/xformation_projects'

# Instance logs directory
XFORMATION_LOGS_DIR = '/tmp/xformation_logs'
```

### Penguin Configuration
```python
# Penguin command (can be full path)
PENGUIN_COMMAND = 'penguin'
```

## Management Commands

### Cleanup Command
```bash
# Cleanup dead instances and orphaned data
python manage.py xformation_cleanup

# Dry run (show what would be done)
python manage.py xformation_cleanup --dry-run

# Also cleanup old log files
python manage.py xformation_cleanup --cleanup-logs
```

## Architecture

### Models
- **EmulatedDevice**: Represents devices that can be emulated
- **EmulationInstance**: Represents running emulation instances
- **Component**: Legacy model for backward compatibility

### Services
- **DeviceDiscoveryService**: Discovers devices from firmware extractions
- **PenguinIntegrationService**: Handles penguin init/run operations
- **EmulationManagerService**: Manages instance lifecycle and monitoring
- **LiveOutputService**: Handles real-time output streaming

### Templates
- **index.html**: Main dashboard with device overview
- **device_detail.html**: Device configuration and management
- **instance_detail.html**: Live instance monitoring
- **start_instance.html**: Instance configuration form
- **initialize_device.html**: Device initialization interface

## Honeypot Deployment

### Package Generation
Tested emulations can be exported as standalone honeypot packages containing:
- Docker images with penguin runtime
- Configuration files and device profiles
- Deployment scripts for various environments
- Monitoring and logging setup

### Deployment Options
- **Standalone**: Direct Docker deployment
- **Cloud**: AWS ECS/Fargate, Azure Container Instances
- **Kubernetes**: K8s deployments with auto-scaling
- **Air-gapped**: Portable archives for offline deployment

### Intelligence Features
- Network traffic capture
- System call monitoring
- Attack pattern analysis
- Threat intelligence generation

## Troubleshooting

### Common Issues
1. **Penguin not found**: Ensure penguin is installed and in PATH
2. **Initialization fails**: Check rootfs.tar.gz file exists and is valid
3. **Instance won't start**: Verify device is initialized and instance limit not exceeded
4. **Web interface not detected**: Wait for services to start, check penguin output

### Debug Mode
Enable Django debug mode and check logs:
```python
DEBUG = True
LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'modules.xFormation': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is part of the xEndity platform and follows the same license terms.


