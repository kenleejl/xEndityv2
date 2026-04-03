# xEndity Platform

xEndity is a modular platform for firmware management, analysis, and security research, with separate modules for different functions:

- **xQuire**: Downloading, indexing and managing firmware files
- **xScout**: Firmware analysis and vulnerability scanning
- **xFormation**: Firmware composition analysis

## Project Architecture

The xEndity platform is built with a modular architecture:

```
xEndity/
├── xendity/                # Main Django project settings
├── modules/                # Core functionality modules
│   ├── base/               # Shared utilities and common functions
│   │   └── utils/          # Utility functions (file, web, database)
│   ├── xQuire/             # Firmware download and management
│   │   ├── migrations/     # Database migrations
│   │   ├── templates/      # Module-specific templates
│   │   ├── models.py       # Data models
│   │   ├── views.py        # View functions
│   │   ├── urls.py         # URL routing
│   │   ├── forms.py        # Form definitions
│   │   ├── admin.py        # Admin interface
│   │   └── utils.py        # Module-specific utilities
│   ├── xScout/             # Firmware analysis (future)
│   ├── xFormation/         # Firmware composition analysis (future)
│   └── xfs/                # Firmware extraction tool (submodule)
│       ├── src/            # Rust source code
│       ├── utils/          # Utility scripts
│       ├── Dockerfile      # Docker build configuration
│       └── xfs             # Wrapper script
├── templates/              # Main templates
│   ├── base.html           # Base template with navigation
│   ├── home.html           # Home page
│   ├── dashboard.html      # Admin dashboard
│   └── registration/       # Authentication templates
├── static/                 # Static files (CSS, JS, etc.)
├── media/                  # User uploaded content
├── firmwares/              # Firmware storage directory
└── venv/                   # Virtual environment
```

## Installation

### Prerequisites

- Python 3.8+
- Docker and Docker Compose (for MongoDB and xfs)
- Virtual environment (recommended)
- python-magic library dependencies (for file type detection)
- Rust (optional, only if building xfs from source without Docker)

### Setup Instructions

1. Clone the repository with submodules:
   ```bash
   git clone --recurse-submodules https://github.com/kenleejl/xEndity.git
   cd xEndity
   ```
   
   If you've already cloned the repository without submodules, you can initialize and update them with:
   ```bash
   git submodule update --init --recursive
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Start MongoDB using Docker:
   ```bash
   docker compose up -d
   ```

5. Set up the database:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

7. Run the development server:
   ```bash
   python manage.py runserver
   ```

8. Access the application at http://127.0.0.1:8000/


### Docker Compose Configuration

Build fwbinary-analysis
```bash
docker compose build fwbinary-analysis
```

The `docker-compose.yml` file sets up MongoDB:
```bash
docker compose up -d
```

If your CPU doesn't support AVX instructions, change proxmox CPU to x86-64-v3

### Building and Installing xfs

The xfs module (Firmware to Root Filesystem Extractor) is included as a submodule and requires additional setup:

#### Option 1: Using Pre-built Docker Image (Not implemented yet)

1. Pull the pre-built Docker image:
   ```bash
   docker pull xendity/xfs:latest
   ```

2. Install the wrapper script:
   ```bash
   #System-wide Installation: This makes the xfs command available to all users:
   $ docker run rehosting/xfs xfs_install | sudo sh

   #Local Installation: This makes xfs command available to your user
   $ docker run rehosting/xfs xfs_install.local | sh
   ```
   
   Follow the instructions provided by the command to install either system-wide or for your individual user.

#### Option 2: Building from Source

1. Navigate to the xfs directory:
   ```bash
   cd modules/xfs
   ```

2. Build the Docker container:
   ```bash
   ./xfs --build
   ```
   
   Or manually with:
   ```bash
   docker build -t xendity/xfs .
   ```

3. (Optional) Install the wrapper script:
   ```bash
   ./xfs --install
   ```
   
   This will provide instructions for installing system-wide or for your individual user.

#### Using xfs

Once installed, you can extract firmware with:
```bash
xfs /path/to/your/firmware.bin
```

This will generate:
- `./rootfs.tar.gz`: Compressed archive of the root filesystem
- `./xfs-extract/`: Directory containing all extracted files
- When using `--copy-rootfs`: `./rootfs/`: Copy of the identified root filesystem
## Authentication System

xEndity uses Django's built-in authentication system with custom templates:

- Login: `/accounts/login/`
- Logout: `/accounts/logout/`
- Password Reset: `/accounts/password_reset/`

Protected views are secured with the `@login_required` decorator.

## Modules

### xQuire Module

- Upload firmware files manually
- Download firmware from URLs
- Automatic firmware categorization and metadata extraction
- Search and browse firmware by manufacturer, device type, and model
- Web scraping capabilities for automatic firmware discovery
- MD5 and SHA256 hash calculation for firmware integrity verification

### xScout Module
- Firmware Binary analysis
- Firmware extraction
- Firmware Componenets Identification
- Firmware Components Analysis
- Vulnerability scanning
- Security reporting

#### xfs (xScout sub-module)
- Firmware image extraction
- Root filesystem identification
- Archive creation for analysis
- Unprivileged operation
- Docker-based execution environment
- Integration with xEndity analysis pipeline

### xFormation Module (Coming Soon)
- Firmware Emulation
- Emulation validation
- Emulation packaging and isolation
- Emulation Network Configurations


## Database Structure

xEndity uses a hybrid database approach:

- **SQLite**: Used by Django for user authentication, sessions, and basic models
- **MongoDB**: Used for storing firmware metadata, analysis results, and other unstructured data

### Key Models

- **Manufacturer**: Firmware manufacturers
- **DeviceType**: Types of devices (router, camera, etc.)
- **FirmwareModel**: Device models that can have firmware
- **Firmware**: The actual firmware files with metadata

## API Reference

The platform provides several utility functions:

- **File Utilities**: Hash calculation, file type detection
- **Web Utilities**: URL downloading, web scraping
- **Database Utilities**: MongoDB connection handling

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
