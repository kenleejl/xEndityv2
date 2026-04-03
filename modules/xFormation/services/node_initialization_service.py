"""
Node Initialization Service for xFormation

Orchestrates the complete device initialization pipeline
"""

import os
import logging
import yaml
from pathlib import Path
from typing import Optional, Dict
from modules.xFormation.models import EmulatedDevice
from modules.xFormation.services.penguin_integration_service import PenguinIntegrationService
from modules.xFormation.services.rootfs_modification_service import RootfsModificationService
from modules.xFormation.services.macvlan_network_service import MacvlanNetworkService
from modules.xFormation.services.kernel_version_service import KernelVersionService
from modules.xScout.services.components_analysis_service import ComponentsAnalysisService

logger = logging.getLogger(__name__)

# Known Linux device nodes that must never be created as directories.
# If any of these appear as parent paths in pseudofiles, those child entries
# are removed. Extend this list as new device node issues are encountered.
KNOWN_DEVICE_NODES = [
    '/dev/null',
    '/dev/zero',
    '/dev/random',
    '/dev/urandom',
    '/dev/console',
    '/dev/tty',
]


class NodeInitializationService:
    """Service for orchestrating device initialization"""
    
    # Path to default configuration file
    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / 'node-emulation-config.yaml'
    
    @staticmethod
    def load_default_config() -> Dict:
        """
        Load default configuration from node-emulation-config.yaml
        
        Returns:
            Dictionary with default configuration
        """
        try:
            if NodeInitializationService.DEFAULT_CONFIG_PATH.exists():
                with open(NodeInitializationService.DEFAULT_CONFIG_PATH, 'r') as f:
                    config = yaml.safe_load(f) or {}
                logger.info(f"Loaded default config from {NodeInitializationService.DEFAULT_CONFIG_PATH}")
                return config
            else:
                logger.warning(f"Default config not found at {NodeInitializationService.DEFAULT_CONFIG_PATH}")
                return {}
        except Exception as e:
            logger.error(f"Failed to load default config: {e}")
            return {}
    
    @staticmethod
    def initialize_device(device: EmulatedDevice, user_config: Optional[Dict] = None) -> Dict:
        """
        Initialize device with automatic configuration
        
        Args:
            device: EmulatedDevice to initialize
            user_config: Optional user configuration dictionary
            
        Returns:
            Dictionary with 'success' (bool), 'message' (str), and 'logs' (list)
        """
        logs = []
        
        try:
            logs.append("Starting device initialization...")
            
            # Step 0: Load xScout analysis results for firmware intelligence
            logs.append("[0/8] Loading xScout analysis results...")
            scout_analysis = None
            hash_type = None
            ssh_implementation = None
            
            try:
                scout_service = ComponentsAnalysisService()
                scout_analysis = scout_service.get_analysis_results(device.firmware.id)
                
                if scout_analysis:
                    # Extract hash type: prefer authoritative hash_algo (Phase 6 ELF detection);
                    # fall back to root_hash_type for backward compat with older xScout JSON files.
                    user_accounts = scout_analysis.get('user_accounts', {})
                    hash_type = user_accounts.get('hash_algo') or user_accounts.get('root_hash_type')
                    if hash_type:
                        detection_method = user_accounts.get('hash_detection_method', '')
                        method_note = f" (via {detection_method})" if detection_method else ""
                        logs.append(f"✓ Detected password hash type: {hash_type.upper()}{method_note}")
                    else:
                        logs.append("⚠ No hash type detected, will use default (MD5)")
                    
                    # Extract SSH service implementation
                    ssh_service = scout_analysis.get('ssh_service', {})
                    ssh_implementation = ssh_service.get('implementation')
                    if ssh_implementation and ssh_implementation != 'unknown':
                        logs.append(f"✓ Detected SSH service: {ssh_implementation}")
                    else:
                        logs.append("⚠ SSH service unknown, will attempt auto-detection")
                else:
                    logs.append("⚠ xScout analysis not found - proceeding with defaults")
            except Exception as e:
                logger.warning(f"Could not load xScout analysis: {e}")
                logs.append(f"⚠ xScout analysis unavailable: {str(e)}")
            
            # Step 1: Run penguin init
            logs.append("[1/8] Running penguin init...")
            success = PenguinIntegrationService.initialize_device(device)
            if not success:
                return {
                    'success': False,
                    'message': 'Penguin init failed',
                    'logs': logs + ['Check device initialization_log for details']
                }
            logs.append("✓ Penguin init completed")
            
            # Reload device to get updated paths
            device.refresh_from_db()
            
            if not device.penguin_project_path or not os.path.exists(device.penguin_project_path):
                return {
                    'success': False,
                    'message': f'Penguin project path not found: {device.penguin_project_path}',
                    'logs': logs
                }
            
            # Step 2: Patch kernel version in base.yaml from xScout analysis
            logs.append("[2/8] Patching kernel version in base.yaml...")
            kernel_version, kernel_reason = KernelVersionService.determine_kernel_version(scout_analysis)
            if NodeInitializationService.patch_kernel_version(device.penguin_project_path, kernel_version):
                logs.append(f"✓ Kernel version set to {kernel_version}")
                logs.append(f"  └─ {kernel_reason}")
            else:
                logs.append("⚠ Kernel version patch failed")

            # Step 3: Fix broken device files
            logs.append("[3/8] Fixing broken device nodes...")
            if NodeInitializationService.fix_broken_device_files(device.penguin_project_path):
                logs.append("✓ Device files fixed")
            else:
                logs.append("⚠ Device files fix skipped or failed")

            # Step 4: Disable auto-shutdown
            logs.append("[4/8] Disabling auto-shutdown in manual.yaml...")
            if NodeInitializationService.disable_auto_shutdown(device.penguin_project_path):
                logs.append("✓ Auto-shutdown disabled")
            else:
                logs.append("⚠ Auto-shutdown disable failed")
            
            # Step 5: Setup SSH access (using xScout intelligence)
            logs.append("[5/8] Setting up SSH access...")
            password = 'root'  # default
            if user_config and 'credentials' in user_config:
                password = user_config['credentials'].get('password', 'root')
            
            rootfs_path = os.path.join(device.penguin_project_path, 'base/fs.tar.gz')
            if os.path.exists(rootfs_path):
                # Pass xScout intelligence to rootfs manipulation
                if RootfsModificationService.setup_management_access(
                    rootfs_path=rootfs_path,
                    username='root',
                    password=password,
                    hash_type=hash_type,  # From xScout
                    ssh_implementation=ssh_implementation  # From xScout
                ):
                    logs.append(f"✓ SSH configured with password: {password}")
                    if hash_type:
                        logs.append(f"  └─ Using {hash_type.upper()} hash (from xScout)")
                    if ssh_implementation:
                        logs.append(f"  └─ Configured {ssh_implementation} (from xScout)")
                else:
                    logs.append("⚠ SSH setup failed")
            else:
                logs.append(f"⚠ Rootfs not found at {rootfs_path}")
            
            # Step 6: Enable telemetry (always with default or custom filter)
            logs.append("[6/8] Enabling telemetry...")
            strace_filter = 'execve'  # default
            if user_config and 'telemetry' in user_config:
                if user_config['telemetry'].get('enabled', True):
                    strace_filter = user_config['telemetry'].get('strace_filter', 'execve')
            
            if RootfsModificationService.setup_telemetry_collection(device.penguin_project_path, strace_filter):
                logs.append(f"✓ Telemetry enabled (filter: {strace_filter})")
            else:
                logs.append("⚠ Telemetry setup failed")
            
            # Step 7: Create init stub (always, with optional custom script)
            logs.append("[7/8] Creating init stub...")
            custom_script_path = None
            if user_config and 'custom_init_path' in user_config:
                custom_script_path = user_config['custom_init_path']
            
            # Read injection mode fields from user_config (set by config_form POST)
            init_mode = user_config.get('init_mode', 'partial_stub') if user_config else 'partial_stub'
            stub_path = user_config.get('stub_path', '/igloo/custom_init.sh') if user_config else '/igloo/custom_init.sh'
            wrapper_original_path = (
                user_config.get('wrapper_original_path', '') or ''
            ) if user_config else ''

            if RootfsModificationService.create_init_stub(
                rootfs_path,
                device.penguin_project_path,
                custom_script_path,
                init_mode=init_mode,
                stub_path=stub_path,
                wrapper_original_path=wrapper_original_path or None
            ):
                if custom_script_path:
                    logs.append(f"✓ Init stub created with custom script ({init_mode})")
                else:
                    logs.append("✓ Init stub created")
            else:
                logs.append("⚠ Init stub creation failed or skipped")
            
            # Step 7: Setup SLIRP interface isolation (provides outbound connectivity)
            logs.append("[7/8] Setting up SLIRP interface isolation...")
            network_config = None
            if user_config and 'network' in user_config:
                network_config = user_config['network']

            # Get gateway for NAT routing
            gateway = '192.168.1.1'  # default
            if network_config:
                gateway = network_config.get('gateway', '192.168.1.1')

            if RootfsModificationService.setup_network_nat(device.penguin_project_path, gateway):
                logs.append("✓ SLIRP interface isolation configured")
                logs.append("  └─ Interface: slirp0 (isolated from firmware)")
                logs.append("  └─ Provides: Outbound connectivity (10.0.2.2 gateway)")
                logs.append("  └─ No conflicts with firmware network managers")
            else:
                logs.append("⚠ SLIRP isolation setup failed")
            
            # Step 8: Configure macvlan networking
            logs.append("[8/8] Configuring macvlan networking...")
            network_runtime_config = NodeInitializationService.configure_macvlan_network(device.penguin_project_path, network_config)
            if network_runtime_config:
                logs.append("✓ Macvlan network configured")
                logs.append(f"  └─ Network: {network_runtime_config['network_name']}")
                logs.append(f"  └─ Subnet: {network_runtime_config['subnet']}")
                logs.append(f"  └─ Mode: {network_runtime_config['mode']}")
                if network_runtime_config['mode'] == 'static':
                    logs.append(f"  └─ Static IP: {network_runtime_config.get('static_ip', 'N/A')}")
            else:
                logs.append("⚠ Macvlan network configuration failed")
            
            # Save user config to device (include network runtime config)
            if user_config:
                device.config_data = user_config
            else:
                device.config_data = {}
            
            # Add network runtime config for EmulationManagerService to use
            if network_runtime_config:
                device.config_data['network_runtime'] = network_runtime_config
            
            device.save()
            
            logs.append("=" * 50)
            logs.append("✓ Initialization completed successfully!")
            logs.append("=" * 50)
            
            return {
                'success': True,
                'message': 'Device initialized successfully',
                'logs': logs
            }
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}", exc_info=True)
            logs.append(f"✗ Error: {str(e)}")
            return {
                'success': False,
                'message': f'Initialization error: {str(e)}',
                'logs': logs
            }
    
    @staticmethod
    def patch_kernel_version(project_path: str, kernel_version: str) -> bool:
        """
        Write the selected kernel version into base.yaml's core.kernel field.

        Called after penguin init so base.yaml already exists. Overwrites
        whatever default kernel version penguin init wrote with the version
        determined from xScout firmware analysis.

        Args:
            project_path: Path to the Penguin project directory.
            kernel_version: Kernel version string to set (e.g. '4.1' or '6.13').

        Returns:
            True if the file was updated, False on error.
        """
        try:
            base_yaml_path = os.path.join(project_path, 'static_patches/base.yaml')

            if not os.path.exists(base_yaml_path):
                logger.warning(f"base.yaml not found at {base_yaml_path}")
                return False

            with open(base_yaml_path, 'r') as f:
                base_config = yaml.safe_load(f) or {}

            if 'core' not in base_config:
                base_config['core'] = {}

            base_config['core']['kernel'] = kernel_version

            with open(base_yaml_path, 'w') as f:
                yaml.dump(base_config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Set base.yaml core.kernel to {kernel_version}")
            return True

        except Exception as e:
            logger.error(f"Failed to patch kernel version in base.yaml: {e}", exc_info=True)
            return False

    @staticmethod
    def fix_broken_device_files(project_path: str) -> bool:
        """
        Fix device nodes that were incorrectly created as directories.

        Two-layer conditional fix:
          - Layer 1: Remove pseudofile entries where a known device node path
            is used as a parent directory (e.g. /dev/null/utmp). These entries
            cause igloo to create the device node as a directory at boot.
          - Layer 2: Remove directory entries for known device nodes from
            base/fs.tar.gz via stream-copy repack. Occurs when xfs/unblob
            extracted a char device as a directory (no-root limitation).

        Both layers only act when a broken state is detected. No writes occur
        if the project is already clean.

        Note: Writing /dev/* entries into base.yaml static_files is NOT done
        here — gen_image.py (Penguin) explicitly skips all /dev/ paths in
        static_files (gen_image.py:257-261), making such entries dead code.

        Args:
            project_path: Path to the Penguin project directory.

        Returns:
            True if the method completed without error (fix may or may not
            have been needed), False on exception.
        """
        try:
            NodeInitializationService._fix_pseudofile_device_dirs(project_path)
            NodeInitializationService._fix_tarball_device_dirs(project_path)
            return True
        except Exception as e:
            logger.error(f"Failed to fix device node files: {e}", exc_info=True)
            return False

    @staticmethod
    def _fix_pseudofile_device_dirs(project_path: str) -> None:
        """
        Remove pseudofile entries that use a known device node as a parent path.

        Scans pseudofiles.dynamic.yaml for keys matching /dev/<device>/<anything>
        and deletes them. Only rewrites the file if entries were actually removed.

        Args:
            project_path: Path to the Penguin project directory.
        """
        pseudo_path = os.path.join(project_path, 'static_patches/pseudofiles.dynamic.yaml')
        if not os.path.exists(pseudo_path):
            return

        with open(pseudo_path, 'r') as f:
            pseudo_config = yaml.safe_load(f) or {}

        pseudofiles = pseudo_config.get('pseudofiles', {})
        if not pseudofiles:
            return

        to_remove = [
            key for key in pseudofiles
            if any(key.startswith(dev + '/') for dev in KNOWN_DEVICE_NODES)
        ]

        if not to_remove:
            return

        for key in to_remove:
            del pseudofiles[key]
            logger.info(f"Removed device child pseudofile entry: {key}")

        with open(pseudo_path, 'w') as f:
            yaml.dump(pseudo_config, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Cleaned {len(to_remove)} device child entries from pseudofiles.dynamic.yaml")

    @staticmethod
    def _fix_tarball_device_dirs(project_path: str) -> None:
        """
        Remove device node directory entries from base/fs.tar.gz via stream repack.

        Detects members in the tarball where a known device node path exists as
        a directory (a side-effect of root-less SquashFS extraction). If found,
        rewrites the tarball skipping those entries. Backs up the original first.

        Args:
            project_path: Path to the Penguin project directory.
        """
        import tarfile as _tarfile
        from datetime import datetime

        tarball_path = os.path.join(project_path, 'base/fs.tar.gz')
        if not os.path.exists(tarball_path):
            return

        # Normalise known device node paths to match tarball member names.
        # Tarball members are typically stored as './dev/null'.
        broken_paths = set()
        with _tarfile.open(tarball_path, 'r:gz') as tar:
            for member in tar.getmembers():
                # Strip leading './' for comparison
                normalised = member.name.lstrip('./')
                if normalised in [d.lstrip('/') for d in KNOWN_DEVICE_NODES]:
                    if member.isdir():
                        broken_paths.add(member.name)
                        logger.info(f"Detected broken device node directory in tarball: {member.name}")

        if not broken_paths:
            return

        # Backup original
        backup_path = f"{tarball_path}.backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        os.rename(tarball_path, backup_path)
        logger.info(f"Backed up original tarball to {backup_path}")

        # Stream-copy, skipping broken directory entries
        with _tarfile.open(backup_path, 'r:gz') as src:
            with _tarfile.open(tarball_path, 'w:gz') as dst:
                for member in src.getmembers():
                    if member.name in broken_paths:
                        logger.info(f"Skipping broken device dir from tarball: {member.name}")
                        continue
                    if member.isfile():
                        dst.addfile(member, src.extractfile(member))
                    else:
                        dst.addfile(member)

        logger.info(f"Repacked tarball, removed {len(broken_paths)} broken device node director(ies)")
    
    @staticmethod
    def disable_auto_shutdown(project_path: str) -> bool:
        """
        Disable auto-shutdown plugins in manual.yaml
        
        Maps to REQ-2.4 from penguin-implementation.md
        
        Args:
            project_path: Path to penguin project directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            manual_yaml_path = os.path.join(project_path, 'static_patches/manual.yaml')
            
            if not os.path.exists(manual_yaml_path):
                logger.warning(f"manual.yaml not found at {manual_yaml_path}")
                return False
            
            with open(manual_yaml_path, 'r') as f:
                manual_config = yaml.safe_load(f) or {}
            
            # Ensure plugins section exists
            if 'plugins' not in manual_config:
                manual_config['plugins'] = {}
            
            plugins = manual_config['plugins']
            
            # Configure core settings to prevent VM exit
            # CRITICAL: root_shell must be false or the VM will exit when shell closes
            if 'core' not in manual_config:
                manual_config['core'] = {}
            manual_config['core']['root_shell'] = False
            
            # Configure plugins to prevent auto-shutdown
            plugin_config = {
                'netbinds': {
                    'enabled': True,
                    'shutdown_on_www': False
                },
                'fetch_web': {
                    'enabled': False,
                    'shutdown_after_www': False,
                    'shutdown_on_failure': False
                },
                'ficd': {
                    'enabled': False,
                    'stop_on_if': False
                },
                'vpn': {
                    'enabled': True
                },
                'health': {
                    'enabled': True
                },
                'nmap': {
                    'enabled': False
                }
            }
            
            # Update plugin configuration
            for plugin_name, plugin_settings in plugin_config.items():
                if plugin_name not in plugins:
                    plugins[plugin_name] = {}
                plugins[plugin_name].update(plugin_settings)
            
            # Write back manual.yaml
            with open(manual_yaml_path, 'w') as f:
                yaml.dump(manual_config, f, default_flow_style=False, sort_keys=False)
            
            logger.info("Updated manual.yaml to disable auto-shutdown")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable auto-shutdown: {e}", exc_info=True)
            return False
    
    @staticmethod
    def configure_macvlan_network(project_path: str, network_config: Optional[Dict] = None) -> Dict:
        """
        Configure macvlan networking for the device
        
        Args:
            project_path: Path to penguin project directory
            network_config: Optional network configuration dict
            
        Returns:
            Dictionary with network configuration (to be stored in device.config_data)
        """
        try:
            config_yaml_path = os.path.join(project_path, 'config.yaml')
            
            if not os.path.exists(config_yaml_path):
                logger.error(f"config.yaml not found at {config_yaml_path}")
                return {}
            
            # Get network configuration
            if network_config is None:
                network_config = {}
            
            mode = network_config.get('mode', 'ipam')
            static_ip = network_config.get('static_ip', '')
            subnet = network_config.get('subnet', '')
            gateway = network_config.get('gateway', '')
            
            # Auto-detect network if not provided
            if not subnet or not gateway:
                auto_network = MacvlanNetworkService.get_host_network_info()
                subnet = subnet or auto_network['subnet']
                gateway = gateway or auto_network['gateway']
            
            # Create or get macvlan network
            try:
                network_name = MacvlanNetworkService.create_or_get_macvlan(subnet, gateway)
            except RuntimeError as e:
                # Network might already exist, try to find it
                if "Pool overlaps" in str(e):
                    # Use the existing xwangnet_lan or similar
                    import subprocess
                    result = subprocess.run(
                        ['docker', 'network', 'ls', '--filter', 'driver=macvlan', '--format', '{{.Name}}'],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    networks = result.stdout.strip().split('\n')
                    if networks and networks[0]:
                        network_name = networks[0]
                        logger.info(f"Using existing macvlan network: {network_name}")
                    else:
                        logger.error(f"Failed to create or find macvlan network: {e}")
                        return {}
                else:
                    logger.error(f"Failed to create macvlan network: {e}")
                    return {}
            
            # Update config.yaml to enable networking
            with open(config_yaml_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            if 'core' not in config:
                config['core'] = {}
            
            config['core']['network'] = True
            
            # Write back config
            with open(config_yaml_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            # Return network configuration to be stored in device.config_data
            network_runtime_config = {
                'network_name': network_name,
                'mode': mode,
                'subnet': subnet,
                'gateway': gateway,
            }
            
            # Check if static IP is in use (if mode is static)
            if mode == 'static' and static_ip:
                if NodeInitializationService._is_ip_in_use(network_name, static_ip):
                    logger.warning(f"Static IP {static_ip} is already in use, falling back to IPAM mode")
                    mode = 'ipam'
                    network_runtime_config['mode'] = 'ipam'
                    network_runtime_config.pop('static_ip', None)
                else:
                    network_runtime_config['static_ip'] = static_ip
            
            logger.info(f"Configured macvlan network: {network_name}")
            logger.info(f"Network mode: {mode}")
            if mode == 'static':
                logger.info(f"Static IP: {static_ip}")
            
            return network_runtime_config
            
        except Exception as e:
            logger.error(f"Failed to configure macvlan network: {e}", exc_info=True)
            return {}
    
    @staticmethod
    def _is_ip_in_use(network_name: str, ip_address: str) -> bool:
        """
        Check if an IP address is already in use on the specified Docker network
        
        Args:
            network_name: Name of the Docker network
            ip_address: IP address to check
            
        Returns:
            True if IP is in use, False otherwise
        """
        try:
            import subprocess
            import json
            
            # Get all containers on this network
            result = subprocess.run(
                ['docker', 'network', 'inspect', network_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            network_info = json.loads(result.stdout)
            if not network_info:
                return False
            
            # Check all containers in the network
            containers = network_info[0].get('Containers', {})
            for container_id, container_info in containers.items():
                container_ip = container_info.get('IPv4Address', '').split('/')[0]
                if container_ip == ip_address:
                    logger.warning(f"IP {ip_address} is in use by container {container_id}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking if IP is in use: {e}")
            # If we can't determine, assume it might be in use to be safe
            return False
