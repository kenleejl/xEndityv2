"""
Emulation Manager Service for xFormation

Manages emulation instances and their lifecycle using Docker API
"""

import os
import subprocess
import threading
import psutil
import logging
import time
import re
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from modules.xFormation.models import EmulatedDevice, EmulationInstance
from .live_output_service import LiveOutputService
from .docker_penguin_service import DockerPenguinService
from .telemetry_service import TelemetryService
from .behavior_analysis_service import BehaviorAnalysisService
from .validation_service import ValidationService
from .rootfs_modification_service import RootfsModificationService

logger = logging.getLogger(__name__)


class EmulationManagerService:
    """Service for managing emulation instances"""
    
    # Configuration
    MAX_INSTANCES = getattr(settings, 'XFORMATION_MAX_INSTANCES', 5)
    PENGUIN_COMMAND = getattr(settings, 'PENGUIN_COMMAND', 'penguin')
    INSTANCE_LOGS_DIR = getattr(settings, 'XFORMATION_LOGS_DIR', '/tmp/xformation_logs')
    USE_DOCKER_API = getattr(settings, 'XFORMATION_USE_DOCKER_API', True)  # Use Docker API by default
    
    
    @staticmethod
    def _cleanup_stale_qcows(penguin_project_path: str) -> None:
        """
        Delete orphaned qcow2 files from previous fs.tar.gz builds.

        Penguin content-hashes fs.tar.gz to derive qcow2 filenames, so modifying
        fs.tar.gz causes a new qcow2 to be built on next launch. This method removes
        older qcow2 files whose mtime precedes the current fs.tar.gz mtime, preventing
        indefinite accumulation of orphaned images on disk.

        Running containers are unaffected: Linux unlink() semantics allow open file
        descriptors to remain valid after their directory entry is removed.

        Args:
            penguin_project_path: Path to the Penguin project directory containing
                                  base/fs.tar.gz and qcows/ subdirectory.
        """
        fs_tar = os.path.join(penguin_project_path, 'base', 'fs.tar.gz')
        qcow_dir = os.path.join(penguin_project_path, 'qcows')

        if not os.path.exists(fs_tar) or not os.path.isdir(qcow_dir):
            return

        fs_mtime = os.path.getmtime(fs_tar)

        try:
            entries = os.listdir(qcow_dir)
        except OSError as e:
            logger.warning(f"_cleanup_stale_qcows: could not list {qcow_dir}: {e}")
            return

        for fname in entries:
            if not fname.endswith('.qcow2'):
                continue
            qcow_path = os.path.join(qcow_dir, fname)
            try:
                qcow_mtime = os.path.getmtime(qcow_path)
            except OSError:
                continue  # File disappeared between listdir and getmtime — skip

            if qcow_mtime < fs_mtime:
                try:
                    os.remove(qcow_path)
                    logger.info(
                        f"_cleanup_stale_qcows: removed stale qcow2 '{fname}' "
                        f"(qcow mtime {qcow_mtime:.0f} < fs.tar.gz mtime {fs_mtime:.0f})"
                    )
                except OSError as e:
                    logger.warning(f"_cleanup_stale_qcows: could not remove {fname}: {e}")

    @staticmethod
    def can_start_instance() -> bool:
        """
        Check if we can start a new instance (within limits)

        Returns:
            True if we can start a new instance, False otherwise
        """
        running_count = EmulationInstance.objects.filter(status='running').count()
        return running_count < EmulationManagerService.MAX_INSTANCES
    
    @staticmethod
    def start_instance(device: EmulatedDevice, instance_name: str = None, 
                      cpu_limit: float = 2.0, memory_limit: str = "1g") -> EmulationInstance:
        """
        Start a new emulation instance
        
        Args:
            device: EmulatedDevice to emulate
            instance_name: Name for the instance (auto-generated if None)
            cpu_limit: CPU limit in cores
            memory_limit: Memory limit (e.g., "1g", "512m")
            
        Returns:
            EmulationInstance object
        """
        try:
            # Check if device can be run
            if not device.can_run:
                logger.error(f"Device {device.id} is not initialized and cannot be run")
                return None
            
            # Check instance limits
            if not EmulationManagerService.can_start_instance():
                logger.error(f"Cannot start instance: maximum instances ({EmulationManagerService.MAX_INSTANCES}) reached")
                return None
            
            # Generate instance name if not provided
            if not instance_name:
                instance_name = f"{device.name}_instance_{int(time.time())}"
            
            # Create instance record
            instance = EmulationInstance.objects.create(
                device=device,
                instance_name=instance_name,
                status='starting',
                cpu_limit=cpu_limit,
                memory_limit=memory_limit
            )
            
            # Start the instance asynchronously
            EmulationManagerService._start_instance_async(instance)
            
            logger.info(f"Started emulation instance {instance.id}: {instance_name}")
            return instance
            
        except Exception as e:
            logger.error(f"Error starting instance for device {device.id}: {e}")
            return None
    
    @staticmethod
    def _start_instance_async(instance: EmulationInstance):
        """
        Start an instance asynchronously in a separate thread
        
        Args:
            instance: EmulationInstance to start
        """
        def start_worker():
            if EmulationManagerService.USE_DOCKER_API:
                EmulationManagerService._run_penguin_docker(instance)
            else:
                EmulationManagerService._run_penguin_instance(instance)
        
        thread = threading.Thread(target=start_worker, daemon=True)
        thread.start()
        logger.info(f"Started async emulation for instance {instance.id}")
    
    @staticmethod
    def _run_penguin_instance(instance: EmulationInstance):
        """
        Run the actual penguin process for an instance
        
        Args:
            instance: EmulationInstance to run
        """
        try:
            # Create logs directory
            os.makedirs(EmulationManagerService.INSTANCE_LOGS_DIR, exist_ok=True)
            
            # Set up log file
            log_filename = f"instance_{instance.id}_{int(time.time())}.log"
            log_path = os.path.join(EmulationManagerService.INSTANCE_LOGS_DIR, log_filename)
            instance.output_log_path = log_path
            instance.save()
            logger.info(f"Log path: {log_path}")
            logger.info(f"Config yaml path: {instance.device.config_yaml_path}")
            logger.info(f"Penguin project path: {instance.device.penguin_project_path}")

            # Build penguin run command with network configuration
            cmd = [EmulationManagerService.PENGUIN_COMMAND]

            # Get network runtime config from device.config_data
            config_data = instance.device.config_data or {}
            network_runtime = config_data.get('network_runtime', {})

            # Apply telemetry mode to config.yaml before launch (idempotent; lazy default to filtered)
            telemetry_mode = config_data.get('telemetry_mode', 'filtered')
            RootfsModificationService.apply_telemetry_mode(
                instance.device.penguin_project_path, telemetry_mode
            )

            # Remove orphaned qcow2 files from previous fs.tar.gz builds (silent, lazy)
            EmulationManagerService._cleanup_stale_qcows(instance.device.penguin_project_path)

            if network_runtime:
                # Build extra_docker_args for macvlan networking
                network_name = network_runtime.get('network_name', '')
                mode = network_runtime.get('mode', 'ipam')
                gateway = network_runtime.get('gateway', '')

                extra_docker_args_parts = [
                    f"--network {network_name}",
                    "--cap-add=NET_ADMIN",
                ]

                if mode == 'static':
                    static_ip = network_runtime.get('static_ip', '')
                    if static_ip:
                        extra_docker_args_parts.append(f"--ip {static_ip}")
                        extra_docker_args_parts.append(f"-e CONTAINER_IP={static_ip}")

                if gateway:
                    extra_docker_args_parts.append(f"-e GATEWAY={gateway}")

                extra_docker_args = ' '.join(extra_docker_args_parts)

                # Add wrapper flags
                cmd.extend(['--extra_docker_args', extra_docker_args])
                cmd.extend(['--subnet', 'none'])  # Disable penguin's auto network creation

                logger.info(f"Network mode: {mode}")
                logger.info(f"Macvlan network: {network_name}")
                if mode == 'static':
                    logger.info(f"Static IP: {static_ip}")
            else:
                logger.warning("No network runtime config found - penguin will create default bridge network")

            # Add the run command and config path
            cmd.extend(['run', instance.device.config_yaml_path])
            
            logger.info(f"Running penguin for instance {instance.id}: {' '.join(cmd)}")
            
            # Start the process
            with open(log_path, 'w') as log_file:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Update instance with process info
                instance.process_id = process.pid
                instance.status = 'running'
                instance.save()
                
                # Start live output monitoring
                LiveOutputService.start_monitoring(instance, process.stdout)
                
                # Monitor the process
                for line in iter(process.stdout.readline, ''):
                    if line:
                        # Write to log file
                        log_file.write(line)
                        log_file.flush()
                        
                        # Parse for network information
                        EmulationManagerService._parse_penguin_output(instance, line)
                
                # Wait for process to complete
                process.wait()
                
                # Update instance status
                if process.returncode == 0:
                    instance.status = 'stopped'
                else:
                    instance.status = 'failed'
                
                instance.stopped_at = timezone.now()
                instance.save()
                
                logger.info(f"Penguin process completed for instance {instance.id} with return code {process.returncode}")
                
                EmulationManagerService._collect_post_emulation_telemetry(instance)
        
        except Exception as e:
            instance.status = 'failed'
            instance.stopped_at = timezone.now()
            instance.save()
            logger.error(f"Error running penguin instance {instance.id}: {e}")
            EmulationManagerService._collect_post_emulation_telemetry(instance)
    
    @staticmethod
    def _run_penguin_docker(instance: EmulationInstance):
        """
        Run penguin using Docker API instead of subprocess.

        Supports two networking modes driven by device.config_data['network_runtime']:
        - Macvlan mode (network_runtime present): connects the penguin container
          directly to the pre-configured macvlan network via Docker API.
        - Bridge mode (no network_runtime): creates a new ephemeral bridge network
          and connects the penguin orchestrator container directly.

        Args:
            instance: EmulationInstance to run
        """
        container = None
        network_name = None
        container_name = None
        gateway = None
        container_ip = ''

        try:
            # Create logs directory
            os.makedirs(EmulationManagerService.INSTANCE_LOGS_DIR, exist_ok=True)

            # Set up log file
            log_filename = f"instance_{instance.id}_{int(time.time())}.log"
            log_path = os.path.join(EmulationManagerService.INSTANCE_LOGS_DIR, log_filename)
            instance.output_log_path = log_path
            instance.save()

            logger.info(f"Log path: {log_path}")
            logger.info(f"Config yaml path: {instance.device.config_yaml_path}")
            logger.info(f"Penguin project path: {instance.device.penguin_project_path}")

            # Resolve networking mode from device config
            config_data = instance.device.config_data or {}
            network_runtime = config_data.get('network_runtime', {})

            # Apply telemetry mode to config.yaml before launch (idempotent; lazy default to filtered)
            telemetry_mode = config_data.get('telemetry_mode', 'filtered')
            RootfsModificationService.apply_telemetry_mode(
                instance.device.penguin_project_path, telemetry_mode
            )

            # Remove orphaned qcow2 files from previous fs.tar.gz builds (silent, lazy)
            EmulationManagerService._cleanup_stale_qcows(instance.device.penguin_project_path)

            if network_runtime:
                # Macvlan mode: connect penguin container directly to the
                # pre-existing macvlan network via Docker API.
                network_name = network_runtime.get('network_name', '')
                mode = network_runtime.get('mode', 'ipam')
                gateway = network_runtime.get('gateway', '')

                if mode == 'static':
                    container_ip = network_runtime.get('static_ip', '')

                # Store network info — not cleaning up the macvlan network on exit
                instance.docker_network_name = network_name
                instance.docker_subnet = network_runtime.get('subnet', '')
                if mode == 'static' and container_ip:
                    instance.host_ip = container_ip
                instance.save()

                logger.info(f"Macvlan mode: network={network_name}, mode={mode}, gateway={gateway}")
            else:
                # Bridge mode: create a fresh ephemeral bridge network
                network_name, subnet, gateway, container_ip = DockerPenguinService.create_penguin_network(
                    subnet=None  # Auto-detect available subnet
                )

                instance.docker_network_name = network_name
                instance.docker_subnet = subnet
                instance.host_ip = container_ip
                instance.save()

                logger.info(f"Bridge mode: created network {network_name} with IP {container_ip}")

            # Run penguin container
            container = DockerPenguinService.run_penguin_container(
                instance_name=instance.instance_name,
                config_path=instance.device.config_yaml_path,
                penguin_project_path=instance.device.penguin_project_path,
                network_name=network_name,
                container_ip=container_ip,
                cpu_limit=instance.cpu_limit,
                memory_limit=instance.memory_limit,
                gateway=gateway,
            )
            
            # Store container info
            instance.docker_container_id = container.id
            instance.docker_container_name = container.name
            container_name = container.name
            instance.status = 'running'
            instance.save()
            
            logger.info(f"Started Docker container: {container.name}")
            
            # Monitor container logs with live output service
            log_stream = DockerPenguinService.get_container_logs(
                container_name=instance.instance_name,
                stream=True,
                follow=True
            )
            
            if log_stream:
                # Process log stream once, feeding both log file and live output
                with open(log_path, 'w') as log_file:
                    for log_entry in log_stream:
                        try:
                            line = log_entry.decode('utf-8') if isinstance(log_entry, bytes) else log_entry
                            line = line.rstrip()
                            
                            if line:
                                # Write raw line to log file (with ANSI codes preserved)
                                log_file.write(line + '\n')
                                log_file.flush()
                                
                                # Process ANSI codes for live output (convert to HTML)
                                processed_line = LiveOutputService._process_ansi_line(line)
                                
                                # Add timestamp
                                timestamped_line = f"[{time.strftime('%H:%M:%S')}] {processed_line}"
                                
                                # Add to live output buffer with lock
                                with LiveOutputService._buffer_locks[instance.id]:
                                    LiveOutputService._output_buffers[instance.id].append(timestamped_line)
                                    
                                    # Trim buffer if too large
                                    if len(LiveOutputService._output_buffers[instance.id]) > LiveOutputService.MAX_BUFFER_SIZE:
                                        LiveOutputService._output_buffers[instance.id] = \
                                            LiveOutputService._output_buffers[instance.id][-LiveOutputService.MAX_BUFFER_SIZE:]
                                
                                # Notify subscribers
                                LiveOutputService._notify_subscribers(instance.id, timestamped_line)
                                
                                # Parse for network information (use raw line without ANSI codes)
                                EmulationManagerService._parse_penguin_output(instance, line)
                        except Exception as line_error:
                            logger.warning(f"Error processing log line: {line_error}")
            
            # Wait for container to exit
            result = container.wait()
            exit_code = result.get('StatusCode', -1)
            
            # Update instance status
            if exit_code == 0:
                instance.status = 'stopped'
                logger.info(f"Container exited successfully for instance {instance.id}")
            else:
                instance.status = 'failed'
                logger.error(f"Container exited with code {exit_code} for instance {instance.id}")
            
            instance.stopped_at = timezone.now()
            instance.save()
            
            EmulationManagerService._collect_post_emulation_telemetry(instance)
            
        except Exception as e:
            instance.status = 'failed'
            instance.stopped_at = timezone.now()
            instance.save()
            logger.error(f"Error running penguin Docker container for instance {instance.id}: {e}", exc_info=True)
            EmulationManagerService._collect_post_emulation_telemetry(instance)
        
        finally:
            # Always cleanup the penguin orchestrator container and any bridge network we created.
            # Macvlan networks are persistent infrastructure — never remove them here.
            cleanup_container = container_name or getattr(instance, 'docker_container_name', None) or instance.instance_name

            # Only cleanup bridge networks we created (penguin_nw_* prefix).
            # Macvlan network names come from device config and must persist.
            stored_network = network_name or getattr(instance, 'docker_network_name', None)
            cleanup_network = (
                stored_network
                if stored_network and stored_network.startswith(DockerPenguinService.NETWORK_PREFIX)
                else None
            )

            if cleanup_container or cleanup_network:
                try:
                    success = DockerPenguinService.stop_penguin_container(
                        container_name=cleanup_container,
                        network_name=cleanup_network,
                        timeout=5
                    )
                    if success:
                        logger.info(f"Cleaned up Docker resources for instance {instance.id}")
                    else:
                        logger.warning(f"Partial cleanup for instance {instance.id}")
                except Exception as cleanup_error:
                    logger.error(f"Error during Docker cleanup for instance {instance.id}: {cleanup_error}")

                    # Try to cleanup bridge network manually if container cleanup failed
                    if cleanup_network:
                        try:
                            import docker
                            client = docker.from_env()
                            network = client.networks.get(cleanup_network)
                            network.remove()
                            logger.info(f"Manually cleaned up network {cleanup_network}")
                        except Exception as net_error:
                            logger.error(f"Failed to manually cleanup network {cleanup_network}: {net_error}")
    
    
    @staticmethod
    def _collect_post_emulation_telemetry(instance: EmulationInstance):
        """
        Collect telemetry from Penguin results after emulation completes.
        Called for both subprocess and Docker-based instances.
        """
        try:
            telemetry = TelemetryService.collect_telemetry(instance)
            if telemetry:
                logger.info(
                    "Telemetry collected for instance %s: %d processes, %d binds, panic=%s",
                    instance.id,
                    len(telemetry.processes),
                    len(telemetry.network_binds),
                    telemetry.kernel_panic,
                )
                findings = BehaviorAnalysisService.analyze(telemetry)
                logger.info(
                    "Behavior analysis for instance %s: %d findings",
                    instance.id, len(findings),
                )
                ValidationService.validate(instance, telemetry)
            else:
                logger.warning("No telemetry data available for instance %s", instance.id)
        except Exception as e:
            logger.error("Failed to collect telemetry for instance %s: %s", instance.id, e)

    @staticmethod
    def _parse_penguin_output(instance: EmulationInstance, line: str):
        """
        Parse penguin output for network and service information
        
        Args:
            instance: EmulationInstance
            line: Output line from penguin
        """
        try:
            # Look for VPN plugin messages indicating bound ports
            # Example: "plugins.VPN INFO         lighttpd binds tcp [::]:80          reach it at 192.168.0.2:80"
            vpn_pattern = r'plugins\.VPN INFO\s+(\w+)\s+binds\s+tcp\s+.*?reach it at\s+([\d.]+):(\d+)'
            match = re.search(vpn_pattern, line)
            
            if match:
                service_name = match.group(1)
                host_ip = match.group(2)
                host_port = match.group(3)
                
                # For macvlan networking, VPN plugin reports 127.0.0.1, but we need the real container IP
                if host_ip == '127.0.0.1':
                    # Try to get actual container IP from Docker
                    try:
                        container_name = "rootfs"  # Penguin default container name
                        result = subprocess.run(
                            ['docker', 'inspect', container_name, '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                        detected_ip = result.stdout.strip()
                        if detected_ip and detected_ip != '127.0.0.1':
                            host_ip = detected_ip
                            logger.info(f"Detected actual container IP: {host_ip} (VPN plugin reported 127.0.0.1)")
                    except Exception as e:
                        logger.warning(f"Could not detect container IP: {e}")
                
                # Update instance with network info
                instance.host_ip = host_ip
                if not instance.host_ports:
                    instance.host_ports = {}
                instance.host_ports[service_name] = {
                    'port': int(host_port),
                    'protocol': 'tcp'
                }
                
                # Check if this looks like a web interface
                if service_name in ['httpd', 'lighttpd', 'nginx'] or host_port in ['80', '443', '8080']:
                    web_url = f"http://{host_ip}:{host_port}"
                    if host_port == '443':
                        web_url = f"https://{host_ip}:{host_port}"
                    elif host_port == '80':
                        web_url = f"http://{host_ip}"  # Don't show :80 for standard HTTP
                    
                    instance.web_interface_url = web_url
                    # Start health checking for web interface
                    EmulationManagerService._check_web_interface_async(instance)
                
                instance.save()
                logger.info(f"Detected service binding for instance {instance.id}: {service_name} on {host_ip}:{host_port}")
        
        except Exception as e:
            logger.error(f"Error parsing penguin output for instance {instance.id}: {e}")
    
    @staticmethod
    def _check_web_interface_async(instance: EmulationInstance):
        """
        Check web interface accessibility asynchronously
        
        Args:
            instance: EmulationInstance to check
        """
        def check_worker():
            time.sleep(10)  # Wait a bit for service to fully start
            EmulationManagerService.check_web_interface_health(instance)
        
        thread = threading.Thread(target=check_worker, daemon=True)
        thread.start()
    
    @staticmethod
    def stop_instance(instance: EmulationInstance) -> bool:
        """
        Stop a running emulation instance
        
        Args:
            instance: EmulationInstance to stop
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if instance.status != 'running':
                logger.warning(f"Instance {instance.id} is not running (status: {instance.status})")
                return False
            
            # Update status
            instance.status = 'stopping'
            instance.save()
            
            # Check if this is a Docker-based instance
            if hasattr(instance, 'docker_container_id') and instance.docker_container_id:
                # Stop using Docker API.
                # Only remove bridge networks (penguin_nw_* prefix) — macvlan networks
                # are persistent LAN infrastructure and must not be torn down on stop.
                stored_network = getattr(instance, 'docker_network_name', None)
                cleanup_network = (
                    stored_network
                    if stored_network and stored_network.startswith(DockerPenguinService.NETWORK_PREFIX)
                    else None
                )
                try:
                    success = DockerPenguinService.stop_penguin_container(
                        container_name=instance.docker_container_name or instance.instance_name,
                        network_name=cleanup_network,
                        timeout=10
                    )
                    
                    if success:
                        logger.info(f"Stopped Docker container for instance {instance.id}")
                    else:
                        logger.warning(f"Failed to fully stop Docker resources for instance {instance.id}")
                        
                except Exception as docker_error:
                    logger.error(f"Error stopping Docker container for instance {instance.id}: {docker_error}")
            
            # Fallback: Kill the process if it exists
            elif instance.process_id:
                try:
                    process = psutil.Process(instance.process_id)
                    process.terminate()
                    
                    # Wait a bit for graceful shutdown
                    time.sleep(5)
                    
                    # Force kill if still running
                    if process.is_running():
                        process.kill()
                    
                    logger.info(f"Stopped process {instance.process_id} for instance {instance.id}")
                    
                except psutil.NoSuchProcess:
                    logger.warning(f"Process {instance.process_id} for instance {instance.id} not found")
                except Exception as stop_error:
                    logger.warning(f"Error stopping process {instance.process_id} for instance {instance.id}: {stop_error}")
            
            # Clean up Docker container to release IP
            try:
                container_name = "rootfs"  # Penguin default container name
                
                # Check if container exists
                result = subprocess.run(
                    ['docker', 'ps', '-a', '--filter', f'name={container_name}', '--format', '{{.Names}}'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                if container_name in result.stdout:
                    # Stop container if running
                    subprocess.run(
                        ['docker', 'stop', container_name],
                        capture_output=True,
                        timeout=10
                    )
                    
                    # Remove container to release IP
                    subprocess.run(
                        ['docker', 'rm', container_name],
                        capture_output=True,
                        check=True
                    )
                    
                    logger.info(f"Removed Docker container '{container_name}' to release IP")
                else:
                    logger.info(f"Container '{container_name}' not found, skipping cleanup")
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout stopping container, forcing removal")
                try:
                    subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)
                except:
                    pass
            except Exception as cleanup_error:
                logger.warning(f"Error cleaning up Docker container: {cleanup_error}")
            
            # Update instance status
            instance.status = 'stopped'
            instance.stopped_at = timezone.now()
            instance.save()
            
            # Cleanup live output data
            LiveOutputService.cleanup_instance_data(instance.id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error stopping instance {instance.id}: {e}")
            instance.status = 'failed'
            instance.save()
            return False
    
    @staticmethod
    def check_web_interface_health(instance: EmulationInstance) -> str:
        """
        Check if the web interface is accessible
        
        Args:
            instance: EmulationInstance to check
            
        Returns:
            Status string: 'accessible', 'inaccessible', or 'unknown'
        """
        if not instance.web_interface_url:
            return 'unknown'
        
        # For macvlan instances, health checks from host may fail due to isolation
        # If the instance is on macvlan and we detected the service, assume it's accessible
        config_data = instance.device.config_data or {}
        network_runtime = config_data.get('network_runtime', {})
        is_macvlan = network_runtime.get('network_name', '').startswith(('xwangnet_lan', 'xformation_macvlan'))
        
        if is_macvlan and instance.host_ip:
            # Macvlan instance - service is accessible from network (just not from host)
            instance.web_interface_status = 'accessible'
            instance.last_health_check = timezone.now()
            instance.save()
            logger.info(f"Macvlan instance {instance.id}: Web interface available at {instance.web_interface_url} (accessible from network)")
            return 'accessible'
        
        # For bridge network instances, perform actual HTTP check
        try:
            import requests
            response = requests.get(instance.web_interface_url, timeout=5)
            
            if response.status_code == 200:
                instance.web_interface_status = 'accessible'
                instance.last_health_check = timezone.now()
                instance.save()
                logger.info(f"Web interface accessible for instance {instance.id}: {instance.web_interface_url}")
                return 'accessible'
            else:
                instance.web_interface_status = 'inaccessible'
                instance.last_health_check = timezone.now()
                instance.save()
                return 'inaccessible'
        
        except Exception as e:
            instance.web_interface_status = 'inaccessible'
            instance.last_health_check = timezone.now()
            instance.save()
            logger.warning(f"Web interface check failed for instance {instance.id}: {e}")
            return 'inaccessible'
    
    @staticmethod
    def get_running_instances() -> list:
        """
        Get all currently running instances
        
        Returns:
            List of EmulationInstance objects
        """
        return list(EmulationInstance.objects.filter(status='running'))
    
    @staticmethod
    def detect_instance_network_info(instance: EmulationInstance) -> bool:
        """
        Detect network information for a running instance
        Useful for instances that started but haven't been detected yet
        
        Args:
            instance: EmulationInstance to detect
            
        Returns:
            True if network info was detected, False otherwise
        """
        try:
            # Get container name (penguin default is 'rootfs')
            container_name = "rootfs"
            
            # Get container IP
            result = subprocess.run(
                ['docker', 'inspect', container_name, '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'],
                capture_output=True,
                text=True,
                check=True
            )
            
            container_ip = result.stdout.strip()
            if not container_ip or container_ip == '127.0.0.1':
                logger.warning(f"Could not detect valid IP for instance {instance.id}")
                return False
            
            # Get docker logs to detect services
            result = subprocess.run(
                ['docker', 'logs', container_name],
                capture_output=True,
                text=True
            )
            
            # Combine stdout and stderr
            logs = result.stdout + result.stderr
            
            # Look for lighttpd/httpd bindings
            import re
            vpn_pattern = r'plugins\.vpn.*?(lighttpd|httpd|nginx)\s+binds\s+tcp.*?:(\d+)'
            matches = re.finditer(vpn_pattern, logs, re.IGNORECASE)
            
            detected_service = False
            for match in matches:
                service_name = match.group(1)
                port = match.group(2)
                
                # Update instance
                instance.host_ip = container_ip
                
                if port in ['80', '443']:
                    web_url = f"http://{container_ip}" if port == '80' else f"https://{container_ip}"
                    instance.web_interface_url = web_url
                    detected_service = True
                    logger.info(f"Detected {service_name} on {container_ip}:{port} for instance {instance.id}")
                    break
            
            if detected_service:
                instance.save()
                # Trigger health check
                EmulationManagerService._check_web_interface_async(instance)
                return True
            elif container_ip:
                # At least we have the IP, even if no web service detected
                instance.host_ip = container_ip
                instance.save()
                logger.info(f"Detected IP {container_ip} for instance {instance.id} (no web service found)")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting network info for instance {instance.id}: {e}")
            return False
    
    @staticmethod
    def cleanup_dead_instances():
        """
        Clean up instances whose processes or containers have died
        """
        running_instances = EmulationInstance.objects.filter(status='running')
        
        for instance in running_instances:
            # Check Docker containers first
            if hasattr(instance, 'docker_container_id') and instance.docker_container_id:
                try:
                    status = DockerPenguinService.get_container_status(
                        instance.docker_container_name or instance.instance_name
                    )
                    
                    if status is None or status in ['exited', 'dead', 'removing']:
                        # Container is dead or gone
                        instance.status = 'stopped'
                        instance.stopped_at = timezone.now()
                        instance.save()
                        logger.info(f"Cleaned up dead Docker instance {instance.id} (status: {status})")
                        
                        # Cleanup Docker resources
                        try:
                            DockerPenguinService.stop_penguin_container(
                                container_name=instance.docker_container_name or instance.instance_name,
                                network_name=getattr(instance, 'docker_network_name', None),
                                timeout=5
                            )
                        except:
                            pass
                        
                except Exception as e:
                    logger.warning(f"Error checking Docker container status for instance {instance.id}: {e}")
            
            # Check process-based instances
            elif instance.process_id:
                try:
                    process = psutil.Process(instance.process_id)
                    if not process.is_running():
                        instance.status = 'stopped'
                        instance.stopped_at = timezone.now()
                        instance.save()
                        logger.info(f"Cleaned up dead process instance {instance.id}")
                except psutil.NoSuchProcess:
                    instance.status = 'stopped'
                    instance.stopped_at = timezone.now()
                    instance.save()
                    logger.info(f"Cleaned up dead process instance {instance.id}")
                except Exception as e:
                    logger.warning(f"Error checking process status for instance {instance.id}: {e}")
            else:
                # No process ID or container ID, mark as failed
                instance.status = 'failed'
                instance.stopped_at = timezone.now()
                instance.save()
                logger.warning(f"Marked instance {instance.id} as failed (no process ID)")

    @staticmethod
    def cleanup_orphaned_containers():
        """
        Clean up orphaned Docker containers to release IPs from macvlan IPAM

        This removes stopped 'rootfs' containers that are no longer associated
        with running instances, freeing up their IP addresses.

        Returns:
            Number of containers cleaned up
        """
        try:
            # Find all stopped rootfs containers
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', 'name=rootfs', '--filter', 'status=exited', '--format', '{{.Names}}'],
                capture_output=True,
                text=True,
                check=True
            )

            stopped_containers = [name.strip() for name in result.stdout.strip().split('\n') if name.strip()]

            if not stopped_containers:
                logger.info("No orphaned containers found")
                return 0

            # Remove them
            cleaned = 0
            for container in stopped_containers:
                try:
                    subprocess.run(
                        ['docker', 'rm', container],
                        capture_output=True,
                        check=True
                    )
                    logger.info(f"Removed orphaned container: {container}")
                    cleaned += 1
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to remove container {container}: {e.stderr}")

            logger.info(f"Cleaned up {cleaned} orphaned container(s)")
            return cleaned

        except Exception as e:
            logger.error(f"Error cleaning up orphaned containers: {e}")
            return 0


