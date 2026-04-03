"""
Docker-based Penguin Service for xFormation

Manages penguin containers directly via Docker API, replacing subprocess calls.
This provides better control, cleanup, and monitoring capabilities.
"""

import logging
import random
import docker
import os
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from modules.base.utils.docker_utils import DockerUtils

logger = logging.getLogger(__name__)

class DockerPenguinService:
    """
    Service for managing penguin emulation via Docker API
    
    Provides direct Docker container control for penguin instances,
    eliminating issues with subprocess cleanup and network orphaning.
    """
    
    PENGUIN_IMAGE = "rehosting/penguin"
    NETWORK_PREFIX = "penguin_nw_"
    CONTAINER_PREFIX = "penguin_"
    
    @staticmethod
    def is_available() -> bool:
        """
        Check if Docker is available and penguin image exists
        
        Returns:
            True if Docker and penguin image are available
        """
        if not DockerUtils.is_docker_available():
            logger.warning("Docker is not available")
            return False
        
        try:
            client = docker.from_env()
            client.images.get(DockerPenguinService.PENGUIN_IMAGE)
            return True
        except docker.errors.ImageNotFound:
            logger.warning(f"Penguin image {DockerPenguinService.PENGUIN_IMAGE} not found")
            return False
        except Exception as e:
            logger.error(f"Error checking penguin availability: {e}")
            return False
    
    @staticmethod
    def find_available_subnet() -> str:
        """
        Find an available subnet in 192.168.x.0/24 range
        
        Returns:
            Available subnet string (e.g., "192.168.42.0/24")
            
        Raises:
            RuntimeError: If no available subnet found or Docker unavailable
        """
        if not DockerUtils.is_docker_available():
            raise RuntimeError("Docker is not available")
        
        client = docker.from_env()

        # Collect all subnets currently in use by Docker networks
        used_subnets = set()
        for network in client.networks.list():
            try:
                ipam_config = network.attrs.get('IPAM', {}).get('Config', [])
                for config in ipam_config:
                    subnet_value = config.get('Subnet')
                    if subnet_value:
                        used_subnets.add(subnet_value)
            except Exception:
                # If we cannot inspect a network's IPAM config, skip it
                continue
        
        # Try to find an available subnet
        for i in range(256):
            subnet = f"192.168.{i}.0/24"
            
            # Check if subnet is in use
            if subnet not in used_subnets:
                logger.info(f"Found available subnet: {subnet}")
                return subnet
        
        raise RuntimeError("No available subnet found in 192.168.x.0/24 range")
    
    @staticmethod
    def create_penguin_network(subnet: str = None) -> Tuple[str, str, str, str]:
        """
        Create Docker network for penguin instance
        
        Args:
            subnet: Optional subnet to use (e.g., "10.0.2.0/24"), auto-detected if None
            
        Returns:
            Tuple of (network_name, subnet, gateway, container_ip)
            
        Raises:
            RuntimeError: If Docker unavailable or network creation fails
        """
        if not DockerUtils.is_docker_available():
            raise RuntimeError("Docker is not available")
        
        client = docker.from_env()
        
        # Generate unique network name
        network_name = f"{DockerPenguinService.NETWORK_PREFIX}{random.randint(10000, 99999)}"
        
        # Find subnet if not provided
        if not subnet:
            subnet = DockerPenguinService.find_available_subnet()
        
        # Calculate gateway and container IP from subnet
        # For subnet 192.168.x.0/24: gateway=192.168.x.1, container=192.168.x.2
        # For subnet 10.0.2.0/24: gateway=10.0.2.1, container=10.0.2.2
        subnet_base = subnet.rsplit('.', 2)[0]  # Get "192.168.x" or "10.0.2"
        third_octet = subnet.split('.')[2]
        subnet_prefix = '.'.join(subnet.split('.')[:3])  # "192.168.x" or "10.0.2"
        
        gateway = f"{subnet_prefix}.1"
        container_ip = f"{subnet_prefix}.2"
        
        try:
            # Create network with IPAM configuration
            ipam_pool = docker.types.IPAMPool(
                subnet=subnet,
                gateway=gateway
            )
            ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
            
            network = client.networks.create(
                name=network_name,
                driver="bridge",
                ipam=ipam_config
            )
            
            logger.info(f"Created Docker network: {network_name} (subnet: {subnet}, gateway: {gateway}, IP: {container_ip})")
            return network_name, subnet, gateway, container_ip
            
        except Exception as e:
            logger.error(f"Failed to create Docker network: {e}")
            raise RuntimeError(f"Failed to create Docker network: {e}")
    
    @staticmethod
    def prepare_volume_mappings(
        config_path: str,
        penguin_project_path: str
    ) -> Tuple[Dict[str, Dict[str, str]], str]:
        """
        Prepare volume mappings for penguin container
        
        Replicates the bash script's volume mapping logic:
        - Maps parent directory of project to /host_<dirname>
        - Translates host paths to container paths
        
        Args:
            config_path: Path to config.yaml on host
            penguin_project_path: Path to penguin project directory on host
            
        Returns:
            Tuple of (volumes dict for Docker, config path in container)
        """
        volumes = {}
        
        try:
            # Get the project directory
            project_path = Path(penguin_project_path).resolve()
            if not project_path.exists():
                raise ValueError(f"Penguin project path does not exist: {project_path}")
            
            # Map the parent directory of the project
            # This matches the bash script logic: maps parent, then accesses subdirectory
            parent = project_path.parent
            guest_base_name = parent.name
            guest_path = f"/host_{guest_base_name}"
            
            volumes[str(parent.absolute())] = {
                'bind': guest_path,
                'mode': 'rw'
            }
            
            # Calculate container path for config
            # If project is at /path/to/projects/rootfs
            # Parent is /path/to/projects
            # Mapped to /host_projects
            # Config is at /host_projects/rootfs/config.yaml
            relative_project = project_path.name
            config_guest_path = f"{guest_path}/{relative_project}/config.yaml"
            
            logger.info(f"Volume mapping: {parent} -> {guest_path}")
            logger.info(f"Config path in container: {config_guest_path}")
            
            return volumes, config_guest_path
            
        except Exception as e:
            logger.error(f"Error preparing volume mappings: {e}")
            raise
    
    @staticmethod
    def run_penguin_container(
        instance_name: str,
        config_path: str,
        penguin_project_path: str,
        network_name: str,
        container_ip: str,
        cpu_limit: float = 2.0,
        memory_limit: str = "1g",
        gateway: str = None,
    ) -> Any:
        """
        Run penguin container with proper configuration.

        Networking is handled at the Docker API level: the penguin container
        is connected to the designated network (bridge or macvlan) before
        starting. The penguin Python binary inside the container only receives
        the 'run' subcommand — wrapper flags like --subnet and
        --extra_docker_args are NOT supported by the container-internal binary.

        Args:
            instance_name: Name for the penguin orchestrator container
            config_path: Path to config.yaml on host
            penguin_project_path: Path to penguin project on host
            network_name: Docker network to attach the container to
            container_ip: Static IP for the network connection (empty for IPAM)
            cpu_limit: CPU limit in cores
            memory_limit: Memory limit (e.g., "1g", "512m")
            gateway: Gateway IP passed as GATEWAY env var to firmware

        Returns:
            Docker container object

        Raises:
            RuntimeError: If container creation fails
        """
        if not DockerUtils.is_docker_available():
            raise RuntimeError("Docker is not available")

        try:
            client = docker.from_env()

            # Prepare volumes and get container config path
            volumes, config_guest_path = DockerPenguinService.prepare_volume_mappings(
                config_path, penguin_project_path
            )

            # Mount Docker socket so penguin can create the firmware (rootfs) container
            volumes['/var/run/docker.sock'] = {'bind': '/var/run/docker.sock', 'mode': 'rw'}

            # Prepare environment variables
            project_path = Path(penguin_project_path)
            guest_project = f"/host_{project_path.parent.name}/{project_path.name}"

            environment = {
                'CONTAINER_IP': container_ip,
                'CONTAINER_NAME': instance_name,
                'PENGUIN_PROJECT_DIR': guest_project,
            }
            if gateway:
                environment['GATEWAY'] = gateway

            # Build penguin command — plain run, no wrapper flags.
            # Networking is attached via Docker API before container start.
            command = ['penguin', 'run', config_guest_path]

            # Generate container name with prefix
            container_name = f"{DockerPenguinService.CONTAINER_PREFIX}{instance_name}"

            logger.info(f"Creating penguin container: {container_name}")
            logger.info(f"Command: {' '.join(command)}")
            logger.info(f"Volumes: {volumes}")
            logger.info(f"Environment: {environment}")

            # Create container (don't start yet — network must be attached first)
            container = client.containers.create(
                image=DockerPenguinService.PENGUIN_IMAGE,
                command=command,
                name=container_name,
                detach=True,
                environment=environment,
                volumes=volumes,
                cap_add=['NET_BIND_SERVICE', 'NET_ADMIN'],
                mem_limit=memory_limit,
                nano_cpus=int(cpu_limit * 1e9),
                stdin_open=False,
                tty=False,
            )

            # Attach container to the designated network (bridge or macvlan)
            network = client.networks.get(network_name)
            if container_ip:
                network.connect(container, ipv4_address=container_ip)
            else:
                network.connect(container)

            # Start the container
            container.start()

            logger.info(f"Started penguin container: {container_name} at {container_ip}")
            return container

        except docker.errors.ImageNotFound:
            error = f"Docker image {DockerPenguinService.PENGUIN_IMAGE} not found. Please build or pull the image first."
            logger.error(error)
            raise RuntimeError(error)
        except docker.errors.APIError as e:
            error = f"Docker API error while creating container: {e}"
            logger.error(error)
            raise RuntimeError(error)
        except Exception as e:
            error = f"Failed to run penguin container: {e}"
            logger.error(error)
            raise RuntimeError(error)
    
    @staticmethod
    def get_container_logs(container_name: str, stream: bool = False, follow: bool = False):
        """
        Get logs from a penguin container
        
        Args:
            container_name: Container name (with or without prefix)
            stream: If True, return generator of log lines
            follow: If True, follow log output (requires stream=True)
            
        Returns:
            Log string or generator of log lines
        """
        if not DockerUtils.is_docker_available():
            return None
        
        try:
            # Add prefix if not present
            if not container_name.startswith(DockerPenguinService.CONTAINER_PREFIX):
                container_name = f"{DockerPenguinService.CONTAINER_PREFIX}{container_name}"
            
            client = docker.from_env()
            container = client.containers.get(container_name)
            
            logs = container.logs(stream=stream, follow=follow, stdout=True, stderr=True)
            
            if stream:
                # Return generator
                return logs
            else:
                # Return full log as string
                return logs.decode('utf-8') if isinstance(logs, bytes) else logs
                
        except docker.errors.NotFound:
            logger.warning(f"Container {container_name} not found")
            return None
        except Exception as e:
            logger.error(f"Error getting container logs: {e}")
            return None
    
    @staticmethod
    def stop_penguin_container(
        container_name: str,
        network_name: str = None,
        timeout: int = 10
    ) -> bool:
        """
        Stop penguin container and clean up network
        
        Args:
            container_name: Container name (with or without prefix)
            network_name: Network to remove (optional)
            timeout: Timeout for graceful shutdown
            
        Returns:
            True if successful
        """
        if not DockerUtils.is_docker_available():
            logger.warning("Docker is not available for cleanup")
            return False
        
        success = True
        client = docker.from_env()
        
        # Add prefix if not present
        if not container_name.startswith(DockerPenguinService.CONTAINER_PREFIX):
            container_name = f"{DockerPenguinService.CONTAINER_PREFIX}{container_name}"
        
        # Stop and remove container
        try:
            container = client.containers.get(container_name)
            logger.info(f"Stopping container: {container_name}")
            container.stop(timeout=timeout)
            logger.info(f"Removing container: {container_name}")
            container.remove()
            logger.info(f"Successfully stopped and removed container: {container_name}")
        except docker.errors.NotFound:
            logger.warning(f"Container {container_name} not found (may already be removed)")
        except Exception as e:
            logger.error(f"Error stopping container {container_name}: {e}")
            success = False
        
        # Remove network (with retry logic for disconnecting containers)
        if network_name:
            try:
                network = client.networks.get(network_name)
                logger.info(f"Removing network: {network_name}")
                
                # Try to disconnect any remaining containers first
                try:
                    network.reload()
                    containers = network.attrs.get('Containers', {})
                    for container_id in containers.keys():
                        try:
                            network.disconnect(container_id, force=True)
                            logger.info(f"Force disconnected container {container_id[:12]} from network")
                        except:
                            pass
                except:
                    pass
                
                # Now remove the network
                network.remove()
                logger.info(f"Successfully removed network: {network_name}")
            except docker.errors.NotFound:
                logger.warning(f"Network {network_name} not found (may already be removed)")
            except Exception as e:
                logger.error(f"Error removing network {network_name}: {e}")
                # Try force removal
                try:
                    import subprocess
                    subprocess.run(['docker', 'network', 'rm', '-f', network_name], 
                                 capture_output=True, timeout=10)
                    logger.info(f"Force removed network {network_name} via CLI")
                except:
                    success = False
        
        return success
    
    @staticmethod
    def get_container_status(container_name: str) -> Optional[str]:
        """
        Get the status of a penguin container
        
        Args:
            container_name: Container name (with or without prefix)
            
        Returns:
            Container status string ('running', 'exited', etc.) or None if not found
        """
        if not DockerUtils.is_docker_available():
            return None
        
        try:
            # Add prefix if not present
            if not container_name.startswith(DockerPenguinService.CONTAINER_PREFIX):
                container_name = f"{DockerPenguinService.CONTAINER_PREFIX}{container_name}"
            
            client = docker.from_env()
            container = client.containers.get(container_name)
            return container.status
        except docker.errors.NotFound:
            return None
        except Exception as e:
            logger.error(f"Error getting container status: {e}")
            return None
    
    @staticmethod
    def cleanup_orphaned_networks() -> int:
        """
        Cleanup orphaned penguin bridge networks (networks with no containers attached).

        Skips macvlan networks — those are persistent infrastructure and must not be
        removed on startup even when no containers are currently attached.

        Returns:
            Number of networks cleaned up
        """
        if not DockerUtils.is_docker_available():
            logger.warning("Docker is not available for cleanup")
            return 0

        client = docker.from_env()
        cleaned = 0

        try:
            networks = client.networks.list()
            for network in networks:
                if network.name.startswith(DockerPenguinService.NETWORK_PREFIX):
                    try:
                        # Reload to get fresh data
                        network.reload()

                        # Skip macvlan networks — persistent LAN infrastructure
                        if network.attrs.get('Driver') == 'macvlan':
                            logger.debug(f"Skipping macvlan network {network.name} (persistent infrastructure)")
                            continue

                        containers = network.attrs.get('Containers', {})

                        # If no containers attached, remove it
                        if not containers or len(containers) == 0:
                            logger.info(f"Removing orphaned network: {network.name}")
                            network.remove()
                            cleaned += 1
                            logger.info(f"Removed orphaned network: {network.name}")
                        else:
                            logger.debug(f"Network {network.name} has {len(containers)} containers attached")
                    except docker.errors.NotFound:
                        # Already removed
                        pass
                    except Exception as e:
                        logger.warning(f"Error checking/removing network {network.name}: {e}")
        except Exception as e:
            logger.error(f"Error during orphaned network cleanup: {e}")

        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} orphaned penguin networks")

        return cleaned
    
    @staticmethod
    def cleanup_penguin_resources(container_pattern: str = None) -> int:
        """
        Clean up orphaned penguin containers and networks
        
        Args:
            container_pattern: Pattern to match container names (default: all penguin containers)
            
        Returns:
            Number of resources cleaned up
        """
        if not DockerUtils.is_docker_available():
            logger.warning("Docker is not available for cleanup")
            return 0
        
        client = docker.from_env()
        cleaned = 0
        
        # Clean up containers
        try:
            # Get all containers with penguin prefix
            all_containers = client.containers.list(all=True)
            for container in all_containers:
                if container.name.startswith(DockerPenguinService.CONTAINER_PREFIX):
                    # Check if we should clean this one
                    if container_pattern and container_pattern not in container.name:
                        continue
                    
                    try:
                        logger.info(f"Cleaning up orphaned container: {container.name} (status: {container.status})")
                        if container.status == 'running':
                            container.stop(timeout=5)
                        container.remove()
                        cleaned += 1
                    except Exception as e:
                        logger.warning(f"Error cleaning up container {container.name}: {e}")
        except Exception as e:
            logger.error(f"Error during container cleanup: {e}")
        
        # Clean up networks (use dedicated method for better handling)
        network_cleaned = DockerPenguinService.cleanup_orphaned_networks()
        cleaned += network_cleaned
        
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} orphaned penguin resources total")
        else:
            logger.info("No orphaned penguin resources found")
        
        return cleaned
    
    @staticmethod
    def run_penguin_init(
        firmware_base_path: str,
        rootfs_filename: str = "rootfs.tar.gz",
        force: bool = True
    ) -> Tuple[bool, str, str]:
        """
        Run penguin init command using Docker API
        
        Args:
            firmware_base_path: Base path containing rootfs.tar.gz
            rootfs_filename: Name of the rootfs file (default: rootfs.tar.gz)
            force: Use --force flag to overwrite existing init
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        if not DockerUtils.is_docker_available():
            return False, "", "Docker is not available"
        
        try:
            client = docker.from_env()
            
            # Convert to Path for easier manipulation
            base_path = Path(firmware_base_path).resolve()
            
            # Check if rootfs file exists
            rootfs_path = base_path / rootfs_filename
            if not rootfs_path.exists():
                return False, "", f"Rootfs file not found: {rootfs_path}"
            
            # Prepare volume mappings
            # Map the firmware base directory to /host_work
            volumes = {
                str(base_path): {
                    'bind': '/host_work',
                    'mode': 'rw'
                }
            }
            
            # Build penguin init command
            command = ['penguin', 'init', rootfs_filename]
            if force:
                command.append('--force')
            
            # Set output base to create projects directory in the mapped volume
            command.extend(['--output_base', '/host_work/projects'])
            
            # Get user ID for proper permissions
            user_id = os.getuid()
            group_id = os.getgid()
            
            logger.info(f"Running penguin init via Docker")
            logger.info(f"Base path: {base_path}")
            logger.info(f"Command: {' '.join(command)}")
            logger.info(f"Volumes: {volumes}")
            
            # Run container with penguin init
            # Use run() instead of create() since we want to wait for completion
            result = client.containers.run(
                image=DockerPenguinService.PENGUIN_IMAGE,
                command=command,
                volumes=volumes,
                working_dir='/host_work',
                user=f"{user_id}:{group_id}",
                remove=True,  # Auto-remove after completion
                stdout=True,
                stderr=True,
                detach=False  # Wait for completion
            )
            
            # Decode output
            output = result.decode('utf-8') if isinstance(result, bytes) else result
            
            logger.info(f"Penguin init completed successfully")
            return True, output, ""
            
        except docker.errors.ContainerError as e:
            # Container exited with non-zero code
            error_output = e.stderr.decode('utf-8') if isinstance(e.stderr, bytes) else str(e.stderr)
            logger.error(f"Penguin init failed: {error_output}")
            return False, "", error_output
        except docker.errors.ImageNotFound:
            error = f"Docker image {DockerPenguinService.PENGUIN_IMAGE} not found"
            logger.error(error)
            return False, "", error
        except Exception as e:
            error = f"Error running penguin init: {e}"
            logger.error(error)
            return False, "", str(e)
    
    @staticmethod
    def get_container_stats(container_name: str) -> Optional[Dict]:
        """
        Get resource usage stats for a container
        
        Args:
            container_name: Container name (with or without prefix)
            
        Returns:
            Dict with CPU, memory usage stats, or None if unavailable
        """
        if not DockerUtils.is_docker_available():
            return None
        
        try:
            # Add prefix if not present
            if not container_name.startswith(DockerPenguinService.CONTAINER_PREFIX):
                container_name = f"{DockerPenguinService.CONTAINER_PREFIX}{container_name}"
            
            client = docker.from_env()
            container = client.containers.get(container_name)
            
            stats = container.stats(stream=False)
            
            # Calculate CPU percentage
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            cpu_percent = 0.0
            if system_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * len(stats['cpu_stats']['cpu_usage'].get('percpu_usage', [])) * 100.0
            
            # Calculate memory usage
            memory_usage = stats['memory_stats'].get('usage', 0)
            memory_limit = stats['memory_stats'].get('limit', 0)
            memory_percent = (memory_usage / memory_limit * 100.0) if memory_limit > 0 else 0.0
            
            return {
                'cpu_percent': round(cpu_percent, 2),
                'memory_usage_mb': round(memory_usage / (1024 * 1024), 2),
                'memory_limit_mb': round(memory_limit / (1024 * 1024), 2),
                'memory_percent': round(memory_percent, 2),
            }
            
        except docker.errors.NotFound:
            logger.warning(f"Container {container_name} not found")
            return None
        except Exception as e:
            logger.error(f"Error getting container stats: {e}")
            return None

