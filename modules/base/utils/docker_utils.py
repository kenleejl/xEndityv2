import docker
import logging
import os
import pwd
import grp
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

try:
    client = docker.from_env()
except Exception as e:
    logger.warning(f"Failed to initialize Docker client: {e}")
    client = None

class DockerUtils:
    """Utility class for Docker operations"""
    
    @staticmethod
    def is_docker_available() -> bool:
        """
        Check if Docker is available and running
        
        Returns:
            True if Docker is available, False otherwise
        """
        try:
            if client is None:
                return False
            client.ping()
            return True
        except Exception as e:
            logger.error(f"Docker is not available: {e}")
            return False
    
    @staticmethod
    def get_docker_info() -> Dict[str, Any]:
        """
        Get Docker system information
        
        Returns:
            Dictionary with Docker system info, empty dict if unavailable
        """
        try:
            if client is None:
                return {}
            return client.info()
        except Exception as e:
            logger.error(f"Failed to get Docker info: {e}")
            return {}
    
    @staticmethod
    def container_exists(name: str) -> bool:
        """
        Check if a container exists
        
        Args:
            name: Container name or ID
            
        Returns:
            True if container exists, False otherwise
        """
        try:
            if client is None:
                return False
            client.containers.get(name)
            return True
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logger.error(f"Error checking container existence: {e}")
            return False
    
    @staticmethod
    def network_exists(name: str) -> bool:
        """
        Check if a network exists
        
        Args:
            name: Network name
            
        Returns:
            True if network exists, False otherwise
        """
        try:
            if client is None:
                return False
            client.networks.get(name)
            return True
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logger.error(f"Error checking network existence: {e}")
            return False
    
    @staticmethod
    def get_current_user_info() -> Tuple[int, int]:
        """
        Get current user and group IDs
        
        Returns:
            Tuple of (user_id, group_id)
        """
        try:
            current_user = pwd.getpwuid(os.getuid())
            user_id = current_user.pw_uid
            group_id = current_user.pw_gid
            return user_id, group_id
        except Exception as e:
            logger.warning(f"Failed to get user info: {e}")
            return 0, 0
    
    @staticmethod
    def determine_mongodb_connection(mongodb_host: str, mongodb_port: int) -> Tuple[str, str]:
        """
        Determine the appropriate MongoDB connection settings for Docker containers
        
        Args:
            mongodb_host: MongoDB host from settings
            mongodb_port: MongoDB port from settings
            
        Returns:
            Tuple of (host_for_container, network_mode)
        """
        if mongodb_host == 'localhost':
            # Check if MongoDB is running in Docker
            if DockerUtils.container_exists('xendity-mongodb'):
                if DockerUtils.network_exists('xendity_xendity-network'):
                    return 'xendity-mongodb', 'xendity_xendity-network'
                else:
                    return 'xendity-mongodb', 'bridge'
            else:
                # MongoDB is running on localhost, use host networking
                return 'host.docker.internal', 'host'
        else:
            # MongoDB is on a remote host
            return mongodb_host, 'host'
    
    @staticmethod
    def run_container(
        image: str,
        command: Optional[List[str]] = None,
        environment: Optional[Dict[str, str]] = None,
        volumes: Optional[Dict[str, Dict[str, str]]] = None,
        network_mode: Optional[str] = None,
        name: Optional[str] = None,
        remove: bool = True,
        detach: bool = True,
        user: Optional[str] = None,
        working_dir: Optional[str] = None,
        extra_hosts: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, Optional[Any], Optional[str]]:
        """
        Run a Docker container with specified configuration
        
        Args:
            image: Docker image name
            command: Command to run in container
            environment: Environment variables
            volumes: Volume mounts (host_path: {'bind': container_path, 'mode': 'rw'})
            network_mode: Network mode for container
            name: Container name
            remove: Whether to remove container after completion
            detach: Whether to run in detached mode
            user: User to run as (format: 'uid:gid')
            working_dir: Working directory in container
            extra_hosts: Extra host entries
            
        Returns:
            Tuple of (success, container_or_logs, error_message)
        """
        try:
            if client is None:
                return False, None, "Docker client not available"
            
            # Prepare kwargs for container run
            kwargs = {
                'image': image,
                'remove': remove,
                'detach': detach
            }
            
            if command:
                kwargs['command'] = command
            if environment:
                kwargs['environment'] = environment
            if volumes:
                kwargs['volumes'] = volumes
            if network_mode:
                kwargs['network_mode'] = network_mode
            if name:
                kwargs['name'] = name
            if user:
                kwargs['user'] = user
            if working_dir:
                kwargs['working_dir'] = working_dir
            if extra_hosts:
                kwargs['extra_hosts'] = extra_hosts
            
            # Run the container
            result = client.containers.run(**kwargs)
            
            if detach:
                # Return the container object
                return True, result, None
            else:
                # Return the logs
                return True, result.decode('utf-8') if isinstance(result, bytes) else result, None
                
        except docker.errors.ImageNotFound as e:
            error_msg = f"Docker image not found: {e}"
            logger.error(error_msg)
            return False, None, error_msg
        except docker.errors.ContainerError as e:
            error_msg = f"Container execution failed: {e}"
            logger.error(error_msg)
            return False, None, error_msg
        except docker.errors.APIError as e:
            error_msg = f"Docker API error: {e}"
            logger.error(error_msg)
            return False, None, error_msg
        except Exception as e:
            error_msg = f"Unexpected error running container: {e}"
            logger.error(error_msg)
            return False, None, error_msg
    
    @staticmethod
    def get_container_logs(container_name: str, tail: int = 100) -> Optional[str]:
        """
        Get logs from a container
        
        Args:
            container_name: Container name or ID
            tail: Number of lines to tail
            
        Returns:
            Container logs as string, None if error
        """
        try:
            if client is None:
                return None
            container = client.containers.get(container_name)
            logs = container.logs(tail=tail, stream=False)
            return logs.decode('utf-8') if isinstance(logs, bytes) else logs
        except Exception as e:
            logger.error(f"Failed to get container logs: {e}")
            return None
    
    @staticmethod
    def get_container_status(container_name: str) -> Optional[str]:
        """
        Get the status of a container
        
        Args:
            container_name: Container name or ID
            
        Returns:
            Container status string, None if not found
        """
        try:
            if client is None:
                return None
            container = client.containers.get(container_name)
            return container.status
        except docker.errors.NotFound:
            return None
        except Exception as e:
            logger.error(f"Failed to get container status: {e}")
            return None
    
    @staticmethod
    def wait_for_container(container_name: str, timeout: int = 300) -> Tuple[bool, Optional[int]]:
        """
        Wait for a container to complete
        
        Args:
            container_name: Container name or ID
            timeout: Maximum time to wait in seconds
            
        Returns:
            Tuple of (success, exit_code)
        """
        try:
            if client is None:
                return False, None
            container = client.containers.get(container_name)
            result = container.wait(timeout=timeout)
            return True, result['StatusCode']
        except Exception as e:
            logger.error(f"Error waiting for container: {e}")
            return False, None
    
    @staticmethod
    def stop_container(container_name: str, timeout: int = 10) -> bool:
        """
        Stop a running container
        
        Args:
            container_name: Container name or ID
            timeout: Time to wait before forcibly killing
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if client is None:
                return False
            container = client.containers.get(container_name)
            container.stop(timeout=timeout)
            return True
        except Exception as e:
            logger.error(f"Failed to stop container: {e}")
            return False
    
    @staticmethod
    def remove_container(container_name: str, force: bool = False) -> bool:
        """
        Remove a container
        
        Args:
            container_name: Container name or ID
            force: Force removal of running container
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if client is None:
                return False
            container = client.containers.get(container_name)
            container.remove(force=force)
            return True
        except Exception as e:
            logger.error(f"Failed to remove container: {e}")
            return False
    
    @staticmethod
    def pull_image(image: str) -> bool:
        """
        Pull a Docker image
        
        Args:
            image: Image name and tag
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if client is None:
                return False
            client.images.pull(image)
            return True
        except Exception as e:
            logger.error(f"Failed to pull image {image}: {e}")
            return False
