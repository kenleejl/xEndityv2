"""
Macvlan Network Service for xFormation

Manages macvlan Docker network creation and lifecycle
"""

import subprocess
import logging
import hashlib
import re
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class MacvlanNetworkService:
    """Service for managing macvlan Docker networks"""
    
    NETWORK_PREFIX = "xformation_macvlan"
    
    @staticmethod
    def get_host_network_info() -> Dict[str, str]:
        """
        Auto-detect host network configuration using ip command
        
        Returns:
            Dictionary with subnet, gateway, and parent_interface
        """
        try:
            # Get default route
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse: default via 192.168.1.1 dev eth0 ...
            route_line = result.stdout.strip()
            match = re.search(r'default via ([\d.]+) dev (\S+)', route_line)
            
            if not match:
                raise ValueError("Could not parse default route")
            
            gateway = match.group(1)
            parent_interface = match.group(2)
            
            # Get interface IP address
            result = subprocess.run(
                ['ip', 'addr', 'show', parent_interface],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse: inet 192.168.1.100/24 ...
            ip_match = re.search(r'inet ([\d.]+)/(\d+)', result.stdout)
            
            if not ip_match:
                raise ValueError(f"Could not parse IP for interface {parent_interface}")
            
            ip = ip_match.group(1)
            prefix_len = ip_match.group(2)
            
            # Calculate subnet from IP (simple /24 assumption for common case)
            if prefix_len == '24':
                subnet_base = '.'.join(ip.split('.')[:-1]) + '.0/24'
            elif prefix_len == '16':
                subnet_base = '.'.join(ip.split('.')[:-2]) + '.0.0/16'
            else:
                # Default to /24
                subnet_base = '.'.join(ip.split('.')[:-1]) + '.0/24'
            
            logger.info(f"Auto-detected network: subnet={subnet_base}, gateway={gateway}, interface={parent_interface}")
            
            return {
                'subnet': subnet_base,
                'gateway': gateway,
                'parent_interface': parent_interface
            }
        except Exception as e:
            logger.error(f"Failed to auto-detect network: {e}")
            # Fallback defaults
            return {
                'subnet': '192.168.1.0/24',
                'gateway': '192.168.1.1',
                'parent_interface': 'eth0'
            }
    
    @staticmethod
    def create_or_get_macvlan(subnet: str, gateway: str, parent_interface: Optional[str] = None) -> str:
        """
        Create or get existing macvlan network
        
        Args:
            subnet: Network subnet (e.g., '192.168.1.0/24')
            gateway: Gateway IP (e.g., '192.168.1.1')
            parent_interface: Parent network interface (auto-detected if None)
            
        Returns:
            Network name
        """
        # Generate network name from subnet hash
        subnet_hash = hashlib.md5(subnet.encode()).hexdigest()[:8]
        network_name = f"{MacvlanNetworkService.NETWORK_PREFIX}_{subnet_hash}"
        
        # Check if network already exists
        try:
            result = subprocess.run(
                ['docker', 'network', 'ls', '--filter', f'name={network_name}', '--format', '{{.Name}}'],
                capture_output=True,
                text=True,
                check=True
            )
            
            if network_name in result.stdout:
                logger.info(f"Macvlan network {network_name} already exists")
                return network_name
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to check for existing network: {e}")
        
        # Auto-detect parent interface if not provided
        if parent_interface is None:
            network_info = MacvlanNetworkService.get_host_network_info()
            parent_interface = network_info['parent_interface']
        
        # Create new macvlan network
        try:
            cmd = [
                'docker', 'network', 'create',
                '-d', 'macvlan',
                '--subnet', subnet,
                '--gateway', gateway,
                '-o', f'parent={parent_interface}',
                network_name
            ]
            
            logger.info(f"Creating macvlan network: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            logger.info(f"Created macvlan network {network_name}")
            return network_name
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create macvlan network: {e.stderr}")
            raise RuntimeError(f"Failed to create macvlan network: {e.stderr}")
    
    @staticmethod
    def get_network_info(network_name: str) -> Optional[Dict]:
        """
        Get information about a Docker network
        
        Args:
            network_name: Name of the network
            
        Returns:
            Network info dictionary or None if not found
        """
        try:
            result = subprocess.run(
                ['docker', 'network', 'inspect', network_name],
                capture_output=True,
                text=True,
                check=True
            )
            
            import json
            network_info = json.loads(result.stdout)
            return network_info[0] if network_info else None
            
        except subprocess.CalledProcessError:
            return None
    
    @staticmethod
    def cleanup_unused_networks():
        """
        Remove macvlan networks with zero attached containers
        """
        try:
            # List all xformation macvlan networks
            result = subprocess.run(
                ['docker', 'network', 'ls', '--filter', f'name={MacvlanNetworkService.NETWORK_PREFIX}', '--format', '{{.Name}}'],
                capture_output=True,
                text=True,
                check=True
            )
            
            networks = result.stdout.strip().split('\n')
            
            for network_name in networks:
                if not network_name:
                    continue
                    
                # Get network info
                info = MacvlanNetworkService.get_network_info(network_name)
                if info and len(info.get('Containers', {})) == 0:
                    # No containers attached, remove network
                    try:
                        subprocess.run(
                            ['docker', 'network', 'rm', network_name],
                            capture_output=True,
                            text=True,
                            check=True
                        )
                        logger.info(f"Removed unused macvlan network {network_name}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Failed to remove network {network_name}: {e.stderr}")
                        
        except Exception as e:
            logger.error(f"Error during network cleanup: {e}")
    
    @staticmethod
    def get_next_available_ip(network_name: str) -> Optional[str]:
        """
        Query Docker IPAM for next available IP (for display purposes)
        
        Args:
            network_name: Name of the network
            
        Returns:
            Next available IP address or None
        """
        info = MacvlanNetworkService.get_network_info(network_name)
        if not info:
            return None
        
        try:
            # Get subnet from IPAM config
            ipam_config = info['IPAM']['Config'][0]
            subnet = ipam_config['Subnet']
            gateway = ipam_config['Gateway']
            
            # Extract base IP
            base_ip = '.'.join(subnet.split('/')[0].split('.')[:-1])
            
            # Get all assigned IPs
            assigned_ips = set()
            assigned_ips.add(gateway)  # Gateway is reserved
            
            for container in info.get('Containers', {}).values():
                ip = container.get('IPv4Address', '').split('/')[0]
                if ip:
                    assigned_ips.add(ip)
            
            # Find next available IP (starting from .10 to avoid common static assignments)
            for i in range(10, 255):
                candidate = f"{base_ip}.{i}"
                if candidate not in assigned_ips:
                    return candidate
            
            return None
            
        except Exception as e:
            logger.error(f"Error calculating next available IP: {e}")
            return None
