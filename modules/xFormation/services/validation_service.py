"""
Validation service for automated verification of emulated devices.

Performs boot checks, service reachability, port connectivity,
and shell access tests against emulation telemetry data.
"""
import logging
import socket

from modules.xFormation.models import EmulationInstance, EmulationTelemetry, ValidationResult

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 3


class ValidationService:
    """Runs automated verification checks on emulated device instances."""

    @classmethod
    def validate(cls, instance: EmulationInstance,
                 telemetry: EmulationTelemetry | None = None) -> ValidationResult | None:
        """
        Run all validation checks for an instance.
        Uses the most recent telemetry if not provided.
        """
        if telemetry is None:
            telemetry = instance.telemetry_records.first()

        if telemetry is None:
            logger.warning("No telemetry available for validation of instance %s", instance.id)
            return None

        boot_ok, boot_details = cls._check_boot(telemetry)
        services_ok, services_details = cls._check_services(instance, telemetry)
        ports_ok, ports_details = cls._check_ports(instance, telemetry)
        shell_ok, shell_details = cls._check_shell(instance)

        checks = [boot_ok, services_ok, ports_ok, shell_ok]
        passed = sum(checks)
        if passed == len(checks):
            overall = 'pass'
        elif passed == 0:
            overall = 'fail'
        else:
            overall = 'partial'

        result = ValidationResult.objects.create(
            instance=instance,
            telemetry=telemetry,
            overall_status=overall,
            boot_check=boot_ok,
            services_check=services_ok,
            ports_check=ports_ok,
            shell_check=shell_ok,
            check_details={
                'boot': boot_details,
                'services': services_details,
                'ports': ports_details,
                'shell': shell_details,
            },
        )

        logger.info(
            "Validation for instance %s: %s (%d/%d checks passed)",
            instance.id, overall, passed, len(checks),
        )
        return result

    @classmethod
    def _check_boot(cls, telemetry: EmulationTelemetry) -> tuple[bool, dict]:
        """Verify the device booted without kernel panic and has running processes."""
        details = {
            'kernel_panic': telemetry.kernel_panic,
            'process_count': telemetry.health_data.get('nproc', 0),
            'exec_count': telemetry.health_data.get('nexecs', 0),
        }

        ok = (
            not telemetry.kernel_panic
            and details['process_count'] > 0
        )
        details['passed'] = ok
        details['reason'] = 'Boot successful' if ok else (
            'Kernel panic detected' if telemetry.kernel_panic
            else 'No processes detected'
        )
        return ok, details

    @classmethod
    def _check_services(cls, instance: EmulationInstance,
                        telemetry: EmulationTelemetry) -> tuple[bool, dict]:
        """Verify that expected services are responding (HTTP health check)."""
        details = {'web_interface_url': instance.web_interface_url, 'checks': []}

        if not instance.web_interface_url:
            has_web_ports = any(
                b.get('guest_port') in (80, 443, 8080, 8443)
                for b in telemetry.network_binds
            )
            if not has_web_ports:
                details['reason'] = 'No web services detected (not a failure)'
                details['passed'] = True
                return True, details

            details['reason'] = 'Web ports detected but no URL configured'
            details['passed'] = False
            return False, details

        try:
            import requests
            resp = requests.get(instance.web_interface_url, timeout=5, verify=False)
            check = {
                'url': instance.web_interface_url,
                'status_code': resp.status_code,
                'reachable': True,
            }
            details['checks'].append(check)
            ok = resp.status_code < 500
            details['passed'] = ok
            details['reason'] = f'HTTP {resp.status_code}' if ok else f'HTTP {resp.status_code} (server error)'
            return ok, details
        except Exception as e:
            details['checks'].append({
                'url': instance.web_interface_url,
                'reachable': False,
                'error': str(e),
            })
            details['passed'] = False
            details['reason'] = f'Connection failed: {e}'
            return False, details

    @classmethod
    def _check_ports(cls, instance: EmulationInstance,
                     telemetry: EmulationTelemetry) -> tuple[bool, dict]:
        """TCP connect check for all detected ports."""
        details = {'checks': []}

        host_ip = instance.host_ip
        if not host_ip or not instance.host_ports:
            if telemetry.network_binds:
                details['reason'] = 'No host port mappings available for connectivity check'
                details['passed'] = False
                return False, details
            details['reason'] = 'No ports detected'
            details['passed'] = True
            return True, details

        reachable = 0
        total = 0
        for service, port_info in instance.host_ports.items():
            port = port_info.get('port')
            if port is None:
                continue
            total += 1
            is_open = cls._tcp_connect(host_ip, port)
            details['checks'].append({
                'service': service,
                'host': host_ip,
                'port': port,
                'reachable': is_open,
            })
            if is_open:
                reachable += 1

        if total == 0:
            details['passed'] = True
            details['reason'] = 'No ports to check'
            return True, details

        ok = reachable == total
        details['passed'] = ok
        details['reason'] = f'{reachable}/{total} ports reachable'
        return ok, details

    @classmethod
    def _check_shell(cls, instance: EmulationInstance) -> tuple[bool, dict]:
        """Check if a shell (telnet) is reachable on the instance."""
        details = {}

        host_ip = instance.host_ip
        if not host_ip:
            details['passed'] = False
            details['reason'] = 'No host IP available'
            return False, details

        for port in (23, 2323, 9999):
            if cls._tcp_connect(host_ip, port):
                details['passed'] = True
                details['port'] = port
                details['reason'] = f'Shell reachable on port {port}'
                return True, details

        if instance.host_ports:
            for service, info in instance.host_ports.items():
                if 'telnet' in service.lower() or 'shell' in service.lower():
                    port = info.get('port')
                    if port and cls._tcp_connect(host_ip, port):
                        details['passed'] = True
                        details['port'] = port
                        details['reason'] = f'Shell reachable via {service} on port {port}'
                        return True, details

        details['passed'] = False
        details['reason'] = 'No shell access detected on common ports'
        return False, details

    @classmethod
    def _tcp_connect(cls, host: str, port: int) -> bool:
        """Attempt a TCP connection to host:port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)
            result = sock.connect_ex((host, int(port)))
            sock.close()
            return result == 0
        except Exception:
            return False
