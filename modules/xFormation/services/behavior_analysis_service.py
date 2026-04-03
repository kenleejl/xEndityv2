"""
Behavior analysis service for detecting suspicious or anomalous activity
in emulated firmware based on collected telemetry data.

Uses rule-based detection across network, process, kernel, resource,
and device access categories.
"""
import logging

from modules.xFormation.models import EmulationTelemetry, BehaviorFinding

logger = logging.getLogger(__name__)

SUSPICIOUS_PORTS = {
    4444: "Metasploit default listener",
    5555: "Common backdoor / Android debug",
    6667: "IRC (commonly used by botnets)",
    6697: "IRC over TLS (botnet C2)",
    31337: "Back Orifice / elite backdoor",
    1337: "Common hacker port",
    12345: "NetBus trojan",
    27374: "SubSeven trojan",
    65535: "Maximum port (often probed)",
}

SUSPICIOUS_PROCESSES = {
    'nc': "Netcat - potential reverse shell",
    'ncat': "Ncat - potential reverse shell",
    'socat': "Socket relay - potential tunneling",
    'meterpreter': "Metasploit payload",
    'payload': "Generic payload binary",
    'backdoor': "Named backdoor binary",
    'cryptominer': "Cryptocurrency miner",
    'xmrig': "XMRig cryptocurrency miner",
    'minerd': "Cryptocurrency miner daemon",
}

SENSITIVE_DEVICES = {
    '/dev/mem': "Direct physical memory access",
    '/dev/kmem': "Kernel virtual memory access",
    '/dev/port': "Direct I/O port access",
    '/dev/sda': "Raw disk access",
    '/dev/hda': "Raw disk access",
    '/dev/mtd0': "Raw flash partition access",
    '/dev/mtdblock0': "Raw flash block access",
}


class BehaviorAnalysisService:
    """Analyzes telemetry data for suspicious behaviors using rule-based detection."""

    @classmethod
    def analyze(cls, telemetry: EmulationTelemetry) -> list[BehaviorFinding]:
        """
        Run all behavior analysis rules against the given telemetry.
        Returns the list of BehaviorFinding objects created.
        """
        findings = []

        findings.extend(cls._check_kernel_panic(telemetry))
        findings.extend(cls._check_suspicious_ports(telemetry))
        findings.extend(cls._check_wildcard_binds(telemetry))
        findings.extend(cls._check_suspicious_processes(telemetry))
        findings.extend(cls._check_tmp_execution(telemetry))
        findings.extend(cls._check_sensitive_device_access(telemetry))
        findings.extend(cls._check_resource_anomalies(telemetry))

        logger.info(
            "Behavior analysis for telemetry %s: %d findings",
            telemetry.id, len(findings)
        )
        return findings

    @classmethod
    def _create_finding(cls, telemetry, severity, category, title, description, evidence=None):
        return BehaviorFinding.objects.create(
            telemetry=telemetry,
            severity=severity,
            category=category,
            title=title,
            description=description,
            evidence=evidence or {},
        )

    @classmethod
    def _check_kernel_panic(cls, telemetry: EmulationTelemetry) -> list:
        findings = []
        if telemetry.kernel_panic:
            findings.append(cls._create_finding(
                telemetry, 'critical', 'kernel',
                'Kernel Panic Detected',
                'The emulated firmware experienced a kernel panic during execution. '
                'This indicates a critical failure in the boot process or during runtime, '
                'which may be caused by missing drivers, incompatible kernel, or firmware corruption.',
                evidence={'console_snippet': (telemetry.console_snippet or '')[:500]},
            ))
        return findings

    @classmethod
    def _check_suspicious_ports(cls, telemetry: EmulationTelemetry) -> list:
        findings = []
        for bind in telemetry.network_binds:
            port = bind.get('guest_port', 0)
            if port in SUSPICIOUS_PORTS:
                findings.append(cls._create_finding(
                    telemetry, 'warning', 'network',
                    f'Suspicious Port Binding: {port}',
                    f'Process "{bind.get("process", "unknown")}" bound to port {port}, '
                    f'which is associated with: {SUSPICIOUS_PORTS[port]}.',
                    evidence=bind,
                ))
        return findings

    @classmethod
    def _check_wildcard_binds(cls, telemetry: EmulationTelemetry) -> list:
        findings = []
        wildcard_binds = [b for b in telemetry.network_binds if b.get('guest_ip') == '0.0.0.0']
        if len(wildcard_binds) > 5:
            findings.append(cls._create_finding(
                telemetry, 'info', 'network',
                f'Excessive Wildcard Binds ({len(wildcard_binds)})',
                f'{len(wildcard_binds)} services are binding to 0.0.0.0, making them '
                'accessible from all network interfaces. This is common in IoT devices '
                'but increases attack surface.',
                evidence={'count': len(wildcard_binds),
                          'processes': list({b.get('process', '') for b in wildcard_binds})},
            ))
        return findings

    @classmethod
    def _check_suspicious_processes(cls, telemetry: EmulationTelemetry) -> list:
        findings = []
        for proc_line in telemetry.processes:
            proc_name = proc_line.split()[0] if proc_line else ''
            basename = proc_name.rsplit('/', 1)[-1]
            if basename.lower() in SUSPICIOUS_PROCESSES:
                findings.append(cls._create_finding(
                    telemetry, 'warning', 'process',
                    f'Suspicious Process: {basename}',
                    f'Process "{proc_line}" was executed. {SUSPICIOUS_PROCESSES[basename.lower()]}',
                    evidence={'process': proc_line},
                ))
        return findings

    @classmethod
    def _check_tmp_execution(cls, telemetry: EmulationTelemetry) -> list:
        findings = []
        tmp_procs = [p for p in telemetry.processes if '/tmp/' in p or '/var/tmp/' in p]
        if tmp_procs:
            findings.append(cls._create_finding(
                telemetry, 'warning', 'process',
                f'Execution from Temporary Directory ({len(tmp_procs)} processes)',
                'Binaries were executed from /tmp or /var/tmp, which is a common '
                'technique used by malware to stage and run payloads from writable directories.',
                evidence={'processes': tmp_procs[:20]},
            ))
        return findings

    @classmethod
    def _check_sensitive_device_access(cls, telemetry: EmulationTelemetry) -> list:
        findings = []
        for dev_path in telemetry.devices_accessed:
            for sensitive_path, reason in SENSITIVE_DEVICES.items():
                if dev_path == sensitive_path or dev_path.startswith(sensitive_path):
                    findings.append(cls._create_finding(
                        telemetry, 'warning', 'device',
                        f'Sensitive Device Access: {dev_path}',
                        f'The firmware accessed {dev_path}. {reason}. '
                        'While this may be normal for IoT firmware, it could also indicate '
                        'attempts to access sensitive system resources.',
                        evidence={'device': dev_path},
                    ))
                    break
        return findings

    @classmethod
    def _check_resource_anomalies(cls, telemetry: EmulationTelemetry) -> list:
        findings = []
        health = telemetry.health_data

        nexecs = health.get('nexecs', 0)
        if nexecs > 200:
            findings.append(cls._create_finding(
                telemetry, 'info', 'resource',
                f'High Exec Count: {nexecs}',
                f'The firmware executed {nexecs} unique binaries during emulation. '
                'An unusually high exec count may indicate fork-bombing, '
                'recursive script execution, or highly complex startup behavior.',
                evidence={'nexecs': nexecs},
            ))

        nioctls = health.get('nioctls', 0)
        if nioctls > 500:
            findings.append(cls._create_finding(
                telemetry, 'info', 'resource',
                f'High Ioctl Count: {nioctls}',
                f'The firmware issued {nioctls} ioctl calls. '
                'Excessive ioctl usage may indicate heavy hardware interaction '
                'or attempts to communicate with device drivers.',
                evidence={'nioctls': nioctls},
            ))

        return findings
