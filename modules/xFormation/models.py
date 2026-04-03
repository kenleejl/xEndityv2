from django.db import models
from django.conf import settings
import os
import json

class EmulatedDevice(models.Model):
    """Represents a device that can be or has been emulated"""
    firmware = models.ForeignKey('modules_xQuire.Firmware', on_delete=models.CASCADE)
    name = models.CharField(max_length=200, help_text="Display name for the device")
    rootfs_path = models.CharField(max_length=500, blank=True, null=True, help_text="Path to rootfs.tar.gz")
    penguin_project_path = models.CharField(max_length=500, blank=True, null=True)
    
    # Rootfs tracking
    has_rootfs = models.BooleanField(default=False, help_text="Whether rootfs.tar.gz exists")
    rootfs_discovered_at = models.DateTimeField(blank=True, null=True, help_text="When rootfs.tar.gz was first discovered")
    
    INIT_STATUS_CHOICES = [
        ('not_initialized', 'Not Initialized'),
        ('initializing', 'Initializing'),
        ('initialized', 'Initialized'),
        ('init_failed', 'Initialization Failed'),
    ]
    initialization_status = models.CharField(max_length=20, choices=INIT_STATUS_CHOICES, default='not_initialized')
    initialization_log = models.TextField(blank=True, null=True, help_text="Penguin init output log")
    config_yaml_path = models.CharField(max_length=500, blank=True, null=True)
    
    # User configuration (applied during initialization)
    config_data = models.JSONField(
        default=dict,
        blank=True,
        help_text="User configuration applied during initialization"
    )
    # Structure: {
    #   'credentials': {'username': 'root', 'password': 'root'},
    #   'telemetry': {'enabled': True, 'strace_filter': 'execve'},
    #   'network': {'mode': 'ipam', 'static_ip': '192.168.1.100', 'subnet': '192.168.1.0/24'},
    #   'custom_init_uploaded': False
    # }
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.firmware.model.manufacturer} {self.firmware.model.model_number})"
    
    @property
    def can_run(self):
        """Check if device can be run (has rootfs and is initialized)"""
        return self.has_rootfs and self.initialization_status == 'initialized'
    
    @property
    def running_instances_count(self):
        """Count of currently running instances"""
        return self.emulationinstance_set.filter(status='running').count()
    
    class Meta:
        verbose_name = "Emulated Device"
        verbose_name_plural = "Emulated Devices"
        app_label = "modules_xFormation"

class EmulationInstance(models.Model):
    """Represents a running emulation instance"""
    device = models.ForeignKey(EmulatedDevice, on_delete=models.CASCADE)
    instance_name = models.CharField(max_length=100)
    process_id = models.IntegerField(blank=True, null=True, help_text="Penguin process PID (for subprocess mode)")
    
    STATUS_CHOICES = [
        ('starting', 'Starting'),
        ('running', 'Running'),
        ('stopping', 'Stopping'),
        ('stopped', 'Stopped'),
        ('failed', 'Failed'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='starting')
    
    # Resource configuration
    cpu_limit = models.FloatField(default=2.0, help_text="CPU cores limit")
    memory_limit = models.CharField(max_length=10, default="1g", help_text="Memory limit (e.g., 1g, 512m)")
    
    # Docker-specific fields (for Docker API mode)
    docker_container_id = models.CharField(max_length=64, blank=True, null=True, help_text="Docker container ID")
    docker_container_name = models.CharField(max_length=100, blank=True, null=True, help_text="Docker container name")
    docker_network_name = models.CharField(max_length=64, blank=True, null=True, help_text="Docker network name")
    docker_subnet = models.CharField(max_length=32, blank=True, null=True, help_text="Docker network subnet")
    
    # Network configuration
    host_ip = models.GenericIPAddressField(blank=True, null=True)
    host_ports = models.JSONField(default=dict, help_text="Port mappings from penguin")
    web_interface_url = models.URLField(blank=True, null=True)
    
    WEB_STATUS_CHOICES = [
        ('unknown', 'Unknown'),
        ('accessible', 'Accessible'),
        ('inaccessible', 'Inaccessible'),
    ]
    web_interface_status = models.CharField(max_length=20, choices=WEB_STATUS_CHOICES, default='unknown')
    
    # Timestamps
    started_at = models.DateTimeField(auto_now_add=True)
    last_health_check = models.DateTimeField(blank=True, null=True)
    stopped_at = models.DateTimeField(blank=True, null=True)
    
    # Output and logs
    output_log_path = models.CharField(max_length=500, blank=True, null=True)
    penguin_results_path = models.CharField(max_length=500, blank=True, null=True, help_text="Path to Penguin results directory")
    
    def __str__(self):
        return f"{self.device.name} - {self.instance_name}"
    
    @property
    def is_running(self):
        """Check if instance is currently running"""
        return self.status == 'running'
    
    @property
    def uptime_seconds(self):
        """Calculate uptime in seconds"""
        if self.status == 'running' and self.started_at:
            from django.utils import timezone
            return (timezone.now() - self.started_at).total_seconds()
        return 0
    
    class Meta:
        verbose_name = "Emulation Instance"
        verbose_name_plural = "Emulation Instances"
        app_label = "modules_xFormation"

class EmulationTelemetry(models.Model):
    """Runtime telemetry collected from Penguin emulation output files"""
    instance = models.ForeignKey(EmulationInstance, on_delete=models.CASCADE, related_name='telemetry_records')
    
    # From health_final.yaml
    health_data = models.JSONField(default=dict, help_text="Raw health metrics (nproc, nexecs, nbound_sockets, etc.)")
    
    # From health_procs_with_args.txt
    processes = models.JSONField(default=list, help_text="List of processes with arguments")
    
    # From netbinds.csv
    network_binds = models.JSONField(default=list, help_text="Network socket bindings (process, ip, port, time)")
    
    # From shell_cov.csv
    shell_coverage = models.JSONField(default=dict, help_text="Shell script coverage data")
    
    # From health_devices_accessed.txt
    devices_accessed = models.JSONField(default=list, help_text="Device paths accessed during emulation")
    
    # From console.log
    kernel_panic = models.BooleanField(default=False, help_text="Whether a kernel panic was detected")
    console_snippet = models.TextField(blank=True, null=True, help_text="Relevant console log excerpt")
    
    # Computed score (from manager.py scoring logic)
    score_data = models.JSONField(default=dict, help_text="Emulation quality scores")
    
    collected_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Telemetry for {self.instance} at {self.collected_at}"
    
    @property
    def total_processes(self):
        return self.health_data.get('nproc', 0)
    
    @property
    def total_execs(self):
        return self.health_data.get('nexecs', 0)
    
    @property
    def total_bound_sockets(self):
        return self.health_data.get('nbound_sockets', 0)
    
    class Meta:
        verbose_name = "Emulation Telemetry"
        verbose_name_plural = "Emulation Telemetry Records"
        app_label = "modules_xFormation"
        ordering = ['-collected_at']


class BehaviorFinding(models.Model):
    """A suspicious or notable behavior detected during emulation analysis"""
    telemetry = models.ForeignKey(EmulationTelemetry, on_delete=models.CASCADE, related_name='findings')
    
    SEVERITY_CHOICES = [
        ('info', 'Informational'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    ]
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info')
    
    CATEGORY_CHOICES = [
        ('network', 'Network'),
        ('process', 'Process'),
        ('kernel', 'Kernel'),
        ('resource', 'Resource'),
        ('device', 'Device Access'),
    ]
    category = models.CharField(max_length=10, choices=CATEGORY_CHOICES)
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    evidence = models.JSONField(default=dict, help_text="Data that triggered this finding")
    
    detected_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"
    
    class Meta:
        verbose_name = "Behavior Finding"
        verbose_name_plural = "Behavior Findings"
        app_label = "modules_xFormation"
        ordering = ['-severity', '-detected_at']


class ValidationResult(models.Model):
    """Results of automated validation checks on an emulation instance"""
    instance = models.ForeignKey(EmulationInstance, on_delete=models.CASCADE, related_name='validation_results')
    telemetry = models.ForeignKey(EmulationTelemetry, on_delete=models.SET_NULL, null=True, blank=True)
    
    STATUS_CHOICES = [
        ('pass', 'Pass'),
        ('fail', 'Fail'),
        ('partial', 'Partial'),
        ('error', 'Error'),
    ]
    overall_status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='error')
    
    boot_check = models.BooleanField(default=False, help_text="Device booted without kernel panic")
    services_check = models.BooleanField(default=False, help_text="Expected services are responding")
    ports_check = models.BooleanField(default=False, help_text="Detected ports are reachable")
    shell_check = models.BooleanField(default=False, help_text="Shell access is available")
    
    check_details = models.JSONField(default=dict, help_text="Detailed results for each check")
    
    validated_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Validation [{self.overall_status}] for {self.instance}"
    
    @property
    def checks_passed(self):
        checks = [self.boot_check, self.services_check, self.ports_check, self.shell_check]
        return sum(checks)
    
    @property
    def checks_total(self):
        return 4
    
    class Meta:
        verbose_name = "Validation Result"
        verbose_name_plural = "Validation Results"
        app_label = "modules_xFormation"
        ordering = ['-validated_at']


# Legacy model for backward compatibility
class Component(models.Model):
    """Legacy firmware component model"""
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=50, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} {self.version}" if self.version else self.name
        
    class Meta:
        verbose_name = "Component"
        verbose_name_plural = "Components"
        app_label = "modules_xFormation" 