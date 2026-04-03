from django.contrib import admin
from .models import (
    EmulatedDevice, EmulationInstance, Component,
    EmulationTelemetry, BehaviorFinding, ValidationResult,
)

@admin.register(EmulatedDevice)
class EmulatedDeviceAdmin(admin.ModelAdmin):
    list_display = ('name', 'firmware', 'initialization_status', 'running_instances_count', 'created_at')
    list_filter = ('initialization_status', 'created_at', 'firmware__model__manufacturer')
    search_fields = ('name', 'firmware__model__model_number', 'firmware__version')
    readonly_fields = ('created_at', 'updated_at', 'running_instances_count')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('firmware', 'name')
        }),
        ('Paths', {
            'fields': ('rootfs_path', 'penguin_project_path', 'config_yaml_path')
        }),
        ('Status', {
            'fields': ('initialization_status', 'initialization_log')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(EmulationInstance)
class EmulationInstanceAdmin(admin.ModelAdmin):
    list_display = ('instance_name', 'device', 'status', 'cpu_limit', 'memory_limit', 'web_interface_status', 'started_at')
    list_filter = ('status', 'web_interface_status', 'started_at')
    search_fields = ('instance_name', 'device__name')
    readonly_fields = ('started_at', 'last_health_check', 'stopped_at', 'uptime_seconds')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('device', 'instance_name', 'status')
        }),
        ('Resources', {
            'fields': ('cpu_limit', 'memory_limit', 'process_id')
        }),
        ('Network', {
            'fields': ('host_ip', 'host_ports', 'web_interface_url', 'web_interface_status')
        }),
        ('Logs', {
            'fields': ('output_log_path',)
        }),
        ('Timestamps', {
            'fields': ('started_at', 'last_health_check', 'stopped_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(EmulationTelemetry)
class EmulationTelemetryAdmin(admin.ModelAdmin):
    list_display = ('instance', 'total_processes', 'total_bound_sockets', 'kernel_panic', 'collected_at')
    list_filter = ('kernel_panic', 'collected_at')
    search_fields = ('instance__instance_name', 'instance__device__name')
    readonly_fields = ('collected_at',)

    fieldsets = (
        ('Instance', {
            'fields': ('instance',)
        }),
        ('Health Metrics', {
            'fields': ('health_data', 'processes', 'network_binds', 'devices_accessed')
        }),
        ('Shell & Kernel', {
            'fields': ('shell_coverage', 'kernel_panic', 'console_snippet')
        }),
        ('Score', {
            'fields': ('score_data',)
        }),
        ('Timestamps', {
            'fields': ('collected_at',),
            'classes': ('collapse',)
        }),
    )


@admin.register(BehaviorFinding)
class BehaviorFindingAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'category', 'telemetry', 'detected_at')
    list_filter = ('severity', 'category', 'detected_at')
    search_fields = ('title', 'description')
    readonly_fields = ('detected_at',)


@admin.register(ValidationResult)
class ValidationResultAdmin(admin.ModelAdmin):
    list_display = ('instance', 'overall_status', 'boot_check', 'services_check', 'ports_check', 'shell_check', 'validated_at')
    list_filter = ('overall_status', 'validated_at')
    search_fields = ('instance__instance_name',)
    readonly_fields = ('validated_at',)


@admin.register(Component)
class ComponentAdmin(admin.ModelAdmin):
    list_display = ('name', 'version', 'created_at')
    search_fields = ('name', 'version')
    list_filter = ('created_at',)
