from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import ListView, DetailView
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator
import ipaddress
import json
import logging
import os
import re
import yaml

from .models import EmulatedDevice, EmulationInstance, EmulationTelemetry, BehaviorFinding, ValidationResult
from .services import (
    DeviceDiscoveryService, 
    PenguinIntegrationService, 
    EmulationManagerService,
    LiveOutputService,
    TelemetryService,
    BehaviorAnalysisService,
    ValidationService,
    PipelineService,
    PackagingService,
)

logger = logging.getLogger(__name__)

@login_required
def index(request):
    """Main dashboard for xFormation module - optimized with no filesystem scanning"""
    # Check if user wants to see firmware without rootfs
    show_without_rootfs = request.GET.get('show_all', 'false').lower() == 'true'
    
    # Get optimized device status (fast database-only queries)
    device_status = DeviceDiscoveryService.get_all_devices_with_status()
    
    # Get running instances
    running_instances = EmulationInstance.objects.filter(status='running').select_related('device')
    # Check penguin installation
    #penguin_available = PenguinIntegrationService.validate_penguin_installation()
    penguin_available = True
    # Check instance limits
    can_start_more = EmulationManagerService.can_start_instance()
    max_instances = EmulationManagerService.MAX_INSTANCES
    context = {
        'module_name': 'xFormation',
        'module_description': 'Device Emulation Management',
        
        # Devices with rootfs (organized by status)
        'available_devices': device_status['available_devices'],
        'initialized_devices': device_status['initialized_devices'],
        'initializing_devices': device_status['initializing_devices'],
        'failed_devices': device_status['failed_devices'],
        
        # Firmware without rootfs (shown conditionally)
        'firmware_without_rootfs': device_status['without_rootfs'] if show_without_rootfs else [],
        'show_without_rootfs': show_without_rootfs,
        'firmware_without_rootfs_count': len(device_status['without_rootfs']),
        
        # Instance management
        'running_instances': running_instances,
        'running_count': running_instances.count(),
        'max_instances': max_instances,
        'can_start_more': can_start_more,
        
        # System status
        'penguin_available': penguin_available,
        'total_firmware': device_status['total_firmware'],
        'devices_with_rootfs_count': len(device_status['with_rootfs']),
    }
    
    return render(request, 'xFormation/index.html', context)

@login_required
def device_detail(request, device_id):
    """Device detail view with initialization capability"""
    from django.conf import settings
    
    device = get_object_or_404(EmulatedDevice, id=device_id)
    
    # Handle POST request for initialization and instance start
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'initialize':
            if device.initialization_status == 'initializing':
                messages.warning(request, f"Device {device.name} is already being initialized.")
            else:
                # Start initialization asynchronously
                PenguinIntegrationService.initialize_device_async(device)
                messages.success(request, f"Started initialization of device {device.name}")
            
            return redirect('xformation:device_detail', device_id=device.id)
            
        elif action == 'start_instance':
            # Get configuration from form
            instance_name = request.POST.get('instance_name', '')
            cpu_limit = float(request.POST.get('cpu_limit', 2.0))
            memory_limit = request.POST.get('memory_limit', '1g')
            
            # Validate inputs
            if not instance_name:
                instance_name = f"{device.name}_instance"
            
            # Start the instance
            instance = EmulationManagerService.start_instance(
                device=device,
                instance_name=instance_name,
                cpu_limit=cpu_limit,
                memory_limit=memory_limit
            )
            
            if instance:
                messages.success(request, f"Started emulation instance: {instance_name}")
                return redirect('xformation:instance_detail', instance_id=instance.id)
            else:
                messages.error(request, "Failed to start emulation instance")
                return redirect('xformation:device_detail', device_id=device.id)
    
    # Get project status
    project_status = PenguinIntegrationService.get_project_status(device)
    
    # Get device config
    config = PenguinIntegrationService.get_device_config(device)
    
    # Get instances for this device
    instances = device.emulationinstance_set.all().order_by('-started_at')
    
    # Convert rootfs path to relative for display
    display_rootfs_path = device.rootfs_path
    if device.rootfs_path:
        if device.rootfs_path.startswith('/'):
            # Legacy absolute path - convert to relative
            display_rootfs_path = os.path.relpath(device.rootfs_path, settings.BASE_DIR)
        else:
            # Already relative - use as is
            display_rootfs_path = device.rootfs_path
    
    context = {
        'device': device,
        'display_rootfs_path': display_rootfs_path,
        'project_status': project_status,
        'config': config,
        'instances': instances,
    }
    return render(request, 'xFormation/device_detail.html', context)


@login_required
def instance_detail(request, instance_id):
    """Instance detail view with live output and stop capability"""
    instance = get_object_or_404(EmulationInstance, id=instance_id)
    
    # Handle POST request for stop instance
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'stop_instance':
            success = EmulationManagerService.stop_instance(instance)
            
            if success:
                messages.success(request, f"Stopped instance: {instance.instance_name}")
                return redirect('xformation:index')
            else:
                messages.error(request, f"Failed to stop instance: {instance.instance_name}")
                return redirect('xformation:instance_detail', instance_id=instance.id)
    
    # Get recent output
    recent_output = LiveOutputService.get_output_buffer(instance.id, last_n_lines=100)
    
    # Get telemetry data (most recent record)
    telemetry = instance.telemetry_records.first()
    findings = telemetry.findings.all() if telemetry else BehaviorFinding.objects.none()
    validation = instance.validation_results.first()
    
    # Allow manual telemetry collection via GET param
    if request.GET.get('collect_telemetry') == '1' and not instance.is_running:
        telemetry = TelemetryService.collect_telemetry(instance)
        if telemetry:
            BehaviorAnalysisService.analyze(telemetry)
            ValidationService.validate(instance, telemetry)
            messages.success(request, "Telemetry collected and analyzed successfully")
        return redirect('xformation:instance_detail', instance_id=instance.id)
    
    context = {
        'instance': instance,
        'recent_output': recent_output,
        'telemetry': telemetry,
        'findings': findings,
        'validation': validation,
    }
    return render(request, 'xFormation/instance_detail.html', context)


# API Views

@login_required
def api_device_status(request, device_id):
    """API endpoint for device status"""
    device = get_object_or_404(EmulatedDevice, id=device_id)
    
    # Refresh device status
    device = DeviceDiscoveryService.refresh_device_status(device)
    
    data = {
        'id': device.id,
        'name': device.name,
        'status': device.initialization_status,
        'can_run': device.can_run,
        'running_instances': device.running_instances_count,
    }
    
    return JsonResponse(data)

@login_required
def api_instance_status(request, instance_id):
    """API endpoint for instance status"""
    instance = get_object_or_404(EmulationInstance, id=instance_id)
    
    # If instance is running but has no IP detected yet, try to detect it
    if instance.status == 'running' and not instance.host_ip:
        EmulationManagerService.detect_instance_network_info(instance)
        instance.refresh_from_db()
    
    # Check web interface health if applicable
    if instance.web_interface_url and instance.status == 'running':
        web_status = EmulationManagerService.check_web_interface_health(instance)
    else:
        web_status = instance.web_interface_status
    
    data = {
        'id': instance.id,
        'name': instance.instance_name,
        'status': instance.status,
        'uptime': instance.uptime_seconds,
        'web_interface_url': instance.web_interface_url,
        'web_interface_status': web_status,
        'host_ports': instance.host_ports,
        'host_ip': instance.host_ip,
    }
    
    return JsonResponse(data)

@login_required
def api_instance_output(request, instance_id):
    """API endpoint for instance output"""
    instance = get_object_or_404(EmulationInstance, id=instance_id)
    
    # Get number of lines requested
    lines = int(request.GET.get('lines', 50))
    
    output = LiveOutputService.get_output_buffer(instance.id, last_n_lines=lines)
    
    data = {
        'instance_id': instance.id,
        'output': output,
        'status': instance.status,
    }
    
    return JsonResponse(data)

@login_required
def download_instance_log(request, instance_id):
    """Download full instance log"""
    instance = get_object_or_404(EmulationInstance, id=instance_id)
    
    if not instance.output_log_path or not os.path.exists(instance.output_log_path):
        messages.error(request, "Log file not found")
        return redirect('xformation:instance_detail', instance_id=instance.id)
    
    def file_iterator(file_path, chunk_size=8192):
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    
    response = StreamingHttpResponse(
        file_iterator(instance.output_log_path),
        content_type='text/plain'
    )
    response['Content-Disposition'] = f'attachment; filename="instance_{instance.id}_log.txt"'
    
    return response

@login_required
def pipeline_dashboard(request):
    """Unified pipeline dashboard showing all firmware with status columns"""
    from modules.xQuire.models import Firmware

    firmwares = Firmware.objects.select_related(
        'model', 'model__manufacturer', 'model__device_type'
    ).order_by('-upload_date')

    pipeline_data = []
    for fw in firmwares:
        device = EmulatedDevice.objects.filter(firmware=fw).first()
        latest_instance = (
            device.emulationinstance_set.order_by('-started_at').first()
            if device else None
        )
        telemetry = (
            latest_instance.telemetry_records.first()
            if latest_instance else None
        )
        validation = (
            latest_instance.validation_results.first()
            if latest_instance else None
        )
        findings_count = telemetry.findings.count() if telemetry else 0
        findings_critical = telemetry.findings.filter(severity='critical').count() if telemetry else 0
        findings_warning = telemetry.findings.filter(severity='warning').count() if telemetry else 0

        running_pipeline = PipelineService.get_pipeline_status(fw.id)

        pipeline_data.append({
            'firmware': fw,
            'device': device,
            'extraction_status': 'complete' if (device and device.has_rootfs) else 'not_started',
            'init_status': device.initialization_status if device else 'not_started',
            'emulation_status': latest_instance.status if latest_instance else 'not_started',
            'instance': latest_instance,
            'telemetry': telemetry,
            'validation': validation,
            'validation_status': validation.overall_status if validation else 'not_run',
            'findings_count': findings_count,
            'findings_critical': findings_critical,
            'findings_warning': findings_warning,
            'pipeline_running': running_pipeline is not None and running_pipeline.get('overall_status') == 'running',
            'pipeline_stage': running_pipeline.get('current_stage') if running_pipeline else None,
        })

    context = {
        'pipeline_data': pipeline_data,
        'total_firmware': len(pipeline_data),
    }
    return render(request, 'xFormation/pipeline_dashboard.html', context)


@login_required
def pipeline_run(request, firmware_id):
    """Trigger the full pipeline for a firmware"""
    if request.method != 'POST':
        return redirect('xformation:pipeline_dashboard')

    existing = PipelineService.get_pipeline_status(firmware_id)
    if existing and existing.get('overall_status') == 'running':
        messages.warning(request, 'Pipeline is already running for this firmware')
        return redirect('xformation:pipeline_dashboard')

    timeout = int(request.POST.get('timeout', 300))
    PipelineService.run_pipeline_async(firmware_id, emulation_timeout=timeout)
    messages.success(request, f'Pipeline started for firmware {firmware_id}')
    return redirect('xformation:pipeline_dashboard')


@login_required
def api_pipeline_status(request, firmware_id):
    """API endpoint for pipeline status polling"""
    status = PipelineService.get_pipeline_status(firmware_id)
    if status is None:
        return JsonResponse({'running': False})

    serializable = {}
    for k, v in status.items():
        if k == 'stages':
            clean_stages = {}
            for sk, sv in v.items():
                clean_stages[sk] = {
                    key: val for key, val in sv.items()
                    if not hasattr(val, 'pk')
                }
            serializable[k] = clean_stages
        else:
            serializable[k] = v
    serializable['running'] = status.get('overall_status') == 'running'
    return JsonResponse(serializable)


@login_required
def export_package(request, instance_id):
    """Export an emulation instance as a deployable Docker package"""
    instance = get_object_or_404(EmulationInstance, id=instance_id)

    if instance.is_running:
        messages.error(request, 'Cannot export a running instance. Stop it first.')
        return redirect('xformation:instance_detail', instance_id=instance.id)

    export_dir = os.path.join(
        getattr(settings, 'XFORMATION_LOGS_DIR', '/tmp/xformation_logs'),
        'exports',
    )
    os.makedirs(export_dir, exist_ok=True)

    archive_path = PackagingService.package_emulation(instance, export_dir)
    if not archive_path or not os.path.exists(archive_path):
        messages.error(request, 'Failed to create deployment package')
        return redirect('xformation:instance_detail', instance_id=instance.id)

    def file_iterator(path, chunk_size=8192):
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    filename = os.path.basename(archive_path)
    response = StreamingHttpResponse(file_iterator(archive_path), content_type='application/gzip')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# Legacy view for backward compatibility
@login_required
def analyze_composition(request):
    """Redirect to main index"""
    return redirect('xformation:index') 


# Node Emulation Engine Views
@login_required
def device_initialize(request, device_id):
    """
    Device initialization page with Init/Configure buttons
    """
    device = get_object_or_404(EmulatedDevice, id=device_id)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'init_defaults':
            # Initialize with defaults from node-emulation-config.yaml
            from modules.xFormation.services.node_initialization_service import NodeInitializationService
            default_config = NodeInitializationService.load_default_config()
            result = NodeInitializationService.initialize_device(device, user_config=default_config)
            
            if result['success']:
                messages.success(request, "Device initialized with default settings")
                return redirect('xformation:config_editor', device_id=device.id)
            else:
                messages.error(request, f"Initialization failed: {result['message']}")
                context = {
                    'device': device,
                    'error_logs': result.get('logs', [])
                }
                return render(request, 'xFormation/device_initialize.html', context)
                
        elif action == 'show_config':
            return redirect('xformation:config_form', device_id=device.id)
    
    context = {'device': device}
    return render(request, 'xFormation/device_initialize.html', context)


@login_required
def config_form(request, device_id):
    """
    Configuration form for advanced device initialization
    """
    device = get_object_or_404(EmulatedDevice, id=device_id)

    # Load xScout analysis to determine recommended kernel version
    from modules.xScout.services.components_analysis_service import ComponentsAnalysisService
    from modules.xFormation.services.kernel_version_service import KernelVersionService

    scout_service = ComponentsAnalysisService()
    scout_analysis = scout_service.get_analysis_results(device.firmware.id)

    # Determine recommended kernel version
    recommended_kernel, kernel_recommendation = KernelVersionService.determine_kernel_version(scout_analysis)

    # Load skeleton template content for "Use template" button in config_form
    # Defined before POST/GET branches so both render paths (POST-error re-render and GET) have it
    from modules.xFormation.services.rootfs_modification_service import RootfsModificationService
    template_file = RootfsModificationService.PATCH_TEMPLATES_DIR / 'custom_init.template.sh'
    try:
        custom_init_template = template_file.read_text()
    except Exception:
        custom_init_template = '#!/bin/sh\n# Template not found\n'

    if request.method == 'POST':
        # Validate and sanitise network fields before use; these flow into docker args
        # that are space-joined and re-split by Penguin — spaces in values = arg injection.
        network_mode = request.POST.get('network_mode', 'ipam')
        if network_mode not in ('ipam', 'macvlan', 'static'):
            network_mode = 'ipam'

        raw_static_ip = request.POST.get('static_ip', '').strip()
        raw_subnet    = request.POST.get('subnet', '').strip()
        raw_gateway   = request.POST.get('gateway', '').strip()

        def _valid_ip(value):
            """Return value if it is a valid IPv4/IPv6 address, else empty string."""
            try:
                ipaddress.ip_address(value)
                return value
            except ValueError:
                return ''

        def _valid_network(value):
            """Return value if it is a valid CIDR network, else empty string."""
            try:
                ipaddress.ip_network(value, strict=False)
                return value
            except ValueError:
                return ''

        static_ip = _valid_ip(raw_static_ip)
        subnet    = _valid_network(raw_subnet)
        gateway   = _valid_ip(raw_gateway)

        if raw_static_ip and not static_ip:
            logger.warning(f"config_form: rejected invalid static_ip value: {raw_static_ip!r}")
            messages.error(request, f"Invalid static IP address: {raw_static_ip}")
        if raw_subnet and not subnet:
            logger.warning(f"config_form: rejected invalid subnet value: {raw_subnet!r}")
            messages.error(request, f"Invalid subnet CIDR: {raw_subnet}")
        if raw_gateway and not gateway:
            logger.warning(f"config_form: rejected invalid gateway value: {raw_gateway!r}")
            messages.error(request, f"Invalid gateway IP address: {raw_gateway}")


        # Collect user configuration
        user_config = {
            'credentials': {
                'username': 'root',
                'password': request.POST.get('password', 'root'),
            },
            'telemetry': {
                'enabled': request.POST.get('telemetry') == 'on',
                'strace_filter': request.POST.get('strace_filter', 'execve'),
            },
            'network': {
                'mode': network_mode,
                'static_ip': static_ip,
                'subnet': subnet,
                'gateway': gateway,
            },
            'kernel_version': request.POST.get('kernel_version', recommended_kernel),
        }
        
        # Init injection mode fields — passed to create_init_stub() via initialize_device()
        raw_init_mode = request.POST.get('init_mode', 'partial_stub').strip()
        user_config['init_mode'] = raw_init_mode if raw_init_mode in ('partial_stub', 'full_stub', 'disabled') else 'partial_stub'
        raw_stub = request.POST.get('stub_path', '/igloo/custom_init.sh').strip()
        user_config['stub_path'] = raw_stub if raw_stub else '/igloo/custom_init.sh'
        user_config['wrapper_original_path'] = request.POST.get('wrapper_original_path', '').strip()

        # Handle custom init script — textarea content takes priority, fallback to file upload
        custom_init_text = request.POST.get('custom_init_text', '').strip().replace('\r', '')
        if custom_init_text:
            import tempfile
            temp_fd, temp_path = tempfile.mkstemp(suffix='.sh', prefix=f'xformation_init_{device.id}_')
            with os.fdopen(temp_fd, 'w') as f:
                f.write(custom_init_text)
            user_config['custom_init_path'] = temp_path
            user_config['custom_init_uploaded'] = True
        elif 'custom_init' in request.FILES:
            script_file = request.FILES['custom_init']
            import tempfile
            temp_fd, temp_path = tempfile.mkstemp(suffix='.sh', prefix=f'xformation_init_{device.id}_')
            with os.fdopen(temp_fd, 'wb') as f:
                for chunk in script_file.chunks():
                    f.write(chunk)
            user_config['custom_init_path'] = temp_path
            user_config['custom_init_uploaded'] = True
        
        # Save user config to device
        device.config_data = user_config
        device.save()
        
        # Run initialization with user config
        from modules.xFormation.services.node_initialization_service import NodeInitializationService
        result = NodeInitializationService.initialize_device(device, user_config)
        
        if result['success']:
            messages.success(request, "Device initialized with custom configuration")
            return redirect('xformation:config_editor', device_id=device.id)
        else:
            messages.error(request, f"Initialization failed: {result['message']}")
            # Re-display form with error
            context = {
                'device': device,
                'error_logs': result.get('logs', []),
                'form_data': user_config,
                'recommended_kernel': recommended_kernel,
                'kernel_recommendation': kernel_recommendation,
                'custom_init_template': custom_init_template,
            }
            return render(request, 'xFormation/config_form.html', context)
    
    # GET - show form with auto-detected defaults
    try:
        import netifaces
        gateway_info = netifaces.gateways()['default'][netifaces.AF_INET]
        subnet = f"{gateway_info[0].rsplit('.', 1)[0]}.0/24"
        gateway = gateway_info[0]
    except:
        subnet = "192.168.1.0/24"
        gateway = "192.168.1.1"
    
    context = {
        'device': device,
        'default_subnet': subnet,
        'default_gateway': gateway,
        'recommended_kernel': recommended_kernel,
        'kernel_recommendation': kernel_recommendation,
        'custom_init_template': custom_init_template,
    }
    return render(request, 'xFormation/config_form.html', context)


@login_required
def config_editor(request, device_id):
    """
    Configuration editor for post-initialization YAML and script editing.

    Gate: uninitialized devices without ?reconfigure=true are redirected silently
    to device_detail. The reconfigure flag is consumed via redirect-after-GET
    to strip it from the browser address bar.

    Args:
        request (HttpRequest): Django HTTP request.
        device_id (int): Primary key of EmulatedDevice.

    Returns:
        HttpResponse: Rendered config editor or redirect response.
    """
    device = get_object_or_404(EmulatedDevice, id=device_id)

    reconfigure = request.GET.get('reconfigure') == 'true'

    # Gate: uninitialized + no reconfigure flag → silent redirect, no flash message
    if device.initialization_status != 'initialized' and not reconfigure:
        return redirect('xformation:device_detail', device_id=device.id)

    # Consume reconfigure flag — redirect to clean URL to strip ?reconfigure from address bar
    if reconfigure:
        return redirect('xformation:config_editor', device_id=device.id)

    # Compute custom init path once — used for both read and write
    custom_init_path = os.path.join(device.penguin_project_path, 'static_patches/custom_init.sh')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'save_config':
            config_content = request.POST.get('config_yaml')
            try:
                with open(device.config_yaml_path, 'w') as f:
                    f.write(config_content)
                messages.success(request, "config.yaml saved successfully")
            except Exception as e:
                messages.error(request, f"Failed to save config.yaml: {str(e)}")

        elif action == 'save_manual':
            manual_content = request.POST.get('manual_yaml')
            try:
                manual_path = os.path.join(device.penguin_project_path, 'static_patches/manual.yaml')
                with open(manual_path, 'w') as f:
                    f.write(manual_content)
                messages.success(request, "manual.yaml saved successfully")
            except Exception as e:
                messages.error(request, f"Failed to save manual.yaml: {str(e)}")

        elif action == 'save_custom_init':
            custom_init_content_post = request.POST.get('custom_init', '').replace('\r', '')
            custom_init_enabled = request.POST.get('custom_init_enabled') == 'true'
            new_init_mode = request.POST.get('init_mode', 'partial_stub').strip()
            if new_init_mode not in ('partial_stub', 'full_stub', 'disabled'):
                new_init_mode = 'partial_stub'
            raw_stub = request.POST.get('stub_path', '/igloo/custom_init.sh').strip()
            new_stub_path = raw_stub if raw_stub else '/igloo/custom_init.sh'
            wrapper_original_path = request.POST.get('wrapper_original_path', '').strip() or None
            archive_path = custom_init_path + '.disabled'

            if not custom_init_enabled:
                # Toggle OFF: delegate cleanup to create_init_stub(disabled)
                result = RootfsModificationService.create_init_stub(
                    rootfs_path=None,
                    project_path=device.penguin_project_path,
                    custom_script_path=None,
                    init_mode='disabled',
                    stub_path=new_stub_path,
                )
                if result:
                    messages.success(request, "Custom init disabled")
                else:
                    messages.error(request, "Failed to disable custom init")
            else:
                # Toggle ON: ensure script file exists
                if not os.path.exists(custom_init_path):
                    if os.path.exists(archive_path):
                        os.rename(archive_path, custom_init_path)
                    elif custom_init_content_post:
                        os.makedirs(os.path.dirname(custom_init_path), exist_ok=True)
                        with open(custom_init_path, 'w') as f:
                            f.write(custom_init_content_post)
                        os.chmod(custom_init_path, 0o755)
                    else:
                        # Fall back to mode-appropriate template
                        template_name = (
                            'custom_init.template.sh'
                            if new_init_mode == 'full_stub'
                            else 'custom_preinit.template.sh'
                        )
                        RootfsModificationService._copy_template_script(
                            template_name, custom_init_path
                        )
                elif custom_init_content_post:
                    # Script exists and content was edited — overwrite
                    with open(custom_init_path, 'w') as f:
                        f.write(custom_init_content_post)
                    os.chmod(custom_init_path, 0o755)

                result = RootfsModificationService.create_init_stub(
                    rootfs_path=os.path.join(device.penguin_project_path, 'base', 'fs.tar.gz'),
                    project_path=device.penguin_project_path,
                    custom_script_path=custom_init_path,
                    init_mode=new_init_mode,
                    stub_path=new_stub_path,
                    wrapper_original_path=wrapper_original_path,
                )
                if result:
                    # Persist mode to device.config_data for reference
                    config_data = device.config_data or {}
                    config_data['init_mode'] = new_init_mode
                    config_data['stub_path'] = new_stub_path
                    if wrapper_original_path:
                        config_data['wrapper_original_path'] = wrapper_original_path
                    device.config_data = config_data
                    device.save()
                    messages.success(request, f"Custom init saved ({new_init_mode})")
                else:
                    messages.error(request, "Failed to save custom init — check server logs")

        elif action == 'save_base':
            base_content = request.POST.get('base_yaml', '').replace('\r', '')
            try:
                base_yaml_path = os.path.join(device.penguin_project_path, 'static_patches/base.yaml')
                with open(base_yaml_path, 'w') as f:
                    f.write(base_content)
                messages.success(request, "base.yaml saved successfully")
            except Exception as e:
                messages.error(request, f"Failed to save base.yaml: {str(e)}")

        elif action == 'save_nat':
            nat_content = request.POST.get('nat_script', '').replace('\r', '')
            try:
                nat_script_path = os.path.join(device.penguin_project_path, 'static_patches/95_network_config.sh')
                with open(nat_script_path, 'w') as f:
                    f.write(nat_content)
                messages.success(request, "NAT script saved successfully")
            except Exception as e:
                messages.error(request, f"Failed to save NAT script: {str(e)}")

        elif action == 'save_strace':
            strace_content = request.POST.get('strace_script', '').replace('\r', '')
            try:
                strace_script_path = os.path.join(device.penguin_project_path, 'static_patches/90_telemetry_collection.sh')
                with open(strace_script_path, 'w') as f:
                    f.write(strace_content)
                messages.success(request, "Strace script saved successfully")
            except Exception as e:
                messages.error(request, f"Failed to save strace script: {str(e)}")

        elif action == 'save_settings':
            raw_mode = request.POST.get('telemetry_mode', 'filtered')
            if raw_mode not in ('filtered', 'full', 'disabled'):
                raw_mode = 'filtered'
            config_data = device.config_data or {}
            config_data['telemetry_mode'] = raw_mode
            device.config_data = config_data
            device.save()
            messages.success(
                request,
                f"Telemetry mode set to '{raw_mode}' — takes effect on next restart"
            )

    # Read current configs
    try:
        with open(device.config_yaml_path, 'r') as f:
            config_content = f.read()
    except Exception as e:
        config_content = f"# Error reading config.yaml: {str(e)}"

    # Derive toggle state from config.yaml static_files — detect any entry whose
    # host_path contains 'custom_init.sh' (device-agnostic, not hardcoded path)
    try:
        _cfg = yaml.safe_load(config_content) or {}
        _active_static = _cfg.get('static_files', {})
        _active_stub_path = next(
            (k for k, v in _active_static.items()
             if isinstance(v, dict) and 'custom_init.sh' in v.get('host_path', '')),
            None
        )
        custom_init_enabled = _active_stub_path is not None
    except Exception:
        custom_init_enabled = False
        _active_stub_path = None

    # Read .xformation.json sidecar for editor display defaults
    _xformation_sidecar_path = os.path.join(device.penguin_project_path, '.xformation.json')
    _xformation_state = {}
    if os.path.exists(_xformation_sidecar_path):
        try:
            with open(_xformation_sidecar_path, 'r') as _f:
                _xformation_state = json.load(_f)
        except Exception:
            pass

    editor_init_mode = _xformation_state.get('init_mode', 'partial_stub')
    editor_stub_path = _xformation_state.get('stub_path', _active_stub_path or '/igloo/custom_init.sh')
    editor_wrapper_original_path = _xformation_state.get('wrapper_original_path', '')

    # Load skeleton template for "Use template" button
    from modules.xFormation.services.rootfs_modification_service import RootfsModificationService
    _template_file = RootfsModificationService.PATCH_TEMPLATES_DIR / 'custom_init.template.sh'
    try:
        custom_init_template = _template_file.read_text()
    except Exception:
        custom_init_template = '#!/bin/sh\n# Template not found\n'

    try:
        manual_path = os.path.join(device.penguin_project_path, 'static_patches/manual.yaml')
        with open(manual_path, 'r') as f:
            manual_content = f.read()
    except Exception as e:
        manual_content = f"# Error reading manual.yaml: {str(e)}"

    # Read base.yaml (written by fix_broken_device_files during init)
    try:
        base_yaml_path = os.path.join(device.penguin_project_path, 'static_patches/base.yaml')
        with open(base_yaml_path, 'r') as f:
            base_yaml_content = f.read()
    except Exception as e:
        base_yaml_content = f"# Error reading base.yaml: {str(e)}"

    # Read NAT isolation script (written by setup_network_nat)
    try:
        nat_script_path = os.path.join(device.penguin_project_path, 'static_patches/95_network_config.sh')
        with open(nat_script_path, 'r') as f:
            nat_script_content = f.read()
    except Exception as e:
        nat_script_content = f"# Error reading NAT script: {str(e)}"

    # Read strace collection script (written by setup_telemetry_collection)
    try:
        strace_script_path = os.path.join(device.penguin_project_path, 'static_patches/90_telemetry_collection.sh')
        with open(strace_script_path, 'r') as f:
            strace_script_content = f.read()
    except Exception as e:
        strace_script_content = f"# Error reading strace script: {str(e)}"

    # Custom init: conditional — only exists if create_init_stub() was called
    custom_init_exists = os.path.exists(custom_init_path)
    custom_init_content = ''
    if custom_init_exists:
        try:
            with open(custom_init_path, 'r') as f:
                custom_init_content = f.read()
        except Exception as e:
            custom_init_content = f"# Error reading custom init: {str(e)}"

    context = {
        'device': device,
        'config_yaml': config_content,
        'manual_yaml': manual_content,
        'base_yaml': base_yaml_content,
        'nat_script': nat_script_content,
        'strace_script': strace_script_content,
        'custom_init': custom_init_content,
        'custom_init_exists': custom_init_exists,
        'custom_init_enabled': custom_init_enabled,
        'custom_init_template': custom_init_template,
        'init_log': device.initialization_log or '',
        # Init injection editor state (from .xformation.json sidecar)
        'editor_init_mode': editor_init_mode,
        'editor_stub_path': editor_stub_path,
        'editor_wrapper_original_path': editor_wrapper_original_path,
        # Telemetry mode for Launch Settings card (lazy default to filtered)
        'telemetry_mode': (device.config_data or {}).get('telemetry_mode', 'filtered'),
    }
    return render(request, 'xFormation/config_editor.html', context)


@login_required
def download_project(request, device_id):
    """
    Download penguin project as tar.gz
    """
    device = get_object_or_404(EmulatedDevice, id=device_id)
    
    if not device.penguin_project_path or not os.path.exists(device.penguin_project_path):
        messages.error(request, "Penguin project not found")
        return redirect('xformation:device_detail', device_id=device.id)
    
    import tarfile
    import tempfile
    from django.http import FileResponse
    
    try:
        # Create temporary tar.gz file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz')
        
        with tarfile.open(temp_file.name, 'w:gz') as tar:
            tar.add(
                device.penguin_project_path,
                arcname=os.path.basename(device.penguin_project_path)
            )
        
        # Stream file to user
        response = FileResponse(
            open(temp_file.name, 'rb'),
            content_type='application/gzip'
        )
        response['Content-Disposition'] = f'attachment; filename="{device.name}_project.tar.gz"'
        
        return response
        
    except Exception as e:
        messages.error(request, f"Failed to create project archive: {str(e)}")
        return redirect('xformation:config_editor', device_id=device.id) 