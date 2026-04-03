from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from modules.xQuire.models import DeviceType, Manufacturer, Firmware
from modules.xScout.services.analysis_service import FirmwareAnalysisService
import logging

logger = logging.getLogger(__name__)

def home(request):
    """Home page view"""
    context = {
        'firmware_count': Firmware.objects.count(),
        'modules': [
            {
                'name': 'xQuire',
                'description': 'Firmware Download and Management',
                'icon': 'fas fa-download',
                'url': 'xquire:index',
                'is_active': True
            },
            {
                'name': 'xScout',
                'description': 'Firmware Analysis and Vulnerability Scanning',
                'icon': 'fas fa-search',
                'url': 'xscout:index',
                'is_active': True  
            },
            {
                'name': 'xFormation',
                'description': 'Firmware Composition Analysis',
                'icon': 'fas fa-project-diagram',
                'url': 'xformation:index',
                'is_active': True
            }
        ]
    }
    return render(request, 'home.html', context)

@login_required
def dashboard(request):
    """Dashboard view"""
    context = {
        'firmware_count': Firmware.objects.count(),
        'device_type_count': DeviceType.objects.count(),
        'manufacturer_count': Manufacturer.objects.count(),
        'recent_firmwares': Firmware.objects.all().order_by('-upload_date')[:5],
        'modules': [
            {
                'name': 'xQuire',
                'description': 'Firmware Download and Management',
                'icon': 'fas fa-download',
                'count': Firmware.objects.count(),
                'url': 'xquire:index'
            },
            {
                'name': 'xScout',
                'description': 'Firmware Analysis',
                'icon': 'fas fa-search',
                'count': get_analysis_count(),
                'url': 'xscout:index'
            },
            {
                'name': 'xFormation',
                'description': 'Firmware Composition',
                'icon': 'fas fa-project-diagram',
                'count': 0,
                'url': 'xformation:index'
            }
        ]
    }
    return render(request, 'dashboard.html', context)

def get_analysis_count() -> int:
    """Get the number of firmware analyses"""
    try:
        analysis_service = FirmwareAnalysisService()
        analyses = analysis_service.list_analyses()
        completed_count = sum(1 for a in analyses if a.status == 'completed')
        return completed_count
    except Exception as e:
        logger.error(f"Error getting analysis count: {str(e)}")
        return 0

def logout_view(request):
    """Custom logout view that works with both GET and POST requests"""
    logout(request)
    return redirect('logged_out') 