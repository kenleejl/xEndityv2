from django.urls import path
from . import views

app_name = 'xformation'

urlpatterns = [
    # Main views
    path('', views.index, name='index'),
    
    # Pipeline
    path('pipeline/', views.pipeline_dashboard, name='pipeline_dashboard'),
    path('pipeline/run/<int:firmware_id>/', views.pipeline_run, name='pipeline_run'),
    path('api/pipeline/<int:firmware_id>/status/', views.api_pipeline_status, name='api_pipeline_status'),
    
    # Device management
    path('device/<int:device_id>/', views.device_detail, name='device_detail'),
    
    # Node Emulation Engine - Initialization workflow
    path('device/<int:device_id>/initialize/', views.device_initialize, name='device_initialize'),
    path('device/<int:device_id>/config-form/', views.config_form, name='config_form'),
    path('device/<int:device_id>/config-editor/', views.config_editor, name='config_editor'),
    path('device/<int:device_id>/download/', views.download_project, name='download_project'),
    
    # Instance management
    path('instance/<int:instance_id>/', views.instance_detail, name='instance_detail'),
    path('instance/<int:instance_id>/log/', views.download_instance_log, name='download_log'),
    path('instance/<int:instance_id>/export/', views.export_package, name='export_package'),
    
    # API endpoints
    path('api/device/<int:device_id>/status/', views.api_device_status, name='api_device_status'),
    path('api/instance/<int:instance_id>/status/', views.api_instance_status, name='api_instance_status'),
    path('api/instance/<int:instance_id>/output/', views.api_instance_output, name='api_instance_output'),
    
    # Legacy
    path('analyze/', views.analyze_composition, name='analyze'),
] 