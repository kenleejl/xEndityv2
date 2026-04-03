from django.urls import path
from . import views

app_name = 'xscout'

urlpatterns = [
    path('', views.index, name='index'),
    
    # New unified firmware analysis structure
    path('firmware/<int:firmware_id>/', views.firmware_analysis, name='firmware_analysis'),
    path('firmware/<int:firmware_id>/binary/', views.analysis_results, name='firmware_binary_detail'),
    path('firmware/<int:firmware_id>/extraction/', views.extract_firmware, name='firmware_extraction_detail'),
    path('firmware/<int:firmware_id>/analysis/', views.components_analysis, name='firmware_analysis_detail'),
    path('firmware/<int:firmware_id>/security/', views.security_analysis_detail, name='firmware_security_detail'),
    path('firmware/<int:firmware_id>/security/sbom/', views.sbom_viewer, name='firmware_sbom_detail'),
    path('firmware/<int:firmware_id>/security/vulnerabilities/', views.vulnerability_viewer, name='firmware_vulnerability_detail'),
    
    # Legacy URLs (keeping for backward compatibility)
    path('analyze/', views.analyze_firmware, name='analyze'),
    path('analyze/start/', views.start_analysis, name='start_analysis'),
    path('analyze/status/<str:analysis_id>/', views.analysis_status, name='analysis_status'),
    path('analyze/results/<str:analysis_id>/', views.analysis_results, name='analysis_results'),
    path('analyses/', views.analysis_list, name='analysis_list'),
    path('analyses/delete/<str:analysis_id>/', views.delete_analysis, name='delete_analysis'),
    
    # Extraction URLs
    path('extract/', views.extract_firmware, name='extract'),
    path('extract/start/', views.start_extraction, name='start_extraction'),
    path('extract/status/<int:firmware_id>/', views.check_extraction_status, name='check_extraction_status'),
    
    # Components Analysis URLs
    path('components-analysis/', views.components_analysis, name='components_analysis'),
    path('components-analysis/start/', views.start_components_analysis, name='start_components_analysis'),
    
    # SBOM and Vulnerability Analysis URLs
    path('sbom/generate/', views.generate_sbom, name='generate_sbom'),
    path('vulnerabilities/check/', views.check_vulnerabilities, name='check_vulnerabilities'),
    path('security-analysis/run/', views.run_security_analysis, name='run_security_analysis'),
    path('start-components-analysis/', views.start_components_analysis, name='start_components_analysis'),
    path('generate-sbom/', views.generate_sbom, name='generate_sbom'),
    path('check-vulnerabilities/', views.check_vulnerabilities, name='check_vulnerabilities'),
    path('run-security-analysis/', views.run_security_analysis, name='run_security_analysis'),
    
    # Security analysis pages
    path('security/', views.security_dashboard, name='security_dashboard'),
    path('security/firmware/<int:firmware_id>/', views.security_analysis_detail, name='security_analysis_detail'),
    path('security/firmware/<int:firmware_id>/sbom/', views.sbom_viewer, name='sbom_viewer'),
    path('security/firmware/<int:firmware_id>/vulnerabilities/', views.vulnerability_viewer, name='vulnerability_viewer'),
    path('security/firmware/<int:firmware_id>/delete/', views.delete_security_analysis, name='delete_security_analysis'),
    path('security/compare/', views.firmware_comparison, name='firmware_comparison'),
    
    # API endpoints
    path('api/workflow/run/', views.run_complete_workflow, name='run_complete_workflow'),
    path('api/security/<int:firmware_id>/summary/', views.api_security_summary, name='api_security_summary'),
    path('api/vulnerabilities/search/', views.api_vulnerability_search, name='api_vulnerability_search'),
] 