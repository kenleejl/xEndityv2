from django.urls import path
from . import views

app_name = 'xquire'

urlpatterns = [
    path('', views.index, name='index'),
    path('firmware/<int:pk>/', views.firmware_detail, name='firmware_detail'),
    path('firmware/<int:pk>/delete/', views.delete_firmware, name='delete_firmware'),
    path('firmware/upload/', views.upload_firmware, name='upload_firmware'),
    path('firmware/download/', views.download_firmware, name='download_firmware'),
    path('download-status/<str:download_id>/', views.download_status, name='download_status'),
    path('cancel-download/<str:download_id>/', views.cancel_download, name='cancel_download'),
    path('firmwares/<str:filename>', views.serve_firmware_file, name='serve_firmware_file'),
] 