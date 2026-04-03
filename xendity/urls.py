"""
URL configuration for xendity project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView, TemplateView
from . import views

urlpatterns = [
    path('admin', admin.site.urls),
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # Authentication URLs
    path('accounts/logout/', views.logout_view, name='logout'),
    path('accounts/logged_out/', TemplateView.as_view(template_name='registration/logged_out.html'), name='logged_out'),
    path('accounts/', include('django.contrib.auth.urls')),
    
    # Module URLs
    path('xquire/', include('modules.xQuire.urls', namespace='xquire')),
    path('xscout/', include('modules.xScout.urls', namespace='xscout')),
    path('xformation/', include('modules.xFormation.urls', namespace='xformation')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
    # Add a pattern for serving firmware files - this is just for development
    # In production, you should use a more secure method
    firmware_url = '/firmwares/'
    urlpatterns += static(firmware_url, document_root=settings.FIRMWARE_ROOT)
