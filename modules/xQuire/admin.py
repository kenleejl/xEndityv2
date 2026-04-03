from django.contrib import admin
from .models import Manufacturer, DeviceType, FirmwareModel, Firmware

@admin.register(Manufacturer)
class ManufacturerAdmin(admin.ModelAdmin):
    list_display = ('name', 'website')
    search_fields = ('name',)

@admin.register(DeviceType)
class DeviceTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name',)

@admin.register(FirmwareModel)
class FirmwareModelAdmin(admin.ModelAdmin):
    list_display = ('model_number', 'manufacturer', 'device_type')
    list_filter = ('manufacturer', 'device_type')
    search_fields = ('model_number', 'manufacturer__name')

@admin.register(Firmware)
class FirmwareAdmin(admin.ModelAdmin):
    list_display = ('model', 'version', 'upload_date', 'md5')
    list_filter = ('model__manufacturer', 'model__device_type')
    search_fields = ('model__model_number', 'version')
    readonly_fields = ('md5', 'sha256', 'file_size', 'upload_date')
    fieldsets = (
        (None, {
            'fields': ('model', 'version', 'file')
        }),
        ('Metadata', {
            'fields': ('md5', 'sha256', 'file_size', 'upload_date', 'source_url', 'notes')
        }),
    )
