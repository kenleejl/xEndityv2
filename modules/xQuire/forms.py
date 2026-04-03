from django import forms
from .models import DeviceType, Manufacturer, FirmwareModel, Firmware

class FirmwareUploadForm(forms.Form):
    """Form for uploading a firmware file manually"""
    manufacturer = forms.ModelChoiceField(
        queryset=Manufacturer.objects.all().order_by('name'),
        required=True,
        empty_label="Select manufacturer"
    )
    device_type = forms.ModelChoiceField(
        queryset=DeviceType.objects.all().order_by('name'),
        required=True,
        empty_label="Select device type"
    )
    model_number = forms.CharField(max_length=100, required=True)
    version = forms.CharField(max_length=50, required=True)
    file = forms.FileField(required=True)
    notes = forms.CharField(widget=forms.Textarea(attrs={'rows': 3}), required=False)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({'class': 'form-control'})

class FirmwareWebDownloadForm(forms.Form):
    manufacturer = forms.ModelChoiceField(
        queryset=Manufacturer.objects.all().order_by('name'),
        required=True,
        empty_label="Select manufacturer"
    )
    device_type = forms.ModelChoiceField(
        queryset=DeviceType.objects.all().order_by('name'),
        required=True,
        empty_label="Select device type"
    )
    model_number = forms.CharField(max_length=100, required=True)
    version = forms.CharField(max_length=50, required=True)
    url = forms.URLField(required=True, label="Firmware URL")
    notes = forms.CharField(widget=forms.Textarea(attrs={'rows': 3}), required=False)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({'class': 'form-control'})

class FirmwareSearchForm(forms.Form):
    search_query = forms.CharField(required=False, label="Search", 
                                 widget=forms.TextInput(attrs={'placeholder': 'Search by model, version...'}))
    manufacturer = forms.ModelChoiceField(
        queryset=Manufacturer.objects.all().order_by('name'),
        required=False,
        empty_label="All Manufacturers"
    )
    device_type = forms.ModelChoiceField(
        queryset=DeviceType.objects.all().order_by('name'),
        required=False,
        empty_label="All Device Types"
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({'class': 'form-control'})
            
    def get_filters(self):
        """Return a dictionary of filters to apply to the queryset"""
        filters = {}
        if self.cleaned_data.get('manufacturer'):
            filters['model__manufacturer'] = self.cleaned_data['manufacturer']
        if self.cleaned_data.get('device_type'):
            filters['model__device_type'] = self.cleaned_data['device_type']
        return filters

class DeviceTypeForm(forms.ModelForm):
    """Form for creating/editing device types"""
    class Meta:
        model = DeviceType
        fields = ['name', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }

class ManufacturerForm(forms.ModelForm):
    """Form for creating/editing manufacturers"""
    class Meta:
        model = Manufacturer
        fields = ['name', 'website']

class FirmwareModelForm(forms.ModelForm):
    """Form for creating/editing firmware models"""
    class Meta:
        model = FirmwareModel
        fields = ['manufacturer', 'device_type', 'model_number', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        } 