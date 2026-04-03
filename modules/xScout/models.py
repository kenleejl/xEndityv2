from django.db import models

# Future models for firmware analysis will be defined here
class Analysis(models.Model):
    """Placeholder for firmware analysis model"""
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name
        
    class Meta:
        verbose_name_plural = "Analyses"
        app_label = "modules_xScout" 