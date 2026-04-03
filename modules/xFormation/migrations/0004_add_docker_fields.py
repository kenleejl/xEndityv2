# Generated migration for Docker API integration

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('modules_xFormation', '0003_emulateddevice_has_rootfs_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='emulationinstance',
            name='docker_container_id',
            field=models.CharField(blank=True, help_text='Docker container ID', max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='emulationinstance',
            name='docker_container_name',
            field=models.CharField(blank=True, help_text='Docker container name', max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='emulationinstance',
            name='docker_network_name',
            field=models.CharField(blank=True, help_text='Docker network name', max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='emulationinstance',
            name='docker_subnet',
            field=models.CharField(blank=True, help_text='Docker network subnet', max_length=32, null=True),
        ),
    ]

