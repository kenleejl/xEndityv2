"""
Management command for xFormation cleanup and maintenance
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from modules.xFormation.models import EmulationInstance
from modules.xFormation.services.emulation_manager_service import EmulationManagerService
from modules.xFormation.services.live_output_service import LiveOutputService
from modules.xFormation.services.docker_penguin_service import DockerPenguinService
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Cleanup dead instances and perform maintenance tasks'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            dest='dry_run',
            help='Show what would be done without actually doing it',
        )
        
        parser.add_argument(
            '--cleanup-logs',
            action='store_true',
            dest='cleanup_logs',
            help='Also cleanup old log files',
        )
        
        parser.add_argument(
            '--cleanup-docker',
            action='store_true',
            dest='cleanup_docker',
            help='Also cleanup orphaned Docker containers and networks',
        )
    
    def handle(self, *args, **options):
        dry_run = options['dry_run']
        cleanup_logs = options['cleanup_logs']
        cleanup_docker = options['cleanup_docker']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))
        
        self.stdout.write('Starting xFormation cleanup...')
        
        # Cleanup dead instances (includes Docker check)
        self.cleanup_dead_instances(dry_run)
        
        # Cleanup old output buffers
        self.cleanup_output_buffers(dry_run)
        
        # Cleanup orphaned Docker resources if requested
        if cleanup_docker:
            self.cleanup_docker_resources(dry_run)
        
        # Cleanup old log files if requested
        if cleanup_logs:
            self.cleanup_old_logs(dry_run)
        
        self.stdout.write(self.style.SUCCESS('Cleanup completed'))
    
    def cleanup_dead_instances(self, dry_run):
        """Clean up instances whose processes or containers have died"""
        self.stdout.write('Checking for dead instances...')
        
        running_instances = EmulationInstance.objects.filter(status='running')
        dead_count = 0
        
        for instance in running_instances:
            # Check Docker containers first
            if hasattr(instance, 'docker_container_id') and instance.docker_container_id:
                try:
                    status = DockerPenguinService.get_container_status(
                        instance.docker_container_name or instance.instance_name
                    )
                    
                    if status is None or status in ['exited', 'dead', 'removing']:
                        self.stdout.write(f'Found dead Docker instance: {instance.instance_name} (container status: {status})')
                        if not dry_run:
                            instance.status = 'stopped'
                            instance.stopped_at = timezone.now()
                            instance.save()
                            
                            # Cleanup Docker resources
                            try:
                                DockerPenguinService.stop_penguin_container(
                                    container_name=instance.docker_container_name or instance.instance_name,
                                    network_name=getattr(instance, 'docker_network_name', None),
                                    timeout=5
                                )
                                self.stdout.write(f'  Cleaned up Docker resources for {instance.instance_name}')
                            except Exception as e:
                                self.stdout.write(self.style.WARNING(f'  Failed to cleanup Docker resources: {e}'))
                        dead_count += 1
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'Error checking Docker container for {instance.instance_name}: {e}'))
            
            # Check process-based instances
            elif instance.process_id:
                try:
                    import psutil
                    process = psutil.Process(instance.process_id)
                    if not process.is_running():
                        self.stdout.write(f'Found dead process instance: {instance.instance_name} (PID {instance.process_id})')
                        if not dry_run:
                            instance.status = 'stopped'
                            instance.stopped_at = timezone.now()
                            instance.save()
                        dead_count += 1
                except (psutil.NoSuchProcess, ImportError):
                    self.stdout.write(f'Found dead process instance: {instance.instance_name} (Process not found)')
                    if not dry_run:
                        instance.status = 'stopped'
                        instance.stopped_at = timezone.now()
                        instance.save()
                    dead_count += 1
            else:
                self.stdout.write(f'Found instance without PID or container: {instance.instance_name}')
                if not dry_run:
                    instance.status = 'failed'
                    instance.stopped_at = timezone.now()
                    instance.save()
                dead_count += 1
        
        if dead_count > 0:
            self.stdout.write(self.style.WARNING(f'Found {dead_count} dead instances'))
        else:
            self.stdout.write(self.style.SUCCESS('No dead instances found'))
    
    def cleanup_output_buffers(self, dry_run):
        """Clean up old output buffers from memory"""
        self.stdout.write('Cleaning up output buffers...')
        
        # Get active instance IDs
        active_instances = set(EmulationInstance.objects.filter(status='running').values_list('id', flat=True))
        
        # Get buffered instance IDs
        buffered_instances = set(LiveOutputService.get_active_instances())
        
        # Find orphaned buffers
        orphaned = buffered_instances - active_instances
        
        if orphaned:
            self.stdout.write(f'Found {len(orphaned)} orphaned output buffers')
            if not dry_run:
                for instance_id in orphaned:
                    LiveOutputService.cleanup_instance_data(instance_id)
                    self.stdout.write(f'Cleaned up buffer for instance {instance_id}')
        else:
            self.stdout.write(self.style.SUCCESS('No orphaned buffers found'))
    
    def cleanup_docker_resources(self, dry_run):
        """Clean up orphaned Docker containers and networks"""
        self.stdout.write('Cleaning up orphaned Docker resources...')
        
        if not DockerPenguinService.is_available():
            self.stdout.write(self.style.WARNING('Docker is not available, skipping Docker cleanup'))
            return
        
        if dry_run:
            self.stdout.write(self.style.WARNING('Would cleanup orphaned penguin Docker resources (dry-run)'))
        else:
            try:
                cleaned_count = DockerPenguinService.cleanup_penguin_resources()
                if cleaned_count > 0:
                    self.stdout.write(self.style.SUCCESS(f'Cleaned up {cleaned_count} orphaned Docker resources'))
                else:
                    self.stdout.write(self.style.SUCCESS('No orphaned Docker resources found'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Error during Docker cleanup: {e}'))
    
    def cleanup_old_logs(self, dry_run):
        """Clean up old log files"""
        self.stdout.write('Cleaning up old log files...')
        
        import os
        from datetime import timedelta
        
        # Get log directory
        log_dir = getattr(EmulationManagerService, 'INSTANCE_LOGS_DIR', '/tmp/xformation_logs')
        
        if not os.path.exists(log_dir):
            self.stdout.write('Log directory does not exist')
            return
        
        # Find logs older than 7 days
        cutoff_time = timezone.now() - timedelta(days=7)
        old_files = []
        
        for filename in os.listdir(log_dir):
            filepath = os.path.join(log_dir, filename)
            if os.path.isfile(filepath):
                file_time = timezone.datetime.fromtimestamp(os.path.getmtime(filepath), tz=timezone.get_current_timezone())
                if file_time < cutoff_time:
                    old_files.append(filepath)
        
        if old_files:
            self.stdout.write(f'Found {len(old_files)} old log files')
            if not dry_run:
                for filepath in old_files:
                    try:
                        os.remove(filepath)
                        self.stdout.write(f'Removed {filepath}')
                    except OSError as e:
                        self.stdout.write(self.style.ERROR(f'Failed to remove {filepath}: {e}'))
        else:
            self.stdout.write(self.style.SUCCESS('No old log files found'))


