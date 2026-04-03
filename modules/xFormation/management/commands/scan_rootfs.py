"""
Management command to scan for existing rootfs.tar.gz files and populate EmulatedDevice records
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from modules.xFormation.services.device_discovery_service import DeviceDiscoveryService
from modules.xFormation.models import EmulatedDevice
from modules.xQuire.models import Firmware
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Scan all firmware for existing rootfs.tar.gz files and create EmulatedDevice records'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force re-scan of all firmware, including those with existing EmulatedDevice records',
        )
        parser.add_argument(
            '--firmware-id',
            type=int,
            help='Scan only a specific firmware ID',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed progress information',
        )
    
    def handle(self, *args, **options):
        start_time = timezone.now()
        
        self.stdout.write(
            self.style.SUCCESS('Starting rootfs.tar.gz scan...')
        )
        
        try:
            if options['firmware_id']:
                # Scan specific firmware
                result = self._scan_specific_firmware(
                    options['firmware_id'], 
                    options['force'],
                    options['dry_run'],
                    options['verbose']
                )
            else:
                # Scan all firmware
                result = self._scan_all_firmware(
                    options['force'],
                    options['dry_run'],
                    options['verbose']
                )
            
            # Report results
            self._report_results(result, start_time, options['dry_run'])
            
        except Exception as e:
            raise CommandError(f'Scan failed: {e}')
    
    def _scan_specific_firmware(self, firmware_id, force, dry_run, verbose):
        """Scan a specific firmware by ID"""
        try:
            firmware = Firmware.objects.get(id=firmware_id)
            
            if verbose:
                self.stdout.write(f'Scanning firmware {firmware_id}: {firmware.model.manufacturer.name} {firmware.model.model_number}')
            
            # Check if device already exists
            existing_device = EmulatedDevice.objects.filter(firmware=firmware).first()
            if existing_device and not force:
                return {
                    'found': [],
                    'missing': [],
                    'errors': [],
                    'skipped': [firmware_id],
                    'total_scanned': 1
                }
            
            # Find rootfs path
            rootfs_path = DeviceDiscoveryService._find_rootfs_path(firmware)
            
            if rootfs_path:
                if not dry_run:
                    device = DeviceDiscoveryService.create_device_from_extraction(firmware.id, rootfs_path)
                    if device:
                        return {
                            'found': [device],
                            'missing': [],
                            'errors': [],
                            'skipped': [],
                            'total_scanned': 1
                        }
                    else:
                        return {
                            'found': [],
                            'missing': [],
                            'errors': [f'Failed to create device for firmware {firmware_id}'],
                            'skipped': [],
                            'total_scanned': 1
                        }
                else:
                    self.stdout.write(f'[DRY RUN] Would create device for firmware {firmware_id} with rootfs at {rootfs_path}')
                    return {
                        'found': [f'firmware_{firmware_id}'],
                        'missing': [],
                        'errors': [],
                        'skipped': [],
                        'total_scanned': 1
                    }
            else:
                return {
                    'found': [],
                    'missing': [firmware_id],
                    'errors': [],
                    'skipped': [],
                    'total_scanned': 1
                }
                
        except Firmware.DoesNotExist:
            raise CommandError(f'Firmware with ID {firmware_id} not found')
    
    def _scan_all_firmware(self, force, dry_run, verbose):
        """Scan all firmware for rootfs files"""
        
        if force:
            # Scan all firmware regardless of existing devices
            firmware_to_scan = Firmware.objects.all()
            if verbose:
                self.stdout.write(f'Force mode: scanning all {firmware_to_scan.count()} firmware files')
        else:
            # Only scan firmware without existing EmulatedDevice records
            firmware_to_scan = Firmware.objects.exclude(
                id__in=EmulatedDevice.objects.values_list('firmware_id', flat=True)
            )
            if verbose:
                self.stdout.write(f'Scanning {firmware_to_scan.count()} firmware files without existing devices')
        
        if dry_run:
            return self._dry_run_scan(firmware_to_scan, verbose)
        else:
            return DeviceDiscoveryService.scan_all_firmware_for_rootfs()
    
    def _dry_run_scan(self, firmware_queryset, verbose):
        """Perform a dry run scan"""
        found = []
        missing = []
        errors = []
        
        for firmware in firmware_queryset:
            try:
                rootfs_path = DeviceDiscoveryService._find_rootfs_path(firmware)
                if rootfs_path:
                    found.append(f'firmware_{firmware.id}')
                    if verbose:
                        self.stdout.write(f'[DRY RUN] Found rootfs for {firmware.model.manufacturer.name} {firmware.model.model_number}: {rootfs_path}')
                else:
                    missing.append(firmware.id)
                    if verbose:
                        self.stdout.write(f'[DRY RUN] No rootfs found for {firmware.model.manufacturer.name} {firmware.model.model_number}')
            except Exception as e:
                errors.append(f'Error scanning firmware {firmware.id}: {e}')
                if verbose:
                    self.stdout.write(self.style.ERROR(f'[DRY RUN] Error scanning firmware {firmware.id}: {e}'))
        
        return {
            'found': found,
            'missing': missing,
            'errors': errors,
            'skipped': [],
            'total_scanned': firmware_queryset.count()
        }
    
    def _report_results(self, result, start_time, dry_run):
        """Report scan results"""
        duration = timezone.now() - start_time
        
        prefix = "[DRY RUN] " if dry_run else ""
        
        self.stdout.write(
            self.style.SUCCESS(f'\n{prefix}Rootfs scan completed in {duration.total_seconds():.2f} seconds')
        )
        
        # Summary statistics
        self.stdout.write(f'\n{prefix}Summary:')
        self.stdout.write(f'  Total firmware scanned: {result.get("total_scanned", len(result["found"]) + len(result["missing"]))}')
        self.stdout.write(f'  Devices with rootfs found: {len(result["found"])}')
        self.stdout.write(f'  Firmware without rootfs: {len(result["missing"])}')
        
        if result.get('skipped'):
            self.stdout.write(f'  Firmware skipped (already have devices): {len(result["skipped"])}')
        
        if result['errors']:
            self.stdout.write(f'  Errors encountered: {len(result["errors"])}')
        
        # Show found devices
        if result['found'] and not dry_run:
            self.stdout.write(f'\n{prefix}Devices created/updated:')
            for device in result['found']:
                self.stdout.write(f'  - {device}')
        
        # Show errors if any
        if result['errors']:
            self.stdout.write(f'\n{prefix}Errors:')
            for error in result['errors']:
                self.stdout.write(self.style.ERROR(f'  - {error}'))
        
        # Performance metrics
        total_firmware = Firmware.objects.count()
        devices_with_rootfs = EmulatedDevice.objects.filter(has_rootfs=True).count() if not dry_run else len(result['found'])
        
        self.stdout.write(f'\n{prefix}Overall status:')
        self.stdout.write(f'  Total firmware in system: {total_firmware}')
        self.stdout.write(f'  Devices with rootfs: {devices_with_rootfs}')
        self.stdout.write(f'  Coverage: {(devices_with_rootfs/total_firmware*100):.1f}%' if total_firmware > 0 else '  Coverage: 0%')
        
        if not dry_run and result['found']:
            self.stdout.write(
                self.style.SUCCESS(f'\n✅ Successfully processed {len(result["found"])} firmware files!')
            )
        elif dry_run:
            self.stdout.write(
                self.style.WARNING(f'\n🔍 Dry run complete. Use without --dry-run to make changes.')
            )
