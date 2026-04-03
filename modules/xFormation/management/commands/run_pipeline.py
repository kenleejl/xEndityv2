"""
Management command to run the full firmware emulation pipeline.

Usage:
    python manage.py run_pipeline <firmware_id> [--timeout 300]
"""
import json

from django.core.management.base import BaseCommand, CommandError

from modules.xFormation.services.pipeline_service import PipelineService


class Command(BaseCommand):
    help = 'Run the full firmware emulation pipeline (extract -> init -> emulate -> analyze -> validate)'

    def add_arguments(self, parser):
        parser.add_argument('firmware_id', type=int, help='ID of the firmware to process')
        parser.add_argument(
            '--timeout', type=int, default=300,
            help='Emulation timeout in seconds (default: 300)',
        )

    def handle(self, *args, **options):
        firmware_id = options['firmware_id']
        timeout = options['timeout']

        self.stdout.write(f'Starting pipeline for firmware {firmware_id} (timeout: {timeout}s)...')
        self.stdout.write('')

        result = PipelineService.run_pipeline(firmware_id, emulation_timeout=timeout)

        for stage_name, stage_data in result.get('stages', {}).items():
            success = stage_data.get('success', False)
            icon = 'PASS' if success else 'FAIL'
            message = stage_data.get('message', '')
            skipped = ' (skipped)' if stage_data.get('skipped') else ''
            self.stdout.write(f'  [{icon}] {stage_name}: {message}{skipped}')

        self.stdout.write('')
        overall = result.get('overall_status', 'unknown')
        if overall == 'completed':
            self.stdout.write(self.style.SUCCESS(f'Pipeline completed successfully'))
        else:
            self.stdout.write(self.style.ERROR(f'Pipeline {overall}'))
            if result.get('error'):
                self.stdout.write(self.style.ERROR(f'  Error: {result["error"]}'))
