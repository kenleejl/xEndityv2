"""
Pipeline orchestration service for end-to-end firmware processing.

Chains: extraction -> device creation -> penguin init -> emulation ->
telemetry collection -> behavior analysis -> validation.
"""
import logging
import time
import threading
import os

from django.utils import timezone

from modules.xQuire.models import Firmware
from modules.xFormation.models import EmulatedDevice, EmulationInstance

logger = logging.getLogger(__name__)

POLL_INTERVAL = 5
EXTRACTION_TIMEOUT = 600
INIT_TIMEOUT = 300
EMULATION_TIMEOUT = 300


class PipelineService:
    """Orchestrates the full firmware analysis and emulation pipeline."""

    # Track running pipelines: firmware_id -> status dict
    _pipelines = {}
    _lock = threading.Lock()

    @classmethod
    def get_pipeline_status(cls, firmware_id: int) -> dict | None:
        with cls._lock:
            return cls._pipelines.get(firmware_id, {}).copy() if firmware_id in cls._pipelines else None

    @classmethod
    def get_all_pipeline_statuses(cls) -> dict:
        with cls._lock:
            return {k: v.copy() for k, v in cls._pipelines.items()}

    @classmethod
    def run_pipeline(cls, firmware_id: int, emulation_timeout: int = EMULATION_TIMEOUT) -> dict:
        """
        Run the full pipeline synchronously for a given firmware.
        Returns a result dict with status of each stage.
        """
        result = {
            'firmware_id': firmware_id,
            'started_at': timezone.now().isoformat(),
            'stages': {},
            'overall_status': 'running',
            'current_stage': 'extraction',
        }

        with cls._lock:
            cls._pipelines[firmware_id] = result

        try:
            firmware = Firmware.objects.get(pk=firmware_id)
        except Firmware.DoesNotExist:
            result['overall_status'] = 'failed'
            result['error'] = f'Firmware {firmware_id} not found'
            cls._update_pipeline(firmware_id, result)
            return result

        # Stage 1: Extraction
        result['current_stage'] = 'extraction'
        cls._update_pipeline(firmware_id, result)
        extraction_result = cls._stage_extraction(firmware)
        result['stages']['extraction'] = extraction_result
        if not extraction_result['success']:
            result['overall_status'] = 'failed'
            cls._update_pipeline(firmware_id, result)
            return result

        # Stage 2: Device Discovery
        result['current_stage'] = 'device_discovery'
        cls._update_pipeline(firmware_id, result)
        device_result = cls._stage_device_discovery(firmware)
        result['stages']['device_discovery'] = device_result
        if not device_result['success']:
            result['overall_status'] = 'failed'
            cls._update_pipeline(firmware_id, result)
            return result

        device = device_result['device']

        # Stage 3: Penguin Init
        result['current_stage'] = 'initialization'
        cls._update_pipeline(firmware_id, result)
        init_result = cls._stage_init(device)
        result['stages']['initialization'] = init_result
        if not init_result['success']:
            result['overall_status'] = 'failed'
            cls._update_pipeline(firmware_id, result)
            return result

        # Stage 4: Emulation
        result['current_stage'] = 'emulation'
        cls._update_pipeline(firmware_id, result)
        emulation_result = cls._stage_emulation(device, emulation_timeout)
        result['stages']['emulation'] = emulation_result

        # Telemetry/analysis/validation run automatically via emulation_manager_service
        # when the instance stops. Check the results.
        instance = emulation_result.get('instance')
        if instance:
            instance.refresh_from_db()
            telemetry = instance.telemetry_records.first()
            result['stages']['telemetry'] = {
                'success': telemetry is not None,
                'has_data': telemetry is not None,
                'process_count': len(telemetry.processes) if telemetry else 0,
                'findings_count': telemetry.findings.count() if telemetry else 0,
            }

            validation = instance.validation_results.first()
            result['stages']['validation'] = {
                'success': validation is not None,
                'status': validation.overall_status if validation else 'not_run',
                'checks_passed': validation.checks_passed if validation else 0,
                'checks_total': validation.checks_total if validation else 4,
            }

        result['current_stage'] = 'completed'
        result['overall_status'] = 'completed'
        result['completed_at'] = timezone.now().isoformat()
        cls._update_pipeline(firmware_id, result)
        return result

    @classmethod
    def run_pipeline_async(cls, firmware_id: int, emulation_timeout: int = EMULATION_TIMEOUT):
        """Launch the pipeline in a background thread."""
        thread = threading.Thread(
            target=cls.run_pipeline,
            args=(firmware_id, emulation_timeout),
            daemon=True,
        )
        thread.start()
        logger.info("Pipeline started async for firmware %s", firmware_id)

    @classmethod
    def _update_pipeline(cls, firmware_id: int, result: dict):
        with cls._lock:
            cls._pipelines[firmware_id] = result.copy()

    @classmethod
    def _stage_extraction(cls, firmware: Firmware) -> dict:
        """Run or verify firmware extraction."""
        from modules.xScout.services.extraction_service import ExtractionService

        device = EmulatedDevice.objects.filter(firmware=firmware, has_rootfs=True).first()
        if device and device.rootfs_path and os.path.exists(
                os.path.join(os.path.dirname(device.rootfs_path or ''), 'rootfs.tar.gz')):
            return {'success': True, 'skipped': True, 'message': 'Already extracted'}

        fw_path = firmware.file.path if firmware.file else None
        if not fw_path or not os.path.exists(fw_path):
            return {'success': False, 'message': f'Firmware file not found: {fw_path}'}

        extractor = ExtractionService()
        success, message = extractor.extract_firmware(firmware.id)
        if not success:
            return {'success': False, 'message': message}

        elapsed = 0
        while elapsed < EXTRACTION_TIMEOUT:
            device = EmulatedDevice.objects.filter(firmware=firmware, has_rootfs=True).first()
            if device:
                return {'success': True, 'skipped': False, 'message': 'Extraction completed'}
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        return {'success': False, 'message': 'Extraction timed out'}

    @classmethod
    def _stage_device_discovery(cls, firmware: Firmware) -> dict:
        """Ensure an EmulatedDevice exists for the firmware."""
        device = EmulatedDevice.objects.filter(firmware=firmware, has_rootfs=True).first()
        if device:
            return {'success': True, 'device': device, 'device_id': device.id}

        return {'success': False, 'message': 'No device with rootfs found after extraction'}

    @classmethod
    def _stage_init(cls, device: EmulatedDevice) -> dict:
        """Run penguin init if not already initialized."""
        from .penguin_integration_service import PenguinIntegrationService

        if device.initialization_status == 'initialized' and device.can_run:
            return {'success': True, 'skipped': True, 'message': 'Already initialized'}

        PenguinIntegrationService.initialize_device_async(device)

        elapsed = 0
        while elapsed < INIT_TIMEOUT:
            device.refresh_from_db()
            if device.initialization_status == 'initialized':
                return {'success': True, 'skipped': False, 'message': 'Initialization completed'}
            if device.initialization_status == 'init_failed':
                return {'success': False, 'message': 'Penguin init failed'}
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        return {'success': False, 'message': 'Initialization timed out'}

    @classmethod
    def _stage_emulation(cls, device: EmulatedDevice, timeout: int) -> dict:
        """Start emulation and wait for it to complete or timeout."""
        from .emulation_manager_service import EmulationManagerService

        device.refresh_from_db()
        if not device.can_run:
            return {'success': False, 'message': 'Device not ready to run'}

        instance = EmulationManagerService.start_instance(device)
        if not instance:
            return {'success': False, 'message': 'Failed to start emulation instance'}

        elapsed = 0
        while elapsed < timeout:
            instance.refresh_from_db()
            if instance.status in ('stopped', 'failed'):
                return {
                    'success': instance.status == 'stopped',
                    'instance': instance,
                    'instance_id': instance.id,
                    'status': instance.status,
                    'message': f'Emulation {instance.status}',
                }
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL

        EmulationManagerService.stop_instance(instance)
        instance.refresh_from_db()
        return {
            'success': True,
            'instance': instance,
            'instance_id': instance.id,
            'status': 'stopped_timeout',
            'message': f'Emulation stopped after {timeout}s timeout',
        }
