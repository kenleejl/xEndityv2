"""
Telemetry collection service for parsing Penguin emulation output files.

Reads health metrics, network binds, process lists, shell coverage,
console logs, and device access data from a Penguin results directory
and stores them as EmulationTelemetry records.
"""
import csv
import logging
import os

import yaml

from modules.xFormation.models import EmulationInstance, EmulationTelemetry

logger = logging.getLogger(__name__)


class TelemetryService:
    """Parses Penguin result files and creates EmulationTelemetry records."""

    HEALTH_FILE = "health_final.yaml"
    PROCS_FILE = "health_procs_with_args.txt"
    PROCS_BASIC_FILE = "health_procs.txt"
    NETBINDS_FILE = "netbinds.csv"
    SHELL_COV_FILE = "shell_cov.csv"
    DEVICES_FILE = "health_devices_accessed.txt"
    CONSOLE_FILE = "console.log"
    COVERAGE_FILE = "coverage.csv"
    RAN_MARKER = ".ran"

    @classmethod
    def collect_telemetry(cls, instance: EmulationInstance) -> EmulationTelemetry | None:
        """
        Parse all available Penguin output files for an instance and store
        the results as an EmulationTelemetry record.

        Returns the created EmulationTelemetry or None if no results directory exists.
        """
        results_dir = cls._resolve_results_dir(instance)
        if not results_dir:
            logger.warning("No Penguin results directory found for instance %s", instance.id)
            return None

        instance.penguin_results_path = results_dir
        instance.save(update_fields=['penguin_results_path'])

        health_data = cls._parse_health_yaml(results_dir)
        processes = cls._parse_processes(results_dir)
        network_binds = cls._parse_netbinds_csv(results_dir)
        shell_coverage = cls._parse_shell_cov(results_dir)
        devices_accessed = cls._parse_devices_accessed(results_dir)
        kernel_panic, console_snippet = cls._parse_console_log(results_dir)
        score_data = cls._compute_score(results_dir, health_data, kernel_panic, shell_coverage)

        telemetry = EmulationTelemetry.objects.create(
            instance=instance,
            health_data=health_data,
            processes=processes,
            network_binds=network_binds,
            shell_coverage=shell_coverage,
            devices_accessed=devices_accessed,
            kernel_panic=kernel_panic,
            console_snippet=console_snippet,
            score_data=score_data,
        )

        logger.info(
            "Collected telemetry for instance %s: %d processes, %d netbinds, panic=%s",
            instance.id, len(processes), len(network_binds), kernel_panic
        )
        return telemetry

    @classmethod
    def _resolve_results_dir(cls, instance: EmulationInstance) -> str | None:
        """Find the Penguin results directory for an instance."""
        if instance.penguin_results_path and os.path.isdir(instance.penguin_results_path):
            return instance.penguin_results_path

        device = instance.device
        if not device.penguin_project_path:
            return None

        latest = os.path.join(device.penguin_project_path, "results", "latest")
        if os.path.isdir(latest):
            return os.path.realpath(latest)

        results_root = os.path.join(device.penguin_project_path, "results")
        if not os.path.isdir(results_root):
            return None

        subdirs = sorted(
            [d for d in os.listdir(results_root) if d.isdigit()],
            key=int, reverse=True
        )
        if subdirs:
            candidate = os.path.join(results_root, subdirs[0])
            if os.path.isdir(candidate):
                return candidate

        return None

    @classmethod
    def _parse_health_yaml(cls, results_dir: str) -> dict:
        """Parse health_final.yaml into a dict of metric name -> count."""
        filepath = os.path.join(results_dir, cls.HEALTH_FILE)
        if not os.path.isfile(filepath):
            logger.debug("health_final.yaml not found in %s", results_dir)
            return {}

        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                return {k: int(v) for k, v in data.items()}
            return {}
        except Exception as e:
            logger.error("Failed to parse health_final.yaml: %s", e)
            return {}

    @classmethod
    def _parse_processes(cls, results_dir: str) -> list[str]:
        """Parse health_procs_with_args.txt (falls back to health_procs.txt)."""
        for filename in (cls.PROCS_FILE, cls.PROCS_BASIC_FILE):
            filepath = os.path.join(results_dir, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'r') as f:
                        return [line.strip() for line in f if line.strip()]
                except Exception as e:
                    logger.error("Failed to parse %s: %s", filename, e)
        return []

    @classmethod
    def _parse_netbinds_csv(cls, results_dir: str) -> list[dict]:
        """Parse netbinds.csv into a list of bind records."""
        filepath = os.path.join(results_dir, cls.NETBINDS_FILE)
        if not os.path.isfile(filepath):
            return []

        try:
            with open(filepath, 'r', newline='') as f:
                reader = csv.DictReader(f)
                binds = []
                for row in reader:
                    binds.append({
                        'process': row.get('procname', ''),
                        'ip_version': row.get('ipvn', ''),
                        'protocol': row.get('domain', ''),
                        'guest_ip': row.get('guest_ip', ''),
                        'guest_port': int(row.get('guest_port', 0)),
                        'time': float(row.get('time', 0)),
                    })
                return binds
        except Exception as e:
            logger.error("Failed to parse netbinds.csv: %s", e)
            return []

    @classmethod
    def _parse_shell_cov(cls, results_dir: str) -> dict:
        """Parse shell_cov.csv and return coverage summary."""
        filepath = os.path.join(results_dir, cls.SHELL_COV_FILE)
        if not os.path.isfile(filepath):
            return {'lines_covered': 0, 'files': []}

        try:
            with open(filepath, 'r', newline='') as f:
                lines = f.readlines()
            line_count = max(len(lines) - 1, 0)  # subtract header

            files = set()
            for line in lines[1:]:
                parts = line.strip().split(',')
                if parts:
                    files.add(parts[0])

            return {
                'lines_covered': line_count,
                'files': sorted(files),
            }
        except Exception as e:
            logger.error("Failed to parse shell_cov.csv: %s", e)
            return {'lines_covered': 0, 'files': []}

    @classmethod
    def _parse_devices_accessed(cls, results_dir: str) -> list[str]:
        """Parse health_devices_accessed.txt."""
        filepath = os.path.join(results_dir, cls.DEVICES_FILE)
        if not os.path.isfile(filepath):
            return []

        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error("Failed to parse devices accessed: %s", e)
            return []

    @classmethod
    def _parse_console_log(cls, results_dir: str) -> tuple[bool, str | None]:
        """
        Parse console.log for kernel panic.
        Returns (kernel_panic: bool, snippet: str or None).
        """
        filepath = os.path.join(results_dir, cls.CONSOLE_FILE)
        if not os.path.isfile(filepath):
            return False, None

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for i, line in enumerate(lines):
                if 'Kernel panic' in line:
                    start = max(0, i - 2)
                    end = min(len(lines), i + 10)
                    snippet = ''.join(lines[start:end])
                    return True, snippet[:2000]

            return False, None
        except Exception as e:
            logger.error("Failed to parse console.log: %s", e)
            return False, None

    @classmethod
    def _compute_score(cls, results_dir: str, health_data: dict,
                       kernel_panic: bool, shell_coverage: dict) -> dict:
        """
        Compute emulation quality score from available data.
        Mirrors Penguin's manager.calculate_score logic.
        """
        score = {}

        score['execs'] = health_data.get('nexecs', 0)
        score['bound_sockets'] = health_data.get('nbound_sockets', 0)
        score['devices_accessed'] = health_data.get('nuniquedevs', 0)
        score['nopanic'] = 0 if kernel_panic else 1
        score['script_lines_covered'] = shell_coverage.get('lines_covered', 0)

        coverage_path = os.path.join(results_dir, cls.COVERAGE_FILE)
        if os.path.isfile(coverage_path):
            try:
                processes = set()
                modules = set()
                blocks = set()
                with open(coverage_path, 'r', newline='') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 3:
                            processes.add(row[0])
                            modules.add(row[1])
                            blocks.add((row[1], row[2]))
                score['processes_run'] = len(processes)
                score['modules_loaded'] = len(modules)
                score['blocks_covered'] = len(blocks)
            except Exception as e:
                logger.error("Failed to parse coverage.csv: %s", e)

        return score
