"""
Packaging service for exporting emulated devices as deployable Docker packages.

Generates a Dockerfile, docker-compose.yml, and deploy.sh that allow
running the emulated device as a standalone container without xEndity.
"""
import logging
import os
import shutil
import tarfile
from datetime import datetime

from modules.xFormation.models import EmulationInstance, EmulatedDevice

logger = logging.getLogger(__name__)

PENGUIN_IMAGE = "rehosting/penguin:latest"


class PackagingService:
    """Packages a validated emulation into a deployable Docker archive."""

    @classmethod
    def package_emulation(cls, instance: EmulationInstance, output_dir: str) -> str | None:
        """
        Create a deployable Docker package from a completed emulation instance.

        Returns the path to the .tar.gz archive, or None on failure.
        """
        device = instance.device

        if not device.penguin_project_path or not os.path.isdir(device.penguin_project_path):
            logger.error("Penguin project path not found for device %s", device.id)
            return None

        if not device.config_yaml_path or not os.path.isfile(device.config_yaml_path):
            logger.error("Config YAML not found for device %s", device.id)
            return None

        safe_name = device.name.replace(' ', '_').replace('/', '-').lower()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        package_name = f"xendity_deploy_{safe_name}_{timestamp}"
        package_dir = os.path.join(output_dir, package_name)

        try:
            os.makedirs(package_dir, exist_ok=True)

            cls._copy_project_files(device, package_dir)
            cls._generate_dockerfile(device, instance, package_dir)
            cls._generate_docker_compose(device, instance, package_dir)
            cls._generate_deploy_script(device, instance, package_dir, package_name)
            cls._generate_readme(device, instance, package_dir)

            archive_path = cls._create_archive(package_dir, output_dir, package_name)

            shutil.rmtree(package_dir)

            logger.info("Package created: %s", archive_path)
            return archive_path

        except Exception as e:
            logger.error("Failed to create package for instance %s: %s", instance.id, e)
            if os.path.isdir(package_dir):
                shutil.rmtree(package_dir, ignore_errors=True)
            return None

    @classmethod
    def _copy_project_files(cls, device: EmulatedDevice, package_dir: str):
        """Copy the Penguin project directory into the package."""
        project_dest = os.path.join(package_dir, 'project')
        shutil.copytree(
            device.penguin_project_path, project_dest,
            ignore=shutil.ignore_patterns('results', '*.log', '__pycache__'),
            dirs_exist_ok=True,
        )

    @classmethod
    def _generate_dockerfile(cls, device: EmulatedDevice,
                             instance: EmulationInstance, package_dir: str):
        """Generate a Dockerfile for the emulated device."""
        ports = instance.host_ports or {}
        expose_lines = '\n'.join(
            f'EXPOSE {info["port"]}/{info.get("protocol", "tcp")}'
            for info in ports.values()
            if 'port' in info
        )

        config_rel = os.path.relpath(device.config_yaml_path, device.penguin_project_path)

        dockerfile = f"""\
FROM {PENGUIN_IMAGE}

LABEL maintainer="xEndity"
LABEL description="Emulated IoT device: {device.name}"

COPY project/ /emulation/project/

WORKDIR /emulation/project

{expose_lines}

ENTRYPOINT ["penguin", "run", "{config_rel}"]
"""
        with open(os.path.join(package_dir, 'Dockerfile'), 'w') as f:
            f.write(dockerfile)

    @classmethod
    def _generate_docker_compose(cls, device: EmulatedDevice,
                                 instance: EmulationInstance, package_dir: str):
        """Generate a docker-compose.yml for the emulated device."""
        ports = instance.host_ports or {}
        port_mappings = []
        for service_name, info in ports.items():
            port = info.get('port')
            if port:
                port_mappings.append(f'      - "{port}:{port}/{info.get("protocol", "tcp")}"')

        ports_block = '\n'.join(port_mappings) if port_mappings else '      - "80:80/tcp"'

        compose = f"""\
version: "3.8"

services:
  emulated-device:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: xendity-{device.name.replace(' ', '-').lower()}
    restart: unless-stopped
    ports:
{ports_block}
    volumes:
      - emulation-logs:/emulation/project/results
    cap_add:
      - NET_ADMIN
      - SYS_PTRACE
    deploy:
      resources:
        limits:
          cpus: "{instance.cpu_limit}"
          memory: {instance.memory_limit}

  # Uncomment to add Elastic telemetry export
  # elasticsearch:
  #   image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
  #   environment:
  #     - discovery.type=single-node
  #     - xpack.security.enabled=false
  #     - ES_JAVA_OPTS=-Xms512m -Xmx512m
  #   ports:
  #     - "9200:9200"
  #   volumes:
  #     - es-data:/usr/share/elasticsearch/data
  #
  # kibana:
  #   image: docker.elastic.co/kibana/kibana:8.12.0
  #   environment:
  #     - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
  #   ports:
  #     - "5601:5601"
  #   depends_on:
  #     - elasticsearch

volumes:
  emulation-logs:
  # es-data:
"""
        with open(os.path.join(package_dir, 'docker-compose.yml'), 'w') as f:
            f.write(compose)

    @classmethod
    def _generate_deploy_script(cls, device: EmulatedDevice,
                                instance: EmulationInstance,
                                package_dir: str, package_name: str):
        """Generate a deploy.sh one-command deployment script."""
        script = f"""\
#!/bin/bash
set -e

echo "=== xEndity Emulated Device Deployment ==="
echo "Device: {device.name}"
echo ""

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo "ERROR: Docker Compose is not installed."
    exit 1
fi

echo "Building and starting emulated device..."

if command -v docker compose &> /dev/null; then
    docker compose up -d --build
else
    docker-compose up -d --build
fi

echo ""
echo "=== Deployment Complete ==="
echo "Container: xendity-{device.name.replace(' ', '-').lower()}"
"""
        ports = instance.host_ports or {}
        for service_name, info in ports.items():
            port = info.get('port', '')
            script += f'echo "  {service_name}: http://localhost:{port}"\n'

        script += """\
echo ""
echo "View logs: docker compose logs -f emulated-device"
echo "Stop:      docker compose down"
"""
        deploy_path = os.path.join(package_dir, 'deploy.sh')
        with open(deploy_path, 'w') as f:
            f.write(script)
        os.chmod(deploy_path, 0o755)

    @classmethod
    def _generate_readme(cls, device: EmulatedDevice,
                         instance: EmulationInstance, package_dir: str):
        """Generate a README for the deployment package."""
        telemetry = instance.telemetry_records.first()
        validation = instance.validation_results.first()

        readme = f"""\
# xEndity Emulated Device: {device.name}

Generated by xEndity on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Quick Start

    chmod +x deploy.sh
    ./deploy.sh

Or manually:

    docker compose up -d --build

## Device Information

- **Firmware:** {device.firmware.model.manufacturer.name} {device.firmware.model.model_number} v{device.firmware.version}
- **Architecture:** Determined automatically by Penguin
"""
        if instance.host_ports:
            readme += "\n## Network Services\n\n"
            for service, info in instance.host_ports.items():
                readme += f"- **{service}**: port {info.get('port', 'N/A')} ({info.get('protocol', 'tcp')})\n"

        if validation:
            readme += f"\n## Validation Status: {validation.overall_status.upper()}\n\n"
            readme += f"- Boot: {'PASS' if validation.boot_check else 'FAIL'}\n"
            readme += f"- Services: {'PASS' if validation.services_check else 'FAIL'}\n"
            readme += f"- Ports: {'PASS' if validation.ports_check else 'FAIL'}\n"
            readme += f"- Shell: {'PASS' if validation.shell_check else 'FAIL'}\n"

        if telemetry:
            findings = telemetry.findings.all()
            if findings.exists():
                readme += f"\n## Behavior Findings ({findings.count()})\n\n"
                for f in findings[:10]:
                    readme += f"- [{f.get_severity_display()}] {f.title}\n"

        readme += """
## Architecture Note

For production deployment with network monitoring, consider integrating
with Security Onion (https://securityonion.net/) to route emulated device
traffic through Suricata/Zeek for network-level threat detection, feeding
telemetry into Elasticsearch/Kibana for unified dashboards.
"""
        with open(os.path.join(package_dir, 'README.md'), 'w') as f:
            f.write(readme)

    @classmethod
    def _create_archive(cls, package_dir: str, output_dir: str, package_name: str) -> str:
        """Create a .tar.gz archive of the package directory."""
        archive_path = os.path.join(output_dir, f'{package_name}.tar.gz')
        with tarfile.open(archive_path, 'w:gz') as tar:
            tar.add(package_dir, arcname=package_name)
        return archive_path
