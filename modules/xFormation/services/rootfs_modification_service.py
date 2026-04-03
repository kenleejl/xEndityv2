"""
Rootfs Modification Service for xFormation

Handles rootfs extraction, modification, and repackaging for firmware configuration.
Uses xScout analysis intelligence to avoid redundant detection.
"""

import json
import os
import re
import subprocess
import tempfile
import shutil
import logging
import tarfile
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class RootfsModificationService:
    """Service for manipulating firmware rootfs using xScout intelligence"""
    
    # Template directory path for penguin patch scripts
    PATCH_TEMPLATES_DIR = Path(__file__).parent.parent / 'penguin-patch-templates'
    
    @staticmethod
    def _copy_template_script(template_name: str, dest_path: str, replacements: Optional[Dict[str, str]] = None) -> bool:
        """
        Copy a template script to destination, optionally replacing placeholders
        
        Args:
            template_name: Name of template file in penguin-patch-templates/
            dest_path: Destination path for the script
            replacements: Optional dict of {placeholder: value} to replace in template
            
        Returns:
            True if successful, False otherwise
        """
        try:
            template_path = RootfsModificationService.PATCH_TEMPLATES_DIR / template_name
            
            if not template_path.exists():
                logger.error(f"Template not found: {template_path}")
                return False
            
            # Read template
            with open(template_path, 'r') as f:
                content = f.read()
            
            # Replace placeholders if provided
            if replacements:
                for placeholder, value in replacements.items():
                    content = content.replace(placeholder, value)
            
            # Write to destination
            with open(dest_path, 'w') as f:
                f.write(content)
            
            # Make executable
            os.chmod(dest_path, 0o755)
            
            logger.info(f"Copied template {template_name} to {dest_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to copy template {template_name}: {e}")
            return False
    
    @staticmethod
    def setup_management_access(
        rootfs_path: str,
        username: str = 'root',
        password: str = 'root',
        hash_type: Optional[str] = None,
        ssh_implementation: Optional[str] = None
    ) -> bool:
        """
        Configure SSH access and credentials in rootfs using xScout intelligence
        
        Args:
            rootfs_path: Path to base/fs.tar.gz
            username: SSH username (default: root)
            password: SSH password (default: root)
            hash_type: Password hash type from xScout (md5, sha256, sha512, bcrypt)
            ssh_implementation: SSH service from xScout (dropbear, openssh, tinyssh)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Setting up management access for {rootfs_path}")
            
            # Create temp directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                extract_dir = os.path.join(temp_dir, 'rootfs')
                os.makedirs(extract_dir)
                
                # Extract rootfs
                logger.info("Extracting rootfs...")
                with tarfile.open(rootfs_path, 'r:gz') as tar:
                    tar.extractall(extract_dir)
                
                # Use xScout intelligence for hash type, fallback to detection
                if not hash_type:
                    logger.info("No hash type from xScout, detecting from shadow file...")
                    shadow_path = os.path.join(extract_dir, 'etc/shadow')
                    if os.path.exists(shadow_path):
                        hash_type = RootfsModificationService._detect_hash_type(shadow_path)
                    else:
                        hash_type = 'sha512'  # Modern default
                        logger.info("No shadow file, defaulting to SHA-512")
                else:
                    logger.info(f"Using hash type from xScout: {hash_type}")
                
                # Generate password hash
                password_hash = RootfsModificationService._generate_password_hash(password, hash_type)
                
                if not password_hash:
                    logger.error("Failed to generate password hash")
                    return False
                
                # Modify /etc/shadow
                shadow_path = os.path.join(extract_dir, 'etc/shadow')
                if os.path.exists(shadow_path):
                    RootfsModificationService._modify_shadow(shadow_path, username, password_hash)
                else:
                    logger.warning("No /etc/shadow found, skipping password modification")
                
                # Configure SSH server using xScout intelligence
                if ssh_implementation:
                    logger.info(f"Using SSH implementation from xScout: {ssh_implementation}")
                    RootfsModificationService._configure_ssh(extract_dir, ssh_implementation)
                else:
                    logger.info("No SSH implementation from xScout, attempting auto-detection")
                    RootfsModificationService._configure_ssh(extract_dir)
                
                # Disable telnet
                RootfsModificationService._disable_telnet(extract_dir)
                
                # Backup original
                backup_path = f"{rootfs_path}.backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                shutil.copy2(rootfs_path, backup_path)
                logger.info(f"Backed up original to {backup_path}")
                
                # Repackage rootfs
                logger.info("Repackaging rootfs...")
                with tarfile.open(rootfs_path, 'w:gz') as tar:
                    tar.add(extract_dir, arcname='.')
                
                logger.info("Management access setup completed")
                return True
                
        except Exception as e:
            logger.error(f"Failed to setup management access: {e}", exc_info=True)
            return False
    
    @staticmethod
    def _detect_hash_type(shadow_path: str) -> str:
        """
        Fallback hash type detection when xScout data unavailable
        
        Args:
            shadow_path: Path to /etc/shadow
            
        Returns:
            Hash type: 'md5', 'sha256', 'sha512', or 'bcrypt'
        """
        try:
            with open(shadow_path, 'r') as f:
                for line in f:
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) > 1 and parts[1]:
                            hash_field = parts[1]
                            
                            if hash_field.startswith('$6$'):
                                logger.info("Detected SHA-512 hash from shadow file")
                                return 'sha512'
                            elif hash_field.startswith('$5$'):
                                logger.info("Detected SHA-256 hash from shadow file")
                                return 'sha256'
                            elif hash_field.startswith('$1$'):
                                logger.info("Detected MD5 hash from shadow file")
                                return 'md5'
                            elif hash_field.startswith('$2a$') or hash_field.startswith('$2b$') or hash_field.startswith('$2y$'):
                                logger.info("Detected Bcrypt hash from shadow file")
                                return 'bcrypt'
        except Exception as e:
            logger.warning(f"Could not detect hash type: {e}")
        
        # Default to SHA-512 (most secure and modern standard)
        logger.info("No existing password hashes found, defaulting to SHA-512")
        return 'sha512'
    
    @staticmethod
    def _generate_password_hash(password: str, hash_type: str) -> Optional[str]:
        """
        Generate password hash using openssl
        
        Args:
            password: Plain text password
            hash_type: Hash algorithm ('md5', 'sha256', 'sha512', 'bcrypt')
            
        Returns:
            Password hash or None on failure
        """
        try:
            # Map hash type to openssl flag
            hash_flags = {
                'md5': '-1',
                'sha256': '-5',
                'sha512': '-6',
                'bcrypt': '-2b'  # Note: may not be supported on all systems
            }
            
            flag = hash_flags.get(hash_type, '-6')  # Default to SHA-512
            
            result = subprocess.run(
                ['openssl', 'passwd', flag, password],
                capture_output=True,
                text=True,
                check=True
            )
            
            return result.stdout.strip()
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate password hash: {e.stderr}")
            # Try fallback to SHA-512 if bcrypt failed
            if hash_type == 'bcrypt':
                logger.warning("Bcrypt not supported, falling back to SHA-512")
                return RootfsModificationService._generate_password_hash(password, 'sha512')
            return None
    
    @staticmethod
    def _modify_shadow(shadow_path: str, username: str, password_hash: str):
        """
        Modify /etc/shadow with new password hash
        
        Args:
            shadow_path: Path to shadow file
            username: Username to modify
            password_hash: New password hash
        """
        try:
            lines = []
            with open(shadow_path, 'r') as f:
                for line in f:
                    if line.startswith(f'{username}:'):
                        parts = line.split(':')
                        parts[1] = password_hash  # Replace password field
                        lines.append(':'.join(parts))
                        logger.info(f"Updated password for {username}")
                    else:
                        lines.append(line)
            
            with open(shadow_path, 'w') as f:
                f.writelines(lines)
                
        except Exception as e:
            logger.error(f"Failed to modify shadow file: {e}")
    
    @staticmethod
    def _configure_ssh(extract_dir: str, ssh_impl: Optional[str] = None):
        """
        Configure SSH server using xScout intelligence or auto-detection
        
        Args:
            extract_dir: Root of extracted filesystem
            ssh_impl: SSH implementation from xScout ('dropbear', 'openssh', 'tinyssh')
        """
        # If xScout provided SSH implementation, configure it directly
        if ssh_impl == 'dropbear':
            logger.info("Configuring Dropbear (from xScout)")
            RootfsModificationService._configure_dropbear(extract_dir)
            return
        elif ssh_impl == 'openssh':
            logger.info("Configuring OpenSSH (from xScout)")
            RootfsModificationService._configure_openssh(extract_dir)
            return
        elif ssh_impl == 'tinyssh':
            logger.info("Configuring TinySSH (from xScout)")
            RootfsModificationService._configure_tinyssh(extract_dir)
            return
        
        # Fallback to auto-detection
        logger.info("Auto-detecting SSH implementation...")
        
        # Check for Dropbear
        dropbear_path = os.path.join(extract_dir, 'usr/sbin/dropbear')
        if os.path.exists(dropbear_path):
            logger.info("Detected Dropbear SSH server")
            RootfsModificationService._configure_dropbear(extract_dir)
            return
        
        # Check for OpenSSH
        sshd_path = os.path.join(extract_dir, 'usr/sbin/sshd')
        if os.path.exists(sshd_path):
            logger.info("Detected OpenSSH server")
            RootfsModificationService._configure_openssh(extract_dir)
            return
        
        # Check for TinySSH
        tinyssh_path = os.path.join(extract_dir, 'usr/sbin/tinysshd')
        if os.path.exists(tinyssh_path):
            logger.info("Detected TinySSH server")
            RootfsModificationService._configure_tinyssh(extract_dir)
            return
        
        logger.warning("No SSH server detected in firmware")
    
    @staticmethod
    def _configure_dropbear(extract_dir: str):
        """Configure Dropbear SSH server"""
        default_dir = os.path.join(extract_dir, 'etc/default')
        os.makedirs(default_dir, exist_ok=True)
        
        dropbear_config = os.path.join(default_dir, 'dropbear')
        with open(dropbear_config, 'w') as f:
            f.write('# xFormation: Enable root login\n')
            f.write('DROPBEAR_EXTRA_ARGS=""\n')
        logger.info("Configured Dropbear for root login")
    
    @staticmethod
    def _configure_openssh(extract_dir: str):
        """Configure OpenSSH server"""
        sshd_config_path = os.path.join(extract_dir, 'etc/ssh/sshd_config')
        
        if os.path.exists(sshd_config_path):
            with open(sshd_config_path, 'r') as f:
                lines = f.readlines()
            
            # Ensure PermitRootLogin yes
            modified = False
            for i, line in enumerate(lines):
                if line.strip().startswith('PermitRootLogin'):
                    lines[i] = 'PermitRootLogin yes\n'
                    modified = True
                    break
            
            if not modified:
                lines.append('\n# xFormation: Enable root login\n')
                lines.append('PermitRootLogin yes\n')
            
            with open(sshd_config_path, 'w') as f:
                f.writelines(lines)
        else:
            # Create basic config
            ssh_dir = os.path.join(extract_dir, 'etc/ssh')
            os.makedirs(ssh_dir, exist_ok=True)
            with open(sshd_config_path, 'w') as f:
                f.write('# xFormation: Basic SSH config\n')
                f.write('PermitRootLogin yes\n')
                f.write('PasswordAuthentication yes\n')
        
        logger.info("Configured OpenSSH for root login")
    
    @staticmethod
    def _configure_tinyssh(extract_dir: str):
        """Configure TinySSH server"""
        tinyssh_key_dir = os.path.join(extract_dir, 'etc/tinyssh')
        os.makedirs(tinyssh_key_dir, exist_ok=True)
        logger.info("TinySSH configured - root login enabled by default")
    
    @staticmethod
    def _disable_telnet(extract_dir: str):
        """
        Disable telnet service
        
        Args:
            extract_dir: Root of extracted filesystem
        """
        try:
            telnet_init = os.path.join(extract_dir, 'etc/init.d/telnet')
            if os.path.exists(telnet_init):
                # Disable by removing execute permission
                os.chmod(telnet_init, 0o644)
                logger.info("Disabled telnet service")
        except Exception as e:
            logger.warning(f"Could not disable telnet: {e}")
    
    @staticmethod
    def setup_telemetry_collection(project_path: str, strace_filter: str = 'execve') -> bool:
        """
        Enable filtered strace for telemetry collection.

        Validates strace_filter against a strict allowlist (syscall names and commas only)
        before substituting into the shell template, preventing command injection.

        Args:
            project_path: Path to penguin project directory
            strace_filter: Syscall filter string (default: execve); only [a-zA-Z0-9_,] allowed

        Returns:
            True if successful, False otherwise
        """
        # Validate strace_filter: only syscall names (alphanumeric + underscore) and commas
        if not re.match(r'^[a-zA-Z0-9_,]+$', strace_filter):
            logger.error(f"Invalid strace_filter value rejected: {strace_filter!r}")
            return False

        try:
            # Create static_patches directory
            static_patches_dir = os.path.join(project_path, 'static_patches')
            os.makedirs(static_patches_dir, exist_ok=True)

            strace_script_path = os.path.join(static_patches_dir, '90_telemetry_collection.sh')

            # Copy template with strace filter replacement
            if not RootfsModificationService._copy_template_script(
                '90_telemetry_collection.sh',
                strace_script_path,
                replacements={'{STRACE_FILTER}': strace_filter}
            ):
                return False
            
            # Update config.yaml to enable strace
            config_yaml_path = os.path.join(project_path, 'config.yaml')
            with open(config_yaml_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            if 'core' not in config:
                config['core'] = {}
            
            # Disable Penguin's heavy hypervisor-level strace; use guest-side filtered strace only.
            # The STRACE env var triggers the guest-side 90_telemetry_collection.sh script
            # which runs a lightweight execve-only (or user-configured) trace via /igloo/utils/strace.
            config['core']['strace'] = False
            if 'env' not in config:
                config['env'] = {}
            config['env']['STRACE'] = '1'

            # Add static file
            if 'static_files' not in config:
                config['static_files'] = {}
            
            config['static_files']['/igloo/source.d/90_telemetry_collection.sh'] = {
                'type': 'host_file',
                'host_path': 'static_patches/90_telemetry_collection.sh',
                'mode': '0o755'
            }
            
            with open(config_yaml_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Telemetry configured with filter: {strace_filter}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup telemetry: {e}", exc_info=True)
            return False
    
    @staticmethod
    def apply_telemetry_mode(project_path: str, mode: str) -> bool:
        """
        Apply telemetry mode to config.yaml before launching an emulation instance.

        Reads and mutates config.yaml in-place to configure the correct strace
        behaviour. Called at every launch — idempotent and safe to call repeatedly.

        Modes:
            filtered  — Guest-side filtered strace via 90_telemetry_collection.sh
                        (execve-only). core.strace=False, env.STRACE='1'.
            full      — Hypervisor-level full strace. core.strace=True, env.STRACE
                        removed, telemetry script removed from static_files.
            disabled  — No strace. core.strace=False, env.STRACE removed, telemetry
                        script removed from static_files.

        Unrecognised mode values fall back to 'filtered' with a warning log.

        Args:
            project_path: Path to the Penguin project directory.
            mode: One of 'filtered', 'full', 'disabled'.

        Returns:
            True if config.yaml was successfully updated; False on error.
        """
        VALID_MODES = {'filtered', 'full', 'disabled'}
        if mode not in VALID_MODES:
            logger.warning(
                f"apply_telemetry_mode: unrecognised mode {mode!r}, falling back to 'filtered'"
            )
            mode = 'filtered'

        config_yaml_path = os.path.join(project_path, 'config.yaml')
        if not os.path.exists(config_yaml_path):
            logger.error(f"apply_telemetry_mode: config.yaml not found at {config_yaml_path}")
            return False

        try:
            with open(config_yaml_path, 'r') as f:
                config = yaml.safe_load(f) or {}

            config.setdefault('core', {})
            config.setdefault('env', {})
            config.setdefault('static_files', {})

            STRACE_KEY = '/igloo/source.d/90_telemetry_collection.sh'
            SCRIPT_ENTRY = {
                'type': 'host_file',
                'host_path': 'static_patches/90_telemetry_collection.sh',
                'mode': '0o755'
            }

            if mode == 'filtered':
                config['core']['strace'] = False
                config['env']['STRACE'] = '1'
                config['static_files'][STRACE_KEY] = SCRIPT_ENTRY
            elif mode == 'full':
                config['core']['strace'] = True
                config['env'].pop('STRACE', None)
                config['static_files'].pop(STRACE_KEY, None)
            elif mode == 'disabled':
                config['core']['strace'] = False
                config['env'].pop('STRACE', None)
                config['static_files'].pop(STRACE_KEY, None)

            with open(config_yaml_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"apply_telemetry_mode: applied mode '{mode}' to {project_path}")
            return True

        except Exception as e:
            logger.error(f"apply_telemetry_mode failed: {e}", exc_info=True)
            return False

    @staticmethod
    def create_init_stub(
        rootfs_path: str,
        project_path: str,
        custom_script_path: Optional[str] = None,
        init_mode: str = 'partial_stub',
        stub_path: str = '/igloo/custom_init.sh',
        wrapper_original_path: Optional[str] = None
    ) -> bool:
        """
        Register a custom init script in the Penguin project via mode-aware wiring.

        Supports three injection modes:
          partial_stub — Adds a static_files entry in config.yaml at stub_path only.
                         igloo_init in base.yaml is NOT touched. User controls where in
                         the firmware's init chain the script intercepts.
          full_stub    — Adds static_files entry AND redirects igloo_init in base.yaml
                         to stub_path, replacing the firmware's first process. Saves the
                         original igloo_init value to .xformation.json for restoration.
          disabled     — Removes static_files entry for the previously active stub_path
                         and restores igloo_init in base.yaml if full_stub was active.
                         Archives custom_init.sh to custom_init.sh.disabled.

        rootfs (base/fs.tar.gz) is NOT modified — the overlay approach handles injection.

        Args:
            rootfs_path: Path to base/fs.tar.gz (API compat; used only for wrapper binary
                         extraction in partial_stub/full_stub modes).
            project_path: Path to the Penguin project directory.
            custom_script_path: Source path of the custom init script to deploy. Required
                                 for partial_stub and full_stub. Ignored for disabled.
            init_mode: Injection mode — 'partial_stub' (default), 'full_stub', or 'disabled'.
            stub_path: Guest filesystem path for the static_files overlay entry. Also used
                       as igloo_init value in full_stub mode.
            wrapper_original_path: Optional guest path of the binary hidden by stub_path
                                   overlay. Framework stages it at stub_path + '.real' so
                                   wrapper scripts can exec the original.

        Returns:
            True if successful or no-op, False if an error occurred.
        """
        VALID_MODES = {'partial_stub', 'full_stub', 'disabled'}
        STUB_PATH_RE = re.compile(r'^/[^\s"\'\\<>|]+$')

        # No script provided and not disabling — no-op
        if not custom_script_path and init_mode != 'disabled':
            logger.info("No custom init script provided, skipping init stub creation")
            return True

        # Validate init_mode
        if init_mode not in VALID_MODES:
            logger.warning(
                f"create_init_stub: unrecognised init_mode {init_mode!r}. "
                f"Must be one of {sorted(VALID_MODES)}."
            )
            return False

        # Validate stub_path
        if not STUB_PATH_RE.match(stub_path):
            logger.error(
                f"create_init_stub: invalid stub_path {stub_path!r}. "
                "Must be an absolute path with no spaces or shell metacharacters."
            )
            return False

        try:
            # Load .xformation.json sidecar
            xformation_path = os.path.join(project_path, '.xformation.json')
            xformation_state: dict = {}
            if os.path.exists(xformation_path):
                with open(xformation_path, 'r') as f:
                    xformation_state = json.load(f)

            # Load config.yaml
            config_yaml_path = os.path.join(project_path, 'config.yaml')
            if not os.path.exists(config_yaml_path):
                logger.warning(f"create_init_stub: config.yaml not found at {config_yaml_path}")
                return False

            with open(config_yaml_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            config.setdefault('static_files', {})

            static_patches_dir = os.path.join(project_path, 'static_patches')
            dest_script_path = os.path.join(static_patches_dir, 'custom_init.sh')
            archive_script_path = dest_script_path + '.disabled'

            # ------------------------------------------------------------------
            # DISABLED branch — remove injection wiring, archive script
            # ------------------------------------------------------------------
            if init_mode == 'disabled':
                active_stub = xformation_state.get('stub_path', stub_path)

                # Remove static_files entry for the previously active stub path
                config['static_files'].pop(active_stub, None)

                # If full_stub was previously active, restore igloo_init in base.yaml
                if xformation_state.get('init_mode') == 'full_stub':
                    restore_target = xformation_state.get('original_igloo_init', '/etc/preinit')
                    RootfsModificationService._write_igloo_init(project_path, restore_target)

                # Archive script file
                if os.path.exists(dest_script_path):
                    os.rename(dest_script_path, archive_script_path)
                    logger.info(f"Archived custom_init.sh to {archive_script_path}")

                # Update sidecar
                xformation_state['init_mode'] = 'disabled'
                with open(xformation_path, 'w') as f:
                    json.dump(xformation_state, f, indent=2)

                # Save config.yaml
                with open(config_yaml_path, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)

                logger.info("create_init_stub(disabled): injection wiring removed")
                return True

            # ------------------------------------------------------------------
            # PARTIAL_STUB / FULL_STUB — deploy script and wire config
            # ------------------------------------------------------------------

            # Deploy custom script
            os.makedirs(static_patches_dir, exist_ok=True)
            if os.path.exists(dest_script_path):
                logger.info(f"Overwriting existing custom_init.sh at {dest_script_path}")
            with open(custom_script_path, 'r') as src_f:
                content = src_f.read().replace('\r', '')
            with open(dest_script_path, 'w') as dst_f:
                dst_f.write(content)
            os.chmod(dest_script_path, 0o755)

            # Remove old static_files entry if stub_path changed
            old_stub = xformation_state.get('stub_path')
            if old_stub and old_stub != stub_path:
                config['static_files'].pop(old_stub, None)
                logger.info(f"Removed old static_files entry for {old_stub}")

            # Register static_files entry at stub_path.
            # mode MUST be the string '0o755' (not integer);
            # PyYAML serialises integer octals as decimal (493), breaking Penguin's config parser.
            config['static_files'][stub_path] = {
                'type': 'host_file',
                'host_path': 'static_patches/custom_init.sh',
                'mode': '0o755'
            }

            # Handle wrapper original binary (.real path staging)
            if wrapper_original_path:
                real_path = stub_path + '.real'
                staged = RootfsModificationService._stage_wrapper_real_binary(
                    rootfs_path, static_patches_dir, wrapper_original_path
                )
                if staged:
                    wrapper_basename = os.path.basename(wrapper_original_path)
                    config['static_files'][real_path] = {
                        'type': 'host_file',
                        'host_path': f'static_patches/{wrapper_basename}.real',
                        'mode': '0o755'
                    }
                    logger.info(f"Staged wrapper real binary at {real_path}")
                else:
                    logger.warning(
                        f"create_init_stub: wrapper binary extraction failed for "
                        f"{wrapper_original_path!r} — .real path not staged"
                    )

            # FULL_STUB: also redirect igloo_init in base.yaml
            if init_mode == 'full_stub':
                base_yaml_path = os.path.join(project_path, 'static_patches/base.yaml')
                if os.path.exists(base_yaml_path):
                    # Save original igloo_init before first redirect
                    if 'original_igloo_init' not in xformation_state:
                        with open(base_yaml_path, 'r') as f:
                            base_content = f.read()
                        m = re.search(r'^\s*igloo_init:\s*(.+)$', base_content, re.MULTILINE)
                        original = m.group(1).strip() if m else '/etc/preinit'
                        if original != stub_path:
                            xformation_state['original_igloo_init'] = original
                    RootfsModificationService._write_igloo_init(project_path, stub_path)
                else:
                    logger.warning(
                        f"base.yaml not found at {base_yaml_path}, igloo_init not redirected"
                    )

            # Update sidecar with current mode, stub_path, and optional wrapper path
            xformation_state['init_mode'] = init_mode
            xformation_state['stub_path'] = stub_path
            if wrapper_original_path:
                xformation_state['wrapper_original_path'] = wrapper_original_path

            with open(xformation_path, 'w') as f:
                json.dump(xformation_state, f, indent=2)

            # Save config.yaml
            with open(config_yaml_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            logger.info(
                f"create_init_stub: {init_mode} applied — stub_path={stub_path}, "
                f"static_files entry registered"
            )
            return True

        except Exception as e:
            logger.error(f"create_init_stub failed: {e}", exc_info=True)
            return False

    @staticmethod
    def _write_igloo_init(project_path: str, new_init: str) -> None:
        """
        Write or update the igloo_init value in static_patches/base.yaml in-place.

        Uses regex replacement to preserve comments and inline shell blocks that
        PyYAML would destroy on a full round-trip parse.

        Handles three cases:
          1. igloo_init: line already present — replace in-place.
          2. env: section exists but no igloo_init — insert under env:.
          3. Neither env: nor igloo_init: found — append env: block at end of file.

        Args:
            project_path: Path to the Penguin project directory.
            new_init: Guest path to set as the igloo_init value.
        """
        base_yaml_path = os.path.join(project_path, 'static_patches/base.yaml')
        if not os.path.exists(base_yaml_path):
            logger.warning(f"_write_igloo_init: base.yaml not found at {base_yaml_path}")
            return

        with open(base_yaml_path, 'r') as f:
            base_content = f.read()

        if re.search(r'^\s*igloo_init:\s*', base_content, re.MULTILINE):
            # Case 1: igloo_init line exists — replace it
            base_content = re.sub(
                r'^(\s*igloo_init:).*$',
                r'\g<1> ' + new_init,
                base_content,
                flags=re.MULTILINE
            )
        elif re.search(r'^env:\s*$', base_content, re.MULTILINE):
            # Case 2: env: section exists — insert igloo_init under it
            base_content = re.sub(
                r'^(env:\s*\n)',
                r'\1  igloo_init: ' + new_init + '\n',
                base_content,
                flags=re.MULTILINE
            )
        else:
            # Case 3: no env: section — append at end of file
            base_content = base_content.rstrip('\n') + '\nenv:\n  igloo_init: ' + new_init + '\n'

        with open(base_yaml_path, 'w') as f:
            f.write(base_content)

        logger.info(f"_write_igloo_init: set igloo_init={new_init} in base.yaml")

    @staticmethod
    def _stage_wrapper_real_binary(
        rootfs_path: str,
        static_patches_dir: str,
        wrapper_original_path: str
    ) -> bool:
        """
        Extract a binary from fs.tar.gz and stage it in static_patches/ with a .real suffix.

        Needed when a wrapper-style script replaces a binary at stub_path via the
        static_files overlay: the original binary is hidden at stub_path, but the
        script needs to exec it. Staging it at <basename>.real in static_patches/
        and registering it in static_files at stub_path + '.real' makes it accessible.

        Tries both bare path and './' prefixed path variants from the tarball.

        Args:
            rootfs_path: Path to base/fs.tar.gz.
            static_patches_dir: Destination directory (static_patches/).
            wrapper_original_path: Guest path of the binary (e.g. '/sbin/init').

        Returns:
            True if successfully staged, False if binary not found or extraction failed.
        """
        if not rootfs_path or not os.path.exists(rootfs_path):
            return False

        # Normalise: strip leading '/'
        rel_path = wrapper_original_path.lstrip('/')
        candidates = [rel_path, './' + rel_path]
        basename = os.path.basename(rel_path)
        dest = os.path.join(static_patches_dir, basename + '.real')

        try:
            with tarfile.open(rootfs_path, 'r:gz') as tar:
                member = None
                for candidate in candidates:
                    try:
                        member = tar.getmember(candidate)
                        break
                    except KeyError:
                        continue
                if member is None:
                    logger.warning(
                        f"_stage_wrapper_real_binary: '{wrapper_original_path}' not found in tarball"
                    )
                    return False

                f_obj = tar.extractfile(member)
                if f_obj is None:
                    return False
                with open(dest, 'wb') as out_f:
                    out_f.write(f_obj.read())
                os.chmod(dest, 0o755)
                return True

        except Exception as e:
            logger.warning(f"_stage_wrapper_real_binary failed for {wrapper_original_path!r}: {e}")
            return False
    
    @staticmethod
    def setup_network_nat(project_path: str, gateway: str) -> bool:
        """
        Setup SLIRP interface isolation to prevent firmware network manager conflicts
        
        CRITICAL: Creates slirp0 interface that provides outbound connectivity
        without interfering with firmware's network interfaces (eth0, eth1, wlan0, etc.)
        
        Args:
            project_path: Path to penguin project directory
            gateway: Network gateway IP (for NAT routing, if needed - currently unused)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("Setting up SLIRP interface isolation...")
            
            # Create static_patches directory
            static_patches_dir = os.path.join(project_path, 'static_patches')
            os.makedirs(static_patches_dir, exist_ok=True)
            
            # Copy network config script template
            nat_script_path = os.path.join(static_patches_dir, '95_network_config.sh')
            if not RootfsModificationService._copy_template_script(
                '95_network_config.sh',
                nat_script_path
            ):
                return False
            
            # Update config.yaml to add network.external and static_files
            config_yaml_path = os.path.join(project_path, 'config.yaml')
            with open(config_yaml_path, 'r') as f:
                config = yaml.safe_load(f) or {}
            
            # Enable network.external with MAC for SLIRP identification
            if 'network' not in config:
                config['network'] = {}
            
            if 'external' not in config['network']:
                config['network']['external'] = {}
            
            # Set MAC address for SLIRP interface identification
            config['network']['external']['mac'] = "52:54:00:12:34:56"
            
            # Add NAT script to static_files
            if 'static_files' not in config:
                config['static_files'] = {}
            
            config['static_files']['/igloo/source.d/95_network_config.sh'] = {
                'type': 'host_file',
                'host_path': 'static_patches/95_network_config.sh',
                'mode': '0o755'
            }
            
            # Write back config
            with open(config_yaml_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            
            logger.info("✓ SLIRP interface isolation configured")
            logger.info("  └─ Provides outbound connectivity via slirp0")
            logger.info("  └─ No interference with firmware network managers")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup SLIRP isolation: {e}", exc_info=True)
            return False
