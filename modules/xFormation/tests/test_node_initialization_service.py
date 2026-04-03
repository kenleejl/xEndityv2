"""
Tests for NodeInitializationService device node fix logic.

These tests cover the two-layer fix in fix_broken_device_files():
  - Layer 1: pseudofile child entry cleanup
  - Layer 2: tarball directory entry removal
"""

import io
import os
import tarfile
import tempfile
import unittest

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'xendity.settings')
django.setup()

import yaml


class TestFixBrokenDeviceFiles(unittest.TestCase):
    """Tests for fix_broken_device_files() static method."""

    def _make_project(self, pseudo_content: dict, tarball_entries: list) -> str:
        """
        Create a minimal fake Penguin project directory.

        Args:
            pseudo_content: Dict to write as pseudofiles.dynamic.yaml
            tarball_entries: List of (name, is_dir) tuples to add to fs.tar.gz

        Returns:
            Path to temp project directory (caller must clean up)
        """
        tmpdir = tempfile.mkdtemp()
        patches_dir = os.path.join(tmpdir, 'static_patches')
        base_dir = os.path.join(tmpdir, 'base')
        os.makedirs(patches_dir)
        os.makedirs(base_dir)

        # Write pseudofiles.dynamic.yaml
        pseudo_path = os.path.join(patches_dir, 'pseudofiles.dynamic.yaml')
        with open(pseudo_path, 'w') as f:
            yaml.dump(pseudo_content, f)

        # Write base.yaml (minimal, no /dev/ entries)
        base_yaml_path = os.path.join(patches_dir, 'base.yaml')
        with open(base_yaml_path, 'w') as f:
            yaml.dump({'core': {'arch': 'armel'}}, f)

        # Write fs.tar.gz
        tarball_path = os.path.join(base_dir, 'fs.tar.gz')
        with tarfile.open(tarball_path, 'w:gz') as tar:
            for name, is_dir in tarball_entries:
                info = tarfile.TarInfo(name=name)
                if is_dir:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    tar.addfile(info)
                else:
                    data = b'content'
                    info.size = len(data)
                    info.mode = 0o644
                    tar.addfile(info, io.BytesIO(data))

        return tmpdir

    # -------------------------------------------------------------------------
    # Layer 1: pseudofile cleanup
    # -------------------------------------------------------------------------

    def test_removes_devnull_child_entries(self):
        """Child entries like /dev/null/utmp must be removed from pseudofiles."""
        from modules.xFormation.services.node_initialization_service import NodeInitializationService

        pseudo = {
            'pseudofiles': {
                '/dev/null/utmp': {'model': 'write'},
                '/dev/null/wtmp': {'model': 'write'},
                '/etc/hosts': {'model': 'read'},  # unrelated — must survive
            }
        }
        project = self._make_project(pseudo, [('./dev/', True)])
        try:
            result = NodeInitializationService.fix_broken_device_files(project)
            self.assertTrue(result)

            with open(os.path.join(project, 'static_patches/pseudofiles.dynamic.yaml')) as f:
                updated = yaml.safe_load(f)

            self.assertNotIn('/dev/null/utmp', updated['pseudofiles'])
            self.assertNotIn('/dev/null/wtmp', updated['pseudofiles'])
            self.assertIn('/etc/hosts', updated['pseudofiles'])
        finally:
            import shutil; shutil.rmtree(project)

    def test_removes_placeholder_entries(self):
        """Legacy .placeholder entries under device nodes must also be removed."""
        from modules.xFormation.services.node_initialization_service import NodeInitializationService

        pseudo = {
            'pseudofiles': {
                '/dev/null/.placeholder': {'model': 'write'},
                '/dev/zero/.placeholder': {'model': 'write'},
            }
        }
        project = self._make_project(pseudo, [('./dev/', True)])
        try:
            NodeInitializationService.fix_broken_device_files(project)

            with open(os.path.join(project, 'static_patches/pseudofiles.dynamic.yaml')) as f:
                updated = yaml.safe_load(f)

            self.assertNotIn('/dev/null/.placeholder', updated['pseudofiles'])
            self.assertNotIn('/dev/zero/.placeholder', updated['pseudofiles'])
        finally:
            import shutil; shutil.rmtree(project)

    def test_no_write_when_pseudofiles_clean(self):
        """If no device child entries exist, pseudofiles.dynamic.yaml must not be rewritten."""
        from modules.xFormation.services.node_initialization_service import NodeInitializationService

        pseudo = {
            'pseudofiles': {
                '/etc/hosts': {'model': 'read'},
            }
        }
        project = self._make_project(pseudo, [('./dev/', True)])
        pseudo_path = os.path.join(project, 'static_patches/pseudofiles.dynamic.yaml')
        try:
            mtime_before = os.path.getmtime(pseudo_path)
            NodeInitializationService.fix_broken_device_files(project)
            mtime_after = os.path.getmtime(pseudo_path)
            self.assertEqual(mtime_before, mtime_after)
        finally:
            import shutil; shutil.rmtree(project)

    # -------------------------------------------------------------------------
    # Layer 2: tarball repack
    # -------------------------------------------------------------------------

    def test_removes_devnull_directory_from_tarball(self):
        """If /dev/null is a directory in fs.tar.gz, it must be removed during repack."""
        from modules.xFormation.services.node_initialization_service import NodeInitializationService

        pseudo = {'pseudofiles': {}}
        project = self._make_project(pseudo, [
            ('./dev/', True),
            ('./dev/null', True),     # broken — device node as dir
            ('./etc/', True),
            ('./etc/hosts', False),
        ])
        try:
            NodeInitializationService.fix_broken_device_files(project)

            tarball_path = os.path.join(project, 'base/fs.tar.gz')
            with tarfile.open(tarball_path, 'r:gz') as tar:
                names = tar.getnames()

            self.assertNotIn('./dev/null', names)
            self.assertIn('./etc/hosts', names)   # unrelated content survives
        finally:
            import shutil; shutil.rmtree(project)

    def test_backup_created_when_tarball_repacked(self):
        """A .backup-* file must exist alongside fs.tar.gz after a repack."""
        from modules.xFormation.services.node_initialization_service import NodeInitializationService

        pseudo = {'pseudofiles': {}}
        project = self._make_project(pseudo, [
            ('./dev/', True),
            ('./dev/null', True),
        ])
        try:
            NodeInitializationService.fix_broken_device_files(project)

            base_dir = os.path.join(project, 'base')
            backups = [f for f in os.listdir(base_dir) if 'backup' in f]
            self.assertTrue(len(backups) > 0, "No backup file found after repack")
        finally:
            import shutil; shutil.rmtree(project)

    def test_no_repack_when_tarball_clean(self):
        """If no device node dirs are in the tarball, fs.tar.gz must not be rewritten."""
        from modules.xFormation.services.node_initialization_service import NodeInitializationService

        pseudo = {'pseudofiles': {}}
        project = self._make_project(pseudo, [
            ('./dev/', True),
            ('./etc/hosts', False),
        ])
        tarball_path = os.path.join(project, 'base/fs.tar.gz')
        try:
            mtime_before = os.path.getmtime(tarball_path)
            NodeInitializationService.fix_broken_device_files(project)
            mtime_after = os.path.getmtime(tarball_path)
            self.assertEqual(mtime_before, mtime_after)
        finally:
            import shutil; shutil.rmtree(project)

    # -------------------------------------------------------------------------
    # Dead code: base.yaml must NOT get /dev/ entries written into it
    # -------------------------------------------------------------------------

    def test_base_yaml_not_polluted_with_dev_entries(self):
        """fix_broken_device_files must not write any /dev/ entries into base.yaml."""
        from modules.xFormation.services.node_initialization_service import NodeInitializationService

        pseudo = {'pseudofiles': {}}
        project = self._make_project(pseudo, [('./dev/', True)])
        try:
            NodeInitializationService.fix_broken_device_files(project)

            with open(os.path.join(project, 'static_patches/base.yaml')) as f:
                base = yaml.safe_load(f)

            static_files = base.get('static_files', {})
            dev_keys = [k for k in static_files if k.startswith('/dev/')]
            self.assertEqual(dev_keys, [], f"Unexpected /dev/ entries in base.yaml: {dev_keys}")
        finally:
            import shutil; shutil.rmtree(project)


if __name__ == '__main__':
    unittest.main()
