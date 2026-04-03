import subprocess
from typing import Dict, List, Any, Optional

class FileFormatChecker:
    """Module for file format identification"""
    
    def __init__(self):
        self.results = {}
    
    def check_format(self, file_path: str) -> Dict[str, Any]:
        """
        Check file format using 'file' command
        Returns file type, MIME type, and additional info
        """
        try:
            # Run file command
            result = subprocess.run(['file', '-b', file_path], 
                                  capture_output=True, text=True, check=True)
            file_output = result.stdout.strip()
            
            # Run file with MIME type
            mime_result = subprocess.run(['file', '-b', '--mime-type', file_path], 
                                       capture_output=True, text=True, check=True)
            mime_type = mime_result.stdout.strip()
            
            # Parse file output for specific types
            format_info = {
                'raw_output': file_output,
                'mime_type': mime_type,
                'is_compressed': self._is_compressed(file_output),
                'is_encrypted': self._is_encrypted(file_output),
                'is_filesystem': self._is_filesystem(file_output),
                'is_executable': self._is_executable(file_output),
                'architecture': self._extract_architecture(file_output),
                'detected_formats': self._detect_specific_formats(file_output)
            }
            
            return format_info
            
        except subprocess.CalledProcessError as e:
            return {'error': f"File command failed: {e}"}
        except Exception as e:
            return {'error': f"Format check failed: {e}"}
    
    def _is_compressed(self, file_output: str) -> bool:
        """Check if file is compressed"""
        compressed_patterns = [
            'gzip compressed', 'bzip2 compressed', 'XZ compressed',
            'ZIP archive', '7-zip archive', 'POSIX tar archive'
        ]
        return any(pattern in file_output for pattern in compressed_patterns)
    
    def _is_encrypted(self, file_output: str) -> bool:
        """Check if file appears encrypted"""
        encrypted_patterns = [
            'encrypted', 'openssl enc', 'GPG encrypted'
        ]
        return any(pattern in file_output for pattern in encrypted_patterns)
    
    def _is_filesystem(self, file_output: str) -> bool:
        """Check if file is a filesystem image"""
        fs_patterns = [
            'filesystem', 'UBI image', 'ext2', 'ext3', 'ext4',
            'Unix Fast File system', 'CRAMFS', 'SquashFS'
        ]
        return any(pattern in file_output for pattern in fs_patterns)
    
    def _is_executable(self, file_output: str) -> bool:
        """Check if file is executable"""
        exec_patterns = ['ELF', 'PE32', 'Mach-O', 'executable']
        return any(pattern in file_output for pattern in exec_patterns)
    
    def _extract_architecture(self, file_output: str) -> Optional[str]:
        """Extract architecture information"""
        arch_patterns = {
            'ARM': ['ARM', 'arm'],
            'MIPS': ['MIPS', 'mips'],
            'x86': ['x86-64', 'Intel 80386', 'i386'],
            'PowerPC': ['PowerPC', 'ppc'],
        }
        
        for arch, patterns in arch_patterns.items():
            if any(pattern in file_output for pattern in patterns):
                return arch
        return None
    
    def _detect_specific_formats(self, file_output: str) -> List[str]:
        """Detect specific firmware formats"""
        formats = []
        file_output_lower = file_output.lower()
        format_patterns = {
            'u-boot': ['u-boot legacy uimage'],
            'UEFI': ['uefi'],
            'VMDK': ['vmware4 disk image'],
            'QCOW': ['qemu qcow'],
            'Android': ['android package'],
            'OpenSSL_encrypted': ['openssl enc\'d data with salted password'],
            'Windows_PE': ['pe32 executable', 'pe32+ executable', 'msi installer'],
            'ELF': ['elf'],
            'APK': ['android package (apk)'],
            'Script_Perl': ['perl script text executable'],
            'Script_PHP': ['php script'],
            'Script_Python': ['python script'],
            'Script_Shell': ['shell script', 'bash script', '/bin/bash', '/bin/sh', 'script, ascii text executable']
        }
        
        for fmt, patterns in format_patterns.items():
            if any(pattern in file_output_lower for pattern in patterns):
                formats.append(fmt)
        
        return formats