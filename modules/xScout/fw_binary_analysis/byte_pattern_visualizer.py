import os
from typing import Dict, List, Any

class BytePatternVisualizer:
    """Module for byte pattern visualization (pixd equivalent)"""
    
    def visualize_patterns(self, file_path: str, bytes_to_read: int = 2000) -> Dict[str, Any]:
        """Generate byte pattern visualization"""
        # Get output directory
        firmware_name = os.path.splitext(os.path.basename(file_path))[0]
        output_dir = os.path.join(os.path.dirname(file_path), f"{firmware_name}_analysis")
        
        visualization = {
            'patterns_detected': [],
            'byte_distribution': {},
            'ascii_preview': '',
            'hex_preview': ''
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(bytes_to_read)
            
            if not data:
                return {'error': 'File is empty or unreadable'}
            
            # Byte distribution analysis
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Find most common bytes
            common_bytes = sorted(enumerate(byte_counts), key=lambda x: x[1], reverse=True)[:5]
            visualization['byte_distribution'] = {
                f'byte_{byte:02x}': count for byte, count in common_bytes if count > 0
            }
            
            # ASCII preview (printable characters only)
            ascii_chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[:200])
            visualization['ascii_preview'] = ascii_chars
            
            # Hex preview
            visualization['hex_preview'] = data[:64].hex()
            
            # Pattern detection
            visualization['patterns_detected'] = self._detect_byte_patterns(data)
            
            # Generate visualization file
            viz_file = os.path.join(output_dir, "byte_patterns.txt")
            self._generate_visualization_file(data, viz_file)
            visualization['visualization_file'] = viz_file
            
        except Exception as e:
            visualization['error'] = f"Visualization failed: {e}"
        
        return visualization
    
    def _detect_byte_patterns(self, data: bytes) -> List[str]:
        """Detect common byte patterns"""
        patterns = []
        
        # Check for common patterns
        if data[:4] == b'\x7fELF':
            patterns.append('ELF_header')
        elif data[:2] == b'MZ':
            patterns.append('PE_header')
        elif data[:4] == b'PK\x03\x04':
            patterns.append('ZIP_signature')
        elif data[:2] == b'\x1f\x8b':
            patterns.append('GZIP_signature')
        elif data.count(b'\x00') > len(data) * 0.9:
            patterns.append('mostly_zeros')
        elif data.count(b'\xff') > len(data) * 0.9:
            patterns.append('mostly_ones')
        
        return patterns
    
    def _generate_visualization_file(self, data: bytes, output_file: str):
        """Generate visualization file similar to pixd output"""
        try:
            with open(output_file, 'w') as f:
                f.write("Byte Pattern Visualization\n")
                f.write("=" * 40 + "\n\n")
                
                # Hex dump format
                for i in range(0, min(len(data), 512), 16):
                    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
                    f.write(f"{i:08x}: {hex_part:<48} |{ascii_part}|\n")
        except Exception:
            pass