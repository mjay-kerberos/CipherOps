"""
Image Analysis & Steganography Module for CTF Challenges
Analyzes images for hidden data, metadata, LSB steganography, and more
"""

import os
import re
import struct
import zlib
from collections import Counter

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class ImageAnalyzer:
    """Analyze images for steganography and hidden data"""

    def __init__(self):
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[A-Za-z0-9_]+\{[^}]+\}',
        ]

        self.file_signatures = {
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF87a': 'GIF87',
            b'GIF89a': 'GIF89',
            b'BM': 'BMP',
            b'RIFF': 'WEBP',
            b'II*\x00': 'TIFF_LE',
            b'MM\x00*': 'TIFF_BE',
        }

        self.results = {
            'metadata': {},
            'flags': [],
            'hidden_data': [],
            'anomalies': [],
            'embedded_files': [],
            'lsb_data': [],
        }

    def analyze(self, filepath):
        """Main entry point for image analysis"""
        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}

        print(f"[*] Analyzing image: {filepath}")
        self.results = {k: [] if isinstance(v, list) else {} for k, v in self.results.items()}

        # Read raw file data
        with open(filepath, 'rb') as f:
            raw_data = f.read()

        # Detect file type
        file_type = self._detect_file_type(raw_data)
        self.results['metadata']['detected_type'] = file_type
        self.results['metadata']['file_size'] = len(raw_data)

        # Run all analysis methods
        self._extract_strings(raw_data)
        self._check_file_structure(raw_data, file_type)
        self._analyze_metadata(filepath)
        self._check_appended_data(raw_data, file_type)
        self._search_embedded_files(raw_data)

        if PIL_AVAILABLE:
            self._analyze_with_pil(filepath)
            self._extract_lsb(filepath)
            self._analyze_color_planes(filepath)

        if file_type == 'PNG':
            self._analyze_png_chunks(raw_data)

        return self.results

    def _detect_file_type(self, data):
        """Detect file type from magic bytes"""
        for sig, ftype in self.file_signatures.items():
            if data.startswith(sig):
                return ftype
        return 'UNKNOWN'

    def _extract_strings(self, data):
        """Extract printable strings and search for flags"""
        # Find printable ASCII strings (min length 4)
        strings = re.findall(rb'[\x20-\x7e]{4,}', data)

        for s in strings:
            try:
                decoded = s.decode('utf-8')
                for pattern in self.flag_patterns:
                    matches = re.findall(pattern, decoded, re.IGNORECASE)
                    for match in matches:
                        if match not in self.results['flags']:
                            self.results['flags'].append(match)
            except:
                pass

        # Also search raw bytes for flag patterns
        try:
            text = data.decode('utf-8', errors='ignore')
            for pattern in self.flag_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if match not in self.results['flags']:
                        self.results['flags'].append(match)
        except:
            pass

    def _check_file_structure(self, data, file_type):
        """Check for structural anomalies"""
        if file_type == 'JPEG':
            # JPEG should end with FFD9
            if not data.rstrip(b'\x00').endswith(b'\xff\xd9'):
                self.results['anomalies'].append({
                    'type': 'jpeg_missing_eoi',
                    'description': 'JPEG missing End of Image marker'
                })

            # Check for multiple SOI markers (possible concatenated images)
            soi_count = data.count(b'\xff\xd8')
            if soi_count > 1:
                self.results['anomalies'].append({
                    'type': 'multiple_jpeg_soi',
                    'count': soi_count,
                    'description': f'Found {soi_count} JPEG Start of Image markers'
                })

        elif file_type == 'PNG':
            # PNG should end with IEND chunk
            if b'IEND' not in data:
                self.results['anomalies'].append({
                    'type': 'png_missing_iend',
                    'description': 'PNG missing IEND chunk'
                })

        elif file_type.startswith('GIF'):
            # GIF should end with 0x3B
            if not data.endswith(b'\x3b'):
                self.results['anomalies'].append({
                    'type': 'gif_missing_trailer',
                    'description': 'GIF missing trailer byte'
                })

    def _analyze_metadata(self, filepath):
        """Extract EXIF and other metadata"""
        if not PIL_AVAILABLE:
            return

        try:
            img = Image.open(filepath)
            self.results['metadata']['format'] = img.format
            self.results['metadata']['mode'] = img.mode
            self.results['metadata']['size'] = img.size

            # Get EXIF data
            if hasattr(img, '_getexif') and img._getexif():
                exif = img._getexif()
                exif_data = {}

                # Common EXIF tags
                exif_tags = {
                    271: 'Make', 272: 'Model', 274: 'Orientation',
                    306: 'DateTime', 315: 'Artist', 33432: 'Copyright',
                    37510: 'UserComment', 270: 'ImageDescription',
                }

                for tag_id, value in exif.items():
                    tag_name = exif_tags.get(tag_id, str(tag_id))
                    exif_data[tag_name] = str(value)

                    # Search for flags in EXIF
                    str_value = str(value)
                    for pattern in self.flag_patterns:
                        matches = re.findall(pattern, str_value, re.IGNORECASE)
                        self.results['flags'].extend(matches)

                self.results['metadata']['exif'] = exif_data

            # Check for comments
            if img.info:
                for key, value in img.info.items():
                    if isinstance(value, (str, bytes)):
                        str_val = value if isinstance(value, str) else value.decode('utf-8', errors='ignore')
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, str_val, re.IGNORECASE)
                            self.results['flags'].extend(matches)

                        if key in ['comment', 'Comment', 'description', 'Description']:
                            self.results['metadata'][key] = str_val

            img.close()
        except Exception as e:
            self.results['anomalies'].append({
                'type': 'metadata_error',
                'description': str(e)
            })

    def _check_appended_data(self, data, file_type):
        """Check for data appended after image end"""
        end_marker = None
        end_pos = None

        if file_type == 'JPEG':
            end_pos = data.rfind(b'\xff\xd9')
            if end_pos != -1:
                end_pos += 2

        elif file_type == 'PNG':
            # Find IEND chunk
            iend_pos = data.find(b'IEND')
            if iend_pos != -1:
                end_pos = iend_pos + 8  # IEND + CRC

        elif file_type.startswith('GIF'):
            end_pos = data.rfind(b'\x3b')
            if end_pos != -1:
                end_pos += 1

        if end_pos and end_pos < len(data):
            appended = data[end_pos:]
            if len(appended) > 0:
                self.results['hidden_data'].append({
                    'type': 'appended_data',
                    'offset': end_pos,
                    'size': len(appended),
                    'preview': appended[:200].hex(),
                    'ascii_preview': appended[:200].decode('utf-8', errors='ignore')
                })

                # Check for flags in appended data
                try:
                    text = appended.decode('utf-8', errors='ignore')
                    for pattern in self.flag_patterns:
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        self.results['flags'].extend(matches)
                except:
                    pass

    def _search_embedded_files(self, data):
        """Search for files embedded within the image"""
        # Common file signatures to look for
        signatures = {
            b'PK\x03\x04': ('ZIP', b'PK\x05\x06'),
            b'\x1f\x8b\x08': ('GZIP', None),
            b'Rar!\x1a\x07': ('RAR', None),
            b'7z\xbc\xaf\x27\x1c': ('7Z', None),
            b'%PDF': ('PDF', b'%%EOF'),
            b'\x89PNG': ('PNG', b'IEND'),
            b'\xff\xd8\xff': ('JPEG', b'\xff\xd9'),
        }

        for sig, (ftype, end_sig) in signatures.items():
            pos = 0
            while True:
                pos = data.find(sig, pos + 1)
                if pos == -1 or pos == 0:  # Skip if at start (that's the image itself)
                    break

                self.results['embedded_files'].append({
                    'type': ftype,
                    'offset': pos,
                    'description': f'{ftype} file signature found at offset {pos}'
                })

    def _analyze_png_chunks(self, data):
        """Analyze PNG chunks for hidden data"""
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            return

        pos = 8  # Skip PNG signature
        chunks = []

        while pos < len(data):
            try:
                length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
                chunk_data = data[pos+8:pos+8+length]
                crc = struct.unpack('>I', data[pos+8+length:pos+12+length])[0]

                chunks.append({
                    'type': chunk_type,
                    'length': length,
                    'offset': pos
                })

                # Check for non-standard chunks
                standard_chunks = ['IHDR', 'PLTE', 'IDAT', 'IEND', 'cHRM', 'gAMA',
                                   'iCCP', 'sBIT', 'sRGB', 'bKGD', 'hIST', 'tRNS',
                                   'pHYs', 'sPLT', 'tIME', 'iTXt', 'tEXt', 'zTXt']

                if chunk_type not in standard_chunks:
                    self.results['anomalies'].append({
                        'type': 'nonstandard_png_chunk',
                        'chunk': chunk_type,
                        'offset': pos,
                        'length': length
                    })

                # Check text chunks for flags
                if chunk_type in ['tEXt', 'iTXt', 'zTXt']:
                    try:
                        if chunk_type == 'zTXt':
                            # Compressed text
                            null_pos = chunk_data.find(b'\x00')
                            if null_pos != -1:
                                keyword = chunk_data[:null_pos].decode('latin-1')
                                compressed = chunk_data[null_pos+2:]  # Skip null and compression method
                                try:
                                    text = zlib.decompress(compressed).decode('utf-8', errors='ignore')
                                except:
                                    text = ''
                        else:
                            text = chunk_data.decode('utf-8', errors='ignore')

                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, text, re.IGNORECASE)
                            self.results['flags'].extend(matches)

                        self.results['hidden_data'].append({
                            'type': f'png_{chunk_type}',
                            'content': text[:500]
                        })
                    except:
                        pass

                pos += 12 + length

                if chunk_type == 'IEND':
                    break

            except:
                break

        self.results['metadata']['png_chunks'] = chunks

    def _analyze_with_pil(self, filepath):
        """Additional analysis using PIL"""
        try:
            img = Image.open(filepath)

            # Check for palette-based steganography
            if img.mode == 'P':
                palette = img.getpalette()
                if palette:
                    # Look for patterns in palette
                    palette_bytes = bytes(palette)
                    for pattern in self.flag_patterns:
                        text = palette_bytes.decode('utf-8', errors='ignore')
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        self.results['flags'].extend(matches)

            img.close()
        except:
            pass

    def _extract_lsb(self, filepath, bits=1):
        """Extract LSB (Least Significant Bit) steganography"""
        if not NUMPY_AVAILABLE:
            return

        try:
            img = Image.open(filepath)

            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')

            pixels = np.array(img)
            extracted_bits = []

            # Extract LSB from each color channel
            for row in pixels:
                for pixel in row:
                    for channel in pixel[:3]:  # RGB only
                        extracted_bits.append(channel & ((1 << bits) - 1))

            # Convert bits to bytes
            binary_str = ''.join(str(b) for b in extracted_bits)

            # Try to interpret as ASCII
            extracted_text = ''
            for i in range(0, len(binary_str) - 7, 8):
                byte = binary_str[i:i+8]
                try:
                    char_code = int(byte, 2)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        extracted_text += chr(char_code)
                    elif char_code == 0:
                        break  # Null terminator
                except:
                    pass

            if len(extracted_text) > 4:
                self.results['lsb_data'].append({
                    'bits': bits,
                    'method': 'sequential_rgb',
                    'preview': extracted_text[:500],
                    'length': len(extracted_text)
                })

                # Search for flags
                for pattern in self.flag_patterns:
                    matches = re.findall(pattern, extracted_text, re.IGNORECASE)
                    self.results['flags'].extend(matches)

            img.close()

        except Exception as e:
            self.results['anomalies'].append({
                'type': 'lsb_extraction_error',
                'description': str(e)
            })

    def _analyze_color_planes(self, filepath):
        """Analyze individual color planes for hidden data"""
        if not NUMPY_AVAILABLE:
            return

        try:
            img = Image.open(filepath)

            if img.mode != 'RGB':
                img = img.convert('RGB')

            pixels = np.array(img)

            # Check each color plane for anomalies
            for i, color in enumerate(['Red', 'Green', 'Blue']):
                plane = pixels[:, :, i]

                # Check for unusual patterns
                unique_values = len(np.unique(plane))
                mean_val = np.mean(plane)
                std_val = np.std(plane)

                # Very low unique values might indicate hidden data
                if unique_values < 10:
                    self.results['anomalies'].append({
                        'type': 'suspicious_color_plane',
                        'plane': color,
                        'unique_values': unique_values,
                        'description': f'{color} plane has very few unique values'
                    })

            img.close()

        except:
            pass

    def extract_lsb_advanced(self, filepath, channel='all', bit_plane=0):
        """Advanced LSB extraction with configurable parameters"""
        if not PIL_AVAILABLE or not NUMPY_AVAILABLE:
            return None

        try:
            img = Image.open(filepath)
            if img.mode != 'RGB':
                img = img.convert('RGB')

            pixels = np.array(img)
            extracted = []

            # Select channels
            if channel == 'all':
                channels = [0, 1, 2]
            elif channel == 'red':
                channels = [0]
            elif channel == 'green':
                channels = [1]
            elif channel == 'blue':
                channels = [2]
            else:
                channels = [int(channel)]

            # Extract specified bit plane
            for row in pixels:
                for pixel in row:
                    for ch in channels:
                        bit = (pixel[ch] >> bit_plane) & 1
                        extracted.append(bit)

            # Convert to bytes
            result = bytearray()
            for i in range(0, len(extracted) - 7, 8):
                byte_bits = extracted[i:i+8]
                byte_val = sum(b << (7-j) for j, b in enumerate(byte_bits))
                result.append(byte_val)

            img.close()
            return bytes(result)

        except:
            return None

    def zsteg_like_analysis(self, filepath):
        """Perform zsteg-like analysis trying multiple LSB configurations"""
        results = []

        configs = [
            ('1b,lsb,xy', {'bits': 1, 'order': 'xy'}),
            ('1b,msb,xy', {'bits': 1, 'order': 'xy', 'msb': True}),
            ('2b,lsb,xy', {'bits': 2, 'order': 'xy'}),
            ('r,lsb,xy', {'channel': 'red', 'bits': 1}),
            ('g,lsb,xy', {'channel': 'green', 'bits': 1}),
            ('b,lsb,xy', {'channel': 'blue', 'bits': 1}),
        ]

        for config_name, params in configs:
            data = self.extract_lsb_advanced(
                filepath,
                channel=params.get('channel', 'all'),
                bit_plane=0
            )

            if data:
                # Check for readable content
                try:
                    text = data.decode('utf-8', errors='ignore')
                    printable = ''.join(c for c in text if c.isprintable() or c in '\n\r\t')

                    if len(printable) > 10:
                        results.append({
                            'config': config_name,
                            'preview': printable[:200],
                            'flags': []
                        })

                        # Search for flags
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, printable, re.IGNORECASE)
                            if matches:
                                results[-1]['flags'].extend(matches)
                except:
                    pass

        return results

    def quick_analysis(self, filepath):
        """Quick analysis focusing on finding flags fast"""
        results = self.analyze(filepath)

        summary = {
            'flags_found': list(set(results.get('flags', []))),
            'hidden_data_count': len(results.get('hidden_data', [])),
            'anomalies_count': len(results.get('anomalies', [])),
            'embedded_files': results.get('embedded_files', []),
            'recommendation': []
        }

        if not summary['flags_found']:
            summary['recommendation'].append("No flags found directly. Try:")
            summary['recommendation'].append("  - Run zsteg on the image: zsteg <image>")
            summary['recommendation'].append("  - Check with steghide: steghide extract -sf <image>")
            summary['recommendation'].append("  - Try binwalk: binwalk -e <image>")
            summary['recommendation'].append("  - Check with exiftool: exiftool <image>")
            summary['recommendation'].append("  - Look at specific color planes")

        return summary


class SteganographyTools:
    """Collection of steganography extraction methods"""

    @staticmethod
    def extract_with_password(filepath, password, tool='steghide'):
        """Try to extract with password using external tools"""
        import subprocess

        if tool == 'steghide':
            cmd = ['steghide', 'extract', '-sf', filepath, '-p', password, '-f']
        elif tool == 'outguess':
            cmd = ['outguess', '-k', password, '-r', filepath, 'output.txt']
        else:
            return None

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout + result.stderr
        except:
            return None

    @staticmethod
    def try_common_passwords(filepath):
        """Try common CTF passwords"""
        common_passwords = [
            '', 'password', 'secret', 'flag', 'ctf', 'hidden',
            'steganography', 'stego', 'pass', '123456', 'admin'
        ]

        results = []
        for pwd in common_passwords:
            output = SteganographyTools.extract_with_password(filepath, pwd)
            if output and 'wrote extracted data' in output.lower():
                results.append({
                    'password': pwd,
                    'tool': 'steghide',
                    'output': output
                })

        return results


def main():
    """CLI interface for image analysis"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python image_analysis.py <image_file>")
        print("\nOptions:")
        print("  --quick      Quick analysis (flag hunting)")
        print("  --lsb        Focus on LSB extraction")
        print("  --zsteg      Run zsteg-like analysis")
        return

    analyzer = ImageAnalyzer()
    filepath = sys.argv[1]

    if '--quick' in sys.argv:
        results = analyzer.quick_analysis(filepath)
        print("\n=== Quick Analysis Results ===")
        if results['flags_found']:
            print(f"\n[+] FLAGS FOUND: {results['flags_found']}")
        if results['recommendation']:
            print("\n[*] Recommendations:")
            for rec in results['recommendation']:
                print(f"    {rec}")
    elif '--zsteg' in sys.argv:
        results = analyzer.zsteg_like_analysis(filepath)
        print("\n=== LSB Analysis Results ===")
        for r in results:
            print(f"\n[{r['config']}]")
            print(f"  Preview: {r['preview'][:100]}")
            if r['flags']:
                print(f"  FLAGS: {r['flags']}")
    else:
        results = analyzer.analyze(filepath)

        print("\n=== Analysis Results ===")
        print(f"\nMetadata: {results['metadata']}")

        if results['flags']:
            print(f"\n[+] FLAGS FOUND: {list(set(results['flags']))}")

        if results['hidden_data']:
            print(f"\n[+] HIDDEN DATA: {len(results['hidden_data'])} items")
            for hd in results['hidden_data']:
                print(f"    {hd}")

        if results['anomalies']:
            print(f"\n[!] ANOMALIES: {len(results['anomalies'])} found")
            for a in results['anomalies']:
                print(f"    {a}")

        if results['embedded_files']:
            print(f"\n[+] EMBEDDED FILES:")
            for ef in results['embedded_files']:
                print(f"    {ef}")


if __name__ == "__main__":
    main()
