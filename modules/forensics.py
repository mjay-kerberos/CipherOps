"""
Forensics Utilities Module for CTF Challenges
File carving, memory analysis, disk forensics, and general forensics tools
"""

import os
import re
import struct
import mmap
import hashlib
from collections import defaultdict
from datetime import datetime


class ForensicsAnalyzer:
    """General forensics analysis tools for CTF challenges"""

    def __init__(self):
        self.flag_patterns = [
            rb'flag\{[^}]+\}',
            rb'FLAG\{[^}]+\}',
            rb'ctf\{[^}]+\}',
            rb'CTF\{[^}]+\}',
            rb'[A-Za-z0-9_]+\{[^}]+\}',
        ]

        # File signatures for carving
        self.file_signatures = {
            'PNG': {
                'header': b'\x89PNG\r\n\x1a\n',
                'footer': b'IEND\xaeB`\x82',
                'extension': '.png'
            },
            'JPEG': {
                'header': b'\xff\xd8\xff',
                'footer': b'\xff\xd9',
                'extension': '.jpg'
            },
            'GIF': {
                'header': b'GIF8',
                'footer': b'\x00;',
                'extension': '.gif'
            },
            'PDF': {
                'header': b'%PDF',
                'footer': b'%%EOF',
                'extension': '.pdf'
            },
            'ZIP': {
                'header': b'PK\x03\x04',
                'footer': b'PK\x05\x06',
                'extension': '.zip'
            },
            'RAR': {
                'header': b'Rar!\x1a\x07',
                'footer': None,
                'extension': '.rar'
            },
            '7Z': {
                'header': b"7z\xbc\xaf'\x1c",
                'footer': None,
                'extension': '.7z'
            },
            'GZIP': {
                'header': b'\x1f\x8b\x08',
                'footer': None,
                'extension': '.gz'
            },
            'ELF': {
                'header': b'\x7fELF',
                'footer': None,
                'extension': '.elf'
            },
            'PE': {
                'header': b'MZ',
                'footer': None,
                'extension': '.exe'
            },
            'SQLITE': {
                'header': b'SQLite format 3\x00',
                'footer': None,
                'extension': '.sqlite'
            },
            'OGG': {
                'header': b'OggS',
                'footer': None,
                'extension': '.ogg'
            },
            'MP3': {
                'header': b'\xff\xfb',
                'footer': None,
                'extension': '.mp3'
            },
            'WAV': {
                'header': b'RIFF',
                'footer': None,
                'extension': '.wav'
            },
            'AVI': {
                'header': b'RIFF',
                'footer': None,
                'extension': '.avi'
            },
            'MP4': {
                'header': b'\x00\x00\x00\x18ftyp',
                'footer': None,
                'extension': '.mp4'
            },
            'BZ2': {
                'header': b'BZh',
                'footer': None,
                'extension': '.bz2'
            },
            'TAR': {
                'header': b'ustar',
                'footer': None,
                'extension': '.tar'
            },
        }

        self.results = {
            'flags': [],
            'carved_files': [],
            'strings': [],
            'hashes': {},
            'anomalies': [],
            'metadata': {},
        }

    def analyze_file(self, filepath):
        """Main entry point for file forensics"""
        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}

        self.results = {k: [] if isinstance(v, list) else {} for k, v in self.results.items()}

        print(f"[*] Analyzing file: {filepath}")

        with open(filepath, 'rb') as f:
            data = f.read()

        # Basic file info
        self.results['metadata'] = {
            'filename': os.path.basename(filepath),
            'size': len(data),
            'file_type': self._identify_file_type(data),
        }

        # Calculate hashes
        self._calculate_hashes(data)

        # Search for flags
        self._search_flags(data)

        # Extract strings
        self._extract_strings(data)

        # Find embedded files
        self._find_embedded_files(data)

        # Analyze entropy
        self._analyze_entropy(data)

        return self.results

    def _identify_file_type(self, data):
        """Identify file type from magic bytes"""
        for ftype, info in self.file_signatures.items():
            if data.startswith(info['header']):
                return ftype

        # Additional checks
        if data[:4] == b'\x00\x00\x00':
            return 'POSSIBLE_VIDEO'

        return 'UNKNOWN'

    def _calculate_hashes(self, data):
        """Calculate various hashes"""
        self.results['hashes'] = {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }

    def _search_flags(self, data):
        """Search for CTF flags"""
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, data)
            for match in matches:
                try:
                    decoded = match.decode('utf-8')
                    if decoded not in self.results['flags']:
                        self.results['flags'].append(decoded)
                except:
                    self.results['flags'].append(match.hex())

    def _extract_strings(self, data, min_length=4):
        """Extract printable strings"""
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        ascii_strings = re.findall(ascii_pattern, data)

        # Unicode strings (UTF-16LE)
        unicode_strings = []
        i = 0
        while i < len(data) - 1:
            if data[i] != 0 and data[i+1] == 0:
                start = i
                chars = []
                while i < len(data) - 1 and data[i] != 0 and data[i+1] == 0:
                    chars.append(chr(data[i]))
                    i += 2
                if len(chars) >= min_length:
                    unicode_strings.append(''.join(chars))
            else:
                i += 1

        # Deduplicate and store
        seen = set()
        for s in ascii_strings:
            decoded = s.decode('utf-8', errors='ignore')
            if decoded not in seen and len(decoded) >= min_length:
                seen.add(decoded)
                self.results['strings'].append({
                    'type': 'ascii',
                    'value': decoded
                })

        for s in unicode_strings:
            if s not in seen:
                seen.add(s)
                self.results['strings'].append({
                    'type': 'unicode',
                    'value': s
                })

    def _find_embedded_files(self, data):
        """Find files embedded within the data"""
        for ftype, info in self.file_signatures.items():
            header = info['header']
            footer = info['footer']

            pos = 0
            while True:
                start = data.find(header, pos)
                if start == -1:
                    break

                if footer:
                    end = data.find(footer, start)
                    if end != -1:
                        end += len(footer)
                    else:
                        end = min(start + 100000, len(data))
                else:
                    end = min(start + 100000, len(data))

                self.results['carved_files'].append({
                    'type': ftype,
                    'offset': start,
                    'size': end - start,
                    'extension': info['extension']
                })

                pos = start + 1

    def _analyze_entropy(self, data, block_size=256):
        """Analyze entropy to detect encrypted/compressed sections"""
        import math

        def calculate_entropy(block):
            if len(block) == 0:
                return 0
            freq = defaultdict(int)
            for byte in block:
                freq[byte] += 1
            entropy = 0
            for count in freq.values():
                p = count / len(block)
                entropy -= p * math.log2(p)
            return entropy

        # Overall entropy
        overall_entropy = calculate_entropy(data)
        self.results['metadata']['entropy'] = overall_entropy

        # High entropy suggests encryption/compression
        if overall_entropy > 7.5:
            self.results['anomalies'].append({
                'type': 'high_entropy',
                'value': overall_entropy,
                'description': 'File appears to be encrypted or compressed'
            })

        # Look for entropy anomalies (sudden changes)
        entropies = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if len(block) > 0:
                entropies.append(calculate_entropy(block))

        # Find sudden entropy changes
        for i in range(1, len(entropies)):
            if abs(entropies[i] - entropies[i-1]) > 3:
                self.results['anomalies'].append({
                    'type': 'entropy_change',
                    'offset': i * block_size,
                    'description': f'Sudden entropy change at offset {i * block_size}'
                })

    def carve_files(self, filepath, output_dir='carved'):
        """Carve embedded files from a binary"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(filepath, 'rb') as f:
            data = f.read()

        carved_count = 0
        for ftype, info in self.file_signatures.items():
            header = info['header']
            footer = info['footer']

            pos = 0
            while True:
                start = data.find(header, pos)
                if start == -1:
                    break

                if footer:
                    end = data.find(footer, start)
                    if end != -1:
                        end += len(footer)
                    else:
                        end = min(start + 100000, len(data))
                else:
                    end = min(start + 100000, len(data))

                # Save carved file
                carved_data = data[start:end]
                output_path = f"{output_dir}/carved_{carved_count}{info['extension']}"

                with open(output_path, 'wb') as out:
                    out.write(carved_data)

                print(f"[+] Carved {ftype} to {output_path} ({len(carved_data)} bytes)")
                carved_count += 1

                pos = start + 1

        return carved_count

    def analyze_strings_deep(self, filepath, context=50):
        """Deep string analysis with context"""
        results = []

        with open(filepath, 'rb') as f:
            data = f.read()

        # Interesting patterns
        patterns = {
            'url': rb'https?://[^\s<>"]+',
            'email': rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ip_address': rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'base64': rb'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
            'hex_string': rb'(?:0x)?[0-9a-fA-F]{16,}',
            'path_unix': rb'/(?:usr|home|var|etc|tmp|opt)/[^\s\x00]+',
            'path_windows': rb'[A-Za-z]:\\[^\s\x00]+',
            'password_field': rb'(?:password|passwd|pwd|pass)[=:]\s*[^\s]+',
            'private_key': rb'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            'jwt': rb'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        }

        for pattern_name, pattern in patterns.items():
            matches = list(re.finditer(pattern, data))
            for match in matches:
                start = max(0, match.start() - context)
                end = min(len(data), match.end() + context)

                results.append({
                    'type': pattern_name,
                    'match': match.group().decode('utf-8', errors='ignore'),
                    'offset': match.start(),
                    'context': data[start:end].decode('utf-8', errors='ignore')
                })

        return results

    def hex_dump(self, filepath, offset=0, length=256):
        """Generate hex dump of file section"""
        with open(filepath, 'rb') as f:
            f.seek(offset)
            data = f.read(length)

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f'{offset + i:08x}  {hex_part:<48}  {ascii_part}')

        return '\n'.join(lines)

    def diff_files(self, file1, file2):
        """Compare two files and find differences"""
        with open(file1, 'rb') as f:
            data1 = f.read()
        with open(file2, 'rb') as f:
            data2 = f.read()

        differences = []
        min_len = min(len(data1), len(data2))

        for i in range(min_len):
            if data1[i] != data2[i]:
                differences.append({
                    'offset': i,
                    'file1': data1[i],
                    'file2': data2[i]
                })

        result = {
            'file1_size': len(data1),
            'file2_size': len(data2),
            'size_diff': len(data1) - len(data2),
            'byte_differences': len(differences),
            'first_10_diffs': differences[:10]
        }

        # XOR the differences to find potential key
        if differences:
            xor_values = [d['file1'] ^ d['file2'] for d in differences[:100]]
            if len(set(xor_values)) == 1:
                result['possible_xor_key'] = xor_values[0]

        return result


class MemoryForensics:
    """Basic memory dump analysis"""

    def __init__(self):
        self.flag_patterns = [
            rb'flag\{[^}]+\}',
            rb'FLAG\{[^}]+\}',
            rb'ctf\{[^}]+\}',
            rb'CTF\{[^}]+\}',
        ]

    def analyze_memory_dump(self, filepath):
        """Analyze a memory dump file"""
        results = {
            'flags': [],
            'urls': [],
            'emails': [],
            'passwords': [],
            'processes': [],
        }

        with open(filepath, 'rb') as f:
            # Use mmap for large files
            try:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                data = mm
            except:
                data = f.read()

        # Search for flags
        for pattern in self.flag_patterns:
            for match in re.finditer(pattern, data):
                flag = match.group().decode('utf-8', errors='ignore')
                if flag not in results['flags']:
                    results['flags'].append(flag)

        # Search for URLs
        url_pattern = rb'https?://[^\s<>"\']+[^\s<>"\'\.]'
        for match in re.finditer(url_pattern, data):
            url = match.group().decode('utf-8', errors='ignore')
            if url not in results['urls']:
                results['urls'].append(url)

        # Search for email addresses
        email_pattern = rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        for match in re.finditer(email_pattern, data):
            email = match.group().decode('utf-8', errors='ignore')
            if email not in results['emails']:
                results['emails'].append(email)

        # Search for password patterns
        pwd_patterns = [
            rb'password[=:]\s*([^\s&]+)',
            rb'passwd[=:]\s*([^\s&]+)',
            rb'pwd[=:]\s*([^\s&]+)',
        ]
        for pattern in pwd_patterns:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                pwd = match.group().decode('utf-8', errors='ignore')
                if pwd not in results['passwords']:
                    results['passwords'].append(pwd)

        if hasattr(data, 'close'):
            data.close()

        return results


class DiskForensics:
    """Basic disk image analysis"""

    def __init__(self):
        self.partition_types = {
            0x00: 'Empty',
            0x01: 'FAT12',
            0x04: 'FAT16 <32M',
            0x05: 'Extended',
            0x06: 'FAT16',
            0x07: 'NTFS/exFAT',
            0x0b: 'FAT32 CHS',
            0x0c: 'FAT32 LBA',
            0x0e: 'FAT16 LBA',
            0x0f: 'Extended LBA',
            0x11: 'Hidden FAT12',
            0x14: 'Hidden FAT16 <32M',
            0x16: 'Hidden FAT16',
            0x17: 'Hidden NTFS',
            0x1b: 'Hidden FAT32',
            0x1c: 'Hidden FAT32 LBA',
            0x1e: 'Hidden FAT16 LBA',
            0x82: 'Linux swap',
            0x83: 'Linux',
            0x85: 'Linux extended',
            0x8e: 'Linux LVM',
        }

    def analyze_mbr(self, filepath):
        """Analyze Master Boot Record"""
        with open(filepath, 'rb') as f:
            mbr = f.read(512)

        if len(mbr) < 512:
            return {'error': 'File too small for MBR'}

        # Check MBR signature
        signature = struct.unpack('<H', mbr[510:512])[0]
        if signature != 0xAA55:
            return {'error': 'Invalid MBR signature'}

        partitions = []
        for i in range(4):
            offset = 446 + (i * 16)
            entry = mbr[offset:offset+16]

            boot_flag = entry[0]
            part_type = entry[4]
            start_lba = struct.unpack('<I', entry[8:12])[0]
            size_sectors = struct.unpack('<I', entry[12:16])[0]

            if part_type != 0:
                partitions.append({
                    'number': i + 1,
                    'bootable': boot_flag == 0x80,
                    'type': self.partition_types.get(part_type, f'Unknown (0x{part_type:02x})'),
                    'type_id': part_type,
                    'start_lba': start_lba,
                    'size_sectors': size_sectors,
                    'size_bytes': size_sectors * 512
                })

        return {
            'signature_valid': True,
            'partitions': partitions
        }

    def extract_deleted_files(self, filepath, output_dir='recovered'):
        """Attempt to recover deleted files from disk image"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Use file carving
        forensics = ForensicsAnalyzer()
        return forensics.carve_files(filepath, output_dir)


def quick_forensics(filepath):
    """Quick forensics analysis"""
    analyzer = ForensicsAnalyzer()
    results = analyzer.analyze_file(filepath)

    summary = {
        'file_type': results['metadata'].get('file_type', 'UNKNOWN'),
        'size': results['metadata'].get('size', 0),
        'entropy': results['metadata'].get('entropy', 0),
        'md5': results['hashes'].get('md5', ''),
        'flags_found': results.get('flags', []),
        'embedded_files': len(results.get('carved_files', [])),
        'anomalies': results.get('anomalies', []),
    }

    return summary


def main():
    """CLI interface for forensics analysis"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python forensics.py <file>")
        print("\nOptions:")
        print("  --carve <output_dir>   Carve embedded files")
        print("  --strings              Deep string analysis")
        print("  --hex <offset> <len>   Hex dump")
        print("  --mbr                  Analyze MBR (disk images)")
        print("  --memory               Memory dump analysis")
        return

    filepath = sys.argv[1]

    if '--carve' in sys.argv:
        idx = sys.argv.index('--carve')
        output_dir = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else 'carved'
        analyzer = ForensicsAnalyzer()
        count = analyzer.carve_files(filepath, output_dir)
        print(f"[+] Carved {count} files to {output_dir}")

    elif '--strings' in sys.argv:
        analyzer = ForensicsAnalyzer()
        results = analyzer.analyze_strings_deep(filepath)
        print("\n=== Deep String Analysis ===")
        for r in results[:50]:
            print(f"\n[{r['type']}] {r['match']}")
            print(f"  Offset: {r['offset']}")

    elif '--hex' in sys.argv:
        idx = sys.argv.index('--hex')
        offset = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 0
        length = int(sys.argv[idx + 2]) if idx + 2 < len(sys.argv) else 256
        analyzer = ForensicsAnalyzer()
        print(analyzer.hex_dump(filepath, offset, length))

    elif '--mbr' in sys.argv:
        disk = DiskForensics()
        results = disk.analyze_mbr(filepath)
        print("\n=== MBR Analysis ===")
        if 'error' in results:
            print(f"Error: {results['error']}")
        else:
            print(f"Signature valid: {results['signature_valid']}")
            for part in results['partitions']:
                print(f"\nPartition {part['number']}:")
                print(f"  Type: {part['type']}")
                print(f"  Bootable: {part['bootable']}")
                print(f"  Start: {part['start_lba']}")
                print(f"  Size: {part['size_bytes']} bytes")

    elif '--memory' in sys.argv:
        mem = MemoryForensics()
        results = mem.analyze_memory_dump(filepath)
        print("\n=== Memory Dump Analysis ===")
        if results['flags']:
            print(f"\n[+] FLAGS: {results['flags']}")
        if results['urls']:
            print(f"\n[+] URLs: {results['urls'][:10]}")
        if results['emails']:
            print(f"\n[+] Emails: {results['emails'][:10]}")
        if results['passwords']:
            print(f"\n[+] Passwords: {results['passwords'][:10]}")

    else:
        results = quick_forensics(filepath)
        print("\n=== Quick Forensics Analysis ===")
        print(f"File type: {results['file_type']}")
        print(f"Size: {results['size']} bytes")
        print(f"Entropy: {results['entropy']:.2f}")
        print(f"MD5: {results['md5']}")

        if results['flags_found']:
            print(f"\n[+] FLAGS FOUND: {results['flags_found']}")

        if results['embedded_files'] > 0:
            print(f"\n[+] Embedded files detected: {results['embedded_files']}")

        if results['anomalies']:
            print(f"\n[!] Anomalies:")
            for a in results['anomalies']:
                print(f"    {a['type']}: {a['description']}")


if __name__ == "__main__":
    main()
