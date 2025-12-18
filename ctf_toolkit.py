#!/usr/bin/env python3
"""
CTF Toolkit - Comprehensive CTF Challenge Analysis Suite
Combines crypto analysis, packet analysis, image/stego analysis, and forensics
"""

import os
import sys
import argparse
from datetime import datetime

# Import modules
try:
    from modules.packet_analysis import PacketAnalyzer, SCAPY_AVAILABLE
except ImportError:
    PacketAnalyzer = None
    SCAPY_AVAILABLE = False

try:
    from modules.image_analysis import ImageAnalyzer, PIL_AVAILABLE
except ImportError:
    ImageAnalyzer = None
    PIL_AVAILABLE = False

try:
    from modules.forensics import ForensicsAnalyzer, MemoryForensics, DiskForensics
except ImportError:
    ForensicsAnalyzer = None
    MemoryForensics = None
    DiskForensics = None

try:
    from modules.flag_finder import FlagFinder, FlagExtractor, hunt_flags
except ImportError:
    FlagFinder = None
    FlagExtractor = None
    hunt_flags = None

# Import the original crypto analyzer
try:
    from cipherOps import CryptoAnalyzer
except ImportError:
    CryptoAnalyzer = None


class CTFToolkit:
    """Main CTF Toolkit orchestrator"""

    def __init__(self, flag_format=None, verbose=True):
        self.flag_format = flag_format
        self.verbose = verbose
        self.results = {
            'flags': [],
            'analysis': {},
            'recommendations': [],
            'errors': [],
        }

        # Initialize analyzers
        self.crypto = CryptoAnalyzer() if CryptoAnalyzer else None
        self.packets = PacketAnalyzer() if PacketAnalyzer else None
        self.images = ImageAnalyzer() if ImageAnalyzer else None
        self.forensics = ForensicsAnalyzer() if ForensicsAnalyzer else None
        self.flag_finder = FlagFinder(flag_format) if FlagFinder else None

    def log(self, message, level='info'):
        """Log messages if verbose mode is on"""
        if self.verbose:
            prefix = {
                'info': '[*]',
                'success': '[+]',
                'warning': '[!]',
                'error': '[-]',
            }.get(level, '[*]')
            print(f"{prefix} {message}")

    def detect_file_type(self, filepath):
        """Detect file type from magic bytes and extension"""
        ext = os.path.splitext(filepath)[1].lower()

        # Read magic bytes
        try:
            with open(filepath, 'rb') as f:
                magic = f.read(16)
        except:
            return 'unknown'

        # Check magic bytes
        signatures = {
            b'\x89PNG': 'image',
            b'\xff\xd8\xff': 'image',
            b'GIF8': 'image',
            b'BM': 'image',
            b'RIFF': 'image',  # Could be WEBP
            b'\xd4\xc3\xb2\xa1': 'pcap',  # PCAP
            b'\xa1\xb2\xc3\xd4': 'pcap',  # PCAP (big endian)
            b'\x0a\x0d\x0d\x0a': 'pcapng',
            b'%PDF': 'document',
            b'PK\x03\x04': 'archive',
            b'\x1f\x8b': 'archive',
            b'Rar!': 'archive',
            b'7z\xbc\xaf': 'archive',
            b'\x7fELF': 'binary',
            b'MZ': 'binary',
            b'SQLite': 'database',
        }

        for sig, ftype in signatures.items():
            if magic.startswith(sig):
                return ftype

        # Fall back to extension
        ext_types = {
            '.pcap': 'pcap', '.pcapng': 'pcap', '.cap': 'pcap',
            '.png': 'image', '.jpg': 'image', '.jpeg': 'image',
            '.gif': 'image', '.bmp': 'image', '.webp': 'image',
            '.pdf': 'document', '.doc': 'document', '.docx': 'document',
            '.zip': 'archive', '.tar': 'archive', '.gz': 'archive',
            '.rar': 'archive', '.7z': 'archive',
            '.bin': 'binary', '.exe': 'binary', '.elf': 'binary',
            '.raw': 'forensics', '.img': 'forensics', '.dd': 'forensics',
            '.mem': 'memory', '.vmem': 'memory', '.dmp': 'memory',
            '.txt': 'text', '.json': 'text', '.xml': 'text',
            '.py': 'text', '.js': 'text', '.c': 'text', '.cpp': 'text',
        }

        return ext_types.get(ext, 'unknown')

    def analyze_auto(self, target):
        """Automatically detect and analyze target"""
        self.log(f"Auto-analyzing: {target}")

        if not os.path.exists(target):
            # Treat as encoded text
            self.log("Target is not a file, treating as encoded text")
            return self.analyze_crypto(target)

        if os.path.isdir(target):
            return self.analyze_directory(target)

        # Detect file type
        file_type = self.detect_file_type(target)
        self.log(f"Detected file type: {file_type}")

        # Route to appropriate analyzer
        if file_type == 'pcap':
            return self.analyze_pcap(target)
        elif file_type == 'image':
            return self.analyze_image(target)
        elif file_type in ['binary', 'forensics']:
            return self.analyze_forensics(target)
        elif file_type == 'memory':
            return self.analyze_memory(target)
        elif file_type == 'text':
            with open(target, 'r', errors='ignore') as f:
                content = f.read()
            return self.analyze_crypto(content)
        elif file_type == 'archive':
            return self.analyze_archive(target)
        else:
            # Generic analysis
            return self.analyze_generic(target)

    def analyze_pcap(self, filepath):
        """Analyze PCAP file"""
        self.log(f"Analyzing PCAP: {filepath}")

        if not self.packets:
            self.results['errors'].append("Packet analysis module not available")
            self.results['recommendations'].append("Install scapy: pip install scapy")
            return self.results

        try:
            pcap_results = self.packets.analyze_pcap(filepath)

            self.results['analysis']['pcap'] = pcap_results

            # Extract flags
            if pcap_results.get('flags'):
                self.results['flags'].extend(pcap_results['flags'])
                self.log(f"Found {len(pcap_results['flags'])} flags in PCAP", 'success')

            # Check credentials
            if pcap_results.get('credentials'):
                self.log(f"Found {len(pcap_results['credentials'])} credentials", 'success')

            # Check suspicious activity
            if pcap_results.get('suspicious'):
                self.log(f"Found {len(pcap_results['suspicious'])} suspicious items", 'warning')

        except Exception as e:
            self.results['errors'].append(f"PCAP analysis failed: {str(e)}")

        return self.results

    def analyze_image(self, filepath):
        """Analyze image for steganography"""
        self.log(f"Analyzing image: {filepath}")

        if not self.images:
            self.results['errors'].append("Image analysis module not available")
            self.results['recommendations'].append("Install Pillow: pip install Pillow")
            return self.results

        try:
            img_results = self.images.analyze(filepath)

            self.results['analysis']['image'] = img_results

            # Extract flags
            if img_results.get('flags'):
                self.results['flags'].extend(img_results['flags'])
                self.log(f"Found {len(img_results['flags'])} flags in image", 'success')

            # Check for hidden data
            if img_results.get('hidden_data'):
                self.log(f"Found {len(img_results['hidden_data'])} hidden data items", 'success')

            # Check for embedded files
            if img_results.get('embedded_files'):
                self.log(f"Found {len(img_results['embedded_files'])} embedded files", 'success')

            # Add recommendations if no flags found
            if not img_results.get('flags'):
                self.results['recommendations'].extend([
                    "Try: zsteg " + filepath,
                    "Try: steghide extract -sf " + filepath,
                    "Try: binwalk -e " + filepath,
                    "Try: exiftool " + filepath,
                    "Check individual color planes",
                ])

        except Exception as e:
            self.results['errors'].append(f"Image analysis failed: {str(e)}")

        return self.results

    def analyze_forensics(self, filepath):
        """Analyze file for forensics artifacts"""
        self.log(f"Analyzing for forensics: {filepath}")

        if not self.forensics:
            self.results['errors'].append("Forensics module not available")
            return self.results

        try:
            forensics_results = self.forensics.analyze_file(filepath)

            self.results['analysis']['forensics'] = forensics_results

            # Extract flags
            if forensics_results.get('flags'):
                self.results['flags'].extend(forensics_results['flags'])
                self.log(f"Found {len(forensics_results['flags'])} flags", 'success')

            # Check carved files
            if forensics_results.get('carved_files'):
                self.log(f"Found {len(forensics_results['carved_files'])} embeded files", 'success')
                self.results['recommendations'].append(
                    "Run with --carve to extract embedded files"
                )

        except Exception as e:
            self.results['errors'].append(f"Forensics analysis failed: {str(e)}")

        return self.results

    def analyze_memory(self, filepath):
        """Analyze memory dump"""
        self.log(f"Analyzing memory dump: {filepath}")

        if not MemoryForensics:
            self.results['errors'].append("Memory forensics not available")
            return self.results

        try:
            mem = MemoryForensics()
            mem_results = mem.analyze_memory_dump(filepath)

            self.results['analysis']['memory'] = mem_results

            if mem_results.get('flags'):
                self.results['flags'].extend(mem_results['flags'])
                self.log(f"Found {len(mem_results['flags'])} flags", 'success')

            self.results['recommendations'].append(
                "For deeper analysis, use Volatility: vol.py -f " + filepath
            )

        except Exception as e:
            self.results['errors'].append(f"Memory analysis failed: {str(e)}")

        return self.results

    def analyze_crypto(self, ciphertext):
        """Analyze encoded/encrypted text"""
        self.log("Analyzing crypto/encoding")

        results_list = []

        # Use original CryptoAnalyzer if available
        if self.crypto:
            try:
                crypto_results = self.crypto.analyze(ciphertext)
                results_list.extend(crypto_results)
                self.results['analysis']['crypto'] = crypto_results

                # Check for flags in decoded results
                for result in crypto_results:
                    decoded = result.get('decoded', '')
                    if decoded:
                        if self.flag_finder:
                            flags = self.flag_finder.find_in_string(str(decoded))
                            self.results['flags'].extend(flags)

            except Exception as e:
                self.results['errors'].append(f"Crypto analysis error: {str(e)}")

        # Also use flag finder's bruteforce decoder
        if self.flag_finder:
            try:
                flags = self.flag_finder.bruteforce_decode(ciphertext)
                self.results['flags'].extend(flags)
            except:
                pass

        return self.results

    def analyze_archive(self, filepath):
        """Analyze archive file"""
        self.log(f"Analyzing archive: {filepath}")

        self.results['recommendations'].extend([
            f"Extract archive: unzip/tar -xf {filepath}",
            "Check for password protection",
            "Look for hidden files in archive",
        ])

        # Basic flag search in archive
        if self.flag_finder:
            flags = self.flag_finder.find_in_file(filepath)
            self.results['flags'].extend(flags)

        return self.results

    def analyze_directory(self, directory):
        """Analyze all files in a directory"""
        self.log(f"Analyzing directory: {directory}")

        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    self.log(f"Processing: {filepath}")
                    self.analyze_auto(filepath)
                except Exception as e:
                    self.results['errors'].append(f"Error processing {filepath}: {str(e)}")

        return self.results

    def analyze_generic(self, filepath):
        """Generic file analysis"""
        self.log(f"Generic analysis: {filepath}")

        # Flag finder
        if self.flag_finder:
            flags = self.flag_finder.find_in_file(filepath)
            self.results['flags'].extend(flags)

        # Forensics analysis
        if self.forensics:
            try:
                forensics_results = self.forensics.analyze_file(filepath)
                self.results['analysis']['forensics'] = forensics_results

                if forensics_results.get('flags'):
                    self.results['flags'].extend(forensics_results['flags'])

            except:
                pass

        return self.results

    def hunt_flags_fast(self, target):
        """Quick flag hunting mode"""
        self.log("Fast flag hunting mode")

        if hunt_flags:
            return hunt_flags(target, self.flag_format, self.verbose)
        else:
            return self.analyze_auto(target)

    def get_summary(self):
        """Get analysis summary"""
        flags = list(set(self.results['flags']))

        summary = {
            'total_flags': len(flags),
            'flags': flags,
            'recommendations': self.results['recommendations'],
            'errors': self.results['errors'],
        }

        return summary

    def print_results(self):
        """Print formatted results"""
        print("\n" + "="*60)
        print("CTF TOOLKIT ANALYSIS RESULTS")
        print("="*60)

        flags = list(set(self.results['flags']))

        if flags:
            print(f"\n[+] FLAGS FOUND ({len(flags)}):")
            for flag in flags:
                print(f"    {flag}")
        else:
            print("\n[-] No flags found")

        if self.results['recommendations']:
            print(f"\n[*] RECOMMENDATIONS:")
            for rec in self.results['recommendations'][:10]:
                print(f"    - {rec}")

        if self.results['errors']:
            print(f"\n[!] ERRORS:")
            for err in self.results['errors']:
                print(f"    - {err}")

        print("\n" + "="*60)


def print_banner():
    """Print tool banner"""
    banner = """
   ____ _____ _____   _____           _ _    _ _
  / ___|_   _|  ___| |_   _|__   ___ | | | _(_) |_
 | |     | | | |_      | |/ _ \\ / _ \\| | |/ / | __|
 | |___  | | |  _|     | | (_) | (_) | |   <| | |_
  \\____| |_| |_|       |_|\\___/ \\___/|_|_|\\_\\_|\\__|

    Crypto | Packets | Images | Forensics | Flags
    """
    print(banner)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description='CTF Toolkit - Comprehensive CTF Challenge Analysis Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s challenge.pcap              # Analyze PCAP file
  %(prog)s image.png                   # Analyze image for stego
  %(prog)s --hunt challenge_dir/       # Hunt for flags in directory
  %(prog)s --crypto "ZmxhZ3toZWxsb30=" # Analyze encoded text
  %(prog)s --format "picoCTF{}" file   # Use custom flag format

Modules:
  crypto    - Encoding/cipher analysis (Base64, ROT, etc.)
  packets   - PCAP/network analysis
  images    - Steganography analysis
  forensics - File carving, strings, entropy
  flags     - Automated flag hunting
        """
    )

    parser.add_argument('target', nargs='?', help='Target file, directory, or text')
    parser.add_argument('--format', '-f', help='Custom flag format (e.g., "picoCTF{}")')
    parser.add_argument('--hunt', '-H', action='store_true', help='Fast flag hunting mode')
    parser.add_argument('--crypto', '-c', help='Analyze crypto/encoding directly')
    parser.add_argument('--carve', action='store_true', help='Carve embedded files')
    parser.add_argument('--output', '-o', help='Output directory for carved files')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--modules', '-m', action='store_true', help='List available modules')

    args = parser.parse_args()

    if args.modules:
        print("\nAvailable Modules:")
        print(f"  Crypto Analysis:   {'Available' if CryptoAnalyzer else 'Not loaded'}")
        print(f"  Packet Analysis:   {'Available' if PacketAnalyzer else 'Not loaded'} (scapy: {'Yes' if SCAPY_AVAILABLE else 'No'})")
        print(f"  Image Analysis:    {'Available' if ImageAnalyzer else 'Not loaded'} (PIL: {'Yes' if PIL_AVAILABLE else 'No'})")
        print(f"  Forensics:         {'Available' if ForensicsAnalyzer else 'Not loaded'}")
        print(f"  Flag Finder:       {'Available' if FlagFinder else 'Not loaded'}")
        return

    if not args.target and not args.crypto:
        print_banner()
        parser.print_help()
        return

    # Initialize toolkit
    toolkit = CTFToolkit(
        flag_format=args.format,
        verbose=not args.quiet
    )

    if not args.quiet:
        print_banner()

    # Route to appropriate analysis
    if args.crypto:
        toolkit.analyze_crypto(args.crypto)
    elif args.hunt:
        toolkit.hunt_flags_fast(args.target)
    elif args.carve and toolkit.forensics:
        output_dir = args.output or 'carved_files'
        count = toolkit.forensics.carve_files(args.target, output_dir)
        print(f"[+] Carved {count} files to {output_dir}")
    else:
        toolkit.analyze_auto(args.target)

    toolkit.print_results()


# Interactive menu
def interactive_menu():
    """Interactive menu for the toolkit"""
    toolkit = CTFToolkit()

    while True:
        print("\n" + "="*40)
        print("CTF Toolkit - Interactive Mode")
        print("="*40)
        print("1. Analyze file (auto-detect)")
        print("2. Analyze PCAP")
        print("3. Analyze image (steganography)")
        print("4. Analyze crypto/encoding")
        print("5. Hunt for flags")
        print("6. Carve files")
        print("7. Forensics analysis")
        print("8. Exit")
        print("="*40)

        choice = input("\nSelect option (1-8): ").strip()

        if choice == '8':
            print("Goodbye!")
            break

        if choice == '1':
            filepath = input("Enter file path: ").strip()
            toolkit.analyze_auto(filepath)
            toolkit.print_results()

        elif choice == '2':
            filepath = input("Enter PCAP file path: ").strip()
            toolkit.analyze_pcap(filepath)
            toolkit.print_results()

        elif choice == '3':
            filepath = input("Enter image file path: ").strip()
            toolkit.analyze_image(filepath)
            toolkit.print_results()

        elif choice == '4':
            text = input("Enter encoded text: ").strip()
            toolkit.analyze_crypto(text)
            toolkit.print_results()

        elif choice == '5':
            target = input("Enter target (file/directory/text): ").strip()
            toolkit.hunt_flags_fast(target)

        elif choice == '6':
            filepath = input("Enter file to carve: ").strip()
            output = input("Output directory [carved_files]: ").strip() or 'carved_files'
            if toolkit.forensics:
                count = toolkit.forensics.carve_files(filepath, output)
                print(f"[+] Carved {count} files")

        elif choice == '7':
            filepath = input("Enter file path: ").strip()
            toolkit.analyze_forensics(filepath)
            toolkit.print_results()

        # Reset results for next analysis
        toolkit.results = {
            'flags': [],
            'analysis': {},
            'recommendations': [],
            'errors': [],
        }


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments, run interactive mode
        print_banner()
        interactive_menu()
    else:
        main()
