"""
Flag Finder Module for CTF Challenges
Automatically searches for flags using multiple methods and patterns
"""

import os
import re
import base64
import binascii
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


class FlagFinder:
    """Automated flag finder for CTF challenges"""

    def __init__(self, flag_format=None):
        """
        Initialize with optional custom flag format
        flag_format: e.g., "flag{}", "CTF{}", "picoCTF{}", etc.
        """
        self.custom_format = flag_format

        # Common CTF flag patterns
        self.flag_patterns = [
            # Standard formats
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',

            # Competition-specific
            r'picoCTF\{[^}]+\}',
            r'pico\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'hackthebox\{[^}]+\}',
            r'CSAW\{[^}]+\}',
            r'DEFCON\{[^}]+\}',
            r'HITCON\{[^}]+\}',
            r'SECCON\{[^}]+\}',
            r'DragonCTF\{[^}]+\}',
            r'Google\{[^}]+\}',
            r'ASIS\{[^}]+\}',
            r'RCTF\{[^}]+\}',
            r'TJCTF\{[^}]+\}',
            r'UIUCTF\{[^}]+\}',
            r'redpwnCTF\{[^}]+\}',
            r'lactf\{[^}]+\}',

            # Generic pattern
            r'[A-Za-z0-9_]+\{[A-Za-z0-9_!@#$%^&*()+=\-.,<>?/\[\]]+\}',
        ]

        if flag_format:
            # Convert format like "flag{}" to regex
            prefix = flag_format.split('{')[0]
            pattern = re.escape(prefix) + r'\{[^}]+\}'
            self.flag_patterns.insert(0, pattern)

        self.results = {
            'flags': [],
            'possible_flags': [],
            'encoded_flags': [],
            'locations': [],
        }

    def find_in_file(self, filepath):
        """Search for flags in a single file"""
        if not os.path.exists(filepath):
            return []

        found_flags = []

        # Read file
        try:
            with open(filepath, 'rb') as f:
                raw_data = f.read()
        except:
            return []

        # Search in raw bytes
        for pattern in self.flag_patterns:
            try:
                matches = re.findall(pattern.encode(), raw_data, re.IGNORECASE)
                for match in matches:
                    flag = match.decode('utf-8', errors='ignore')
                    if flag not in found_flags:
                        found_flags.append(flag)
                        self.results['locations'].append({
                            'flag': flag,
                            'file': filepath,
                            'method': 'direct_search'
                        })
            except:
                pass

        # Try decoding as text
        try:
            text = raw_data.decode('utf-8', errors='ignore')
            for pattern in self.flag_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if match not in found_flags:
                        found_flags.append(match)
        except:
            pass

        # Try common decodings
        found_flags.extend(self._try_decodings(raw_data, filepath))

        return found_flags

    def _try_decodings(self, data, source='unknown'):
        """Try various decodings to find hidden flags"""
        found = []

        # Try as text
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = ''

        # Base64 decode
        try:
            # Look for base64 strings
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            b64_matches = re.findall(b64_pattern, text)

            for b64 in b64_matches:
                try:
                    decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                    for pattern in self.flag_patterns:
                        matches = re.findall(pattern, decoded, re.IGNORECASE)
                        for match in matches:
                            if match not in found:
                                found.append(match)
                                self.results['encoded_flags'].append({
                                    'flag': match,
                                    'encoding': 'base64',
                                    'original': b64[:50],
                                    'source': source
                                })
                except:
                    pass
        except:
            pass

        # Hex decode
        try:
            hex_pattern = r'[0-9a-fA-F]{20,}'
            hex_matches = re.findall(hex_pattern, text)

            for h in hex_matches:
                try:
                    if len(h) % 2 == 0:
                        decoded = bytes.fromhex(h).decode('utf-8', errors='ignore')
                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, decoded, re.IGNORECASE)
                            for match in matches:
                                if match not in found:
                                    found.append(match)
                                    self.results['encoded_flags'].append({
                                        'flag': match,
                                        'encoding': 'hex',
                                        'original': h[:50],
                                        'source': source
                                    })
                except:
                    pass
        except:
            pass

        # ROT13
        try:
            import codecs
            rot13 = codecs.decode(text, 'rot_13')
            for pattern in self.flag_patterns:
                matches = re.findall(pattern, rot13, re.IGNORECASE)
                for match in matches:
                    if match not in found:
                        found.append(match)
                        self.results['encoded_flags'].append({
                            'flag': match,
                            'encoding': 'rot13',
                            'source': source
                        })
        except:
            pass

        # Binary to ASCII
        try:
            binary_pattern = r'[01]{8,}'
            binary_matches = re.findall(binary_pattern, text)

            for b in binary_matches:
                if len(b) >= 40:  # At least 5 characters
                    try:
                        decoded = ''
                        for i in range(0, len(b) - 7, 8):
                            byte = b[i:i+8]
                            decoded += chr(int(byte, 2))

                        for pattern in self.flag_patterns:
                            matches = re.findall(pattern, decoded, re.IGNORECASE)
                            for match in matches:
                                if match not in found:
                                    found.append(match)
                                    self.results['encoded_flags'].append({
                                        'flag': match,
                                        'encoding': 'binary',
                                        'source': source
                                    })
                    except:
                        pass
        except:
            pass

        return found

    def find_in_directory(self, directory, recursive=True):
        """Search for flags in all files in a directory"""
        all_flags = []

        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    flags = self.find_in_file(filepath)
                    all_flags.extend(flags)
                except:
                    pass

            if not recursive:
                break

        return list(set(all_flags))

    def find_in_string(self, text):
        """Search for flags in a text string"""
        found = []

        # Direct search
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            found.extend(matches)

        # Try decodings
        found.extend(self._try_decodings(text.encode(), 'string_input'))

        return list(set(found))

    def find_in_output(self, command, timeout=30):
        """Run a command and search for flags in output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout + result.stderr
            return self.find_in_string(output)
        except:
            return []

    def bruteforce_decode(self, encoded_text, max_depth=3):
        """Try multiple decoding combinations"""
        found = []
        queue = [(encoded_text, [], 0)]

        decoders = {
            'base64': lambda x: base64.b64decode(x).decode('utf-8', errors='ignore'),
            'base32': lambda x: base64.b32decode(x).decode('utf-8', errors='ignore'),
            'hex': lambda x: bytes.fromhex(x).decode('utf-8', errors='ignore'),
            'rot13': lambda x: __import__('codecs').decode(x, 'rot_13'),
            'reverse': lambda x: x[::-1],
            'url': lambda x: __import__('urllib.parse').parse.unquote(x),
        }

        while queue:
            current, path, depth = queue.pop(0)

            if depth > max_depth:
                continue

            # Check for flags
            for pattern in self.flag_patterns:
                matches = re.findall(pattern, current, re.IGNORECASE)
                for match in matches:
                    if match not in found:
                        found.append(match)
                        self.results['encoded_flags'].append({
                            'flag': match,
                            'encoding_chain': ' -> '.join(path) if path else 'plain',
                            'source': 'bruteforce'
                        })

            # Try each decoder
            for decoder_name, decoder_func in decoders.items():
                try:
                    decoded = decoder_func(current)
                    if decoded and decoded != current:
                        queue.append((decoded, path + [decoder_name], depth + 1))
                except:
                    pass

        return found

    def validate_flag(self, flag, flag_format=None):
        """Validate if a string matches expected flag format"""
        fmt = flag_format or self.custom_format

        if fmt:
            prefix = fmt.split('{')[0]
            if not flag.startswith(prefix + '{'):
                return False
            if not flag.endswith('}'):
                return False

        # Check for common flag characteristics
        if '{' not in flag or '}' not in flag:
            return False

        # Check content between braces
        content = flag[flag.index('{')+1:flag.rindex('}')]
        if len(content) < 1:
            return False

        return True

    def score_flag(self, flag):
        """Score how likely a string is to be a real flag"""
        score = 0

        # Has proper format
        if '{' in flag and '}' in flag:
            score += 10

        # Common prefixes
        common_prefixes = ['flag', 'ctf', 'pico', 'htb', 'hack']
        for prefix in common_prefixes:
            if flag.lower().startswith(prefix):
                score += 20
                break

        # Content characteristics
        content = ''
        if '{' in flag and '}' in flag:
            content = flag[flag.index('{')+1:flag.rindex('}')]

        # Reasonable length
        if 5 <= len(content) <= 100:
            score += 10

        # Contains underscores (common in flags)
        if '_' in content:
            score += 5

        # Contains mix of chars
        if any(c.isdigit() for c in content) and any(c.isalpha() for c in content):
            score += 5

        # Looks like l33t speak or readable
        if re.search(r'[a-zA-Z]{3,}', content):
            score += 10

        return score

    def comprehensive_search(self, target, parallel=True):
        """
        Comprehensive search for flags
        target can be: file path, directory path, or raw text
        """
        all_flags = []

        if os.path.isfile(target):
            all_flags = self.find_in_file(target)
        elif os.path.isdir(target):
            all_flags = self.find_in_directory(target)
        else:
            # Treat as text
            all_flags = self.find_in_string(target)
            all_flags.extend(self.bruteforce_decode(target))

        # Score and sort flags
        scored_flags = [(flag, self.score_flag(flag)) for flag in set(all_flags)]
        scored_flags.sort(key=lambda x: x[1], reverse=True)

        self.results['flags'] = [f for f, s in scored_flags if s >= 30]
        self.results['possible_flags'] = [f for f, s in scored_flags if 10 <= s < 30]

        return self.results

    def get_summary(self):
        """Get a summary of found flags"""
        summary = {
            'total_flags': len(self.results['flags']),
            'possible_flags': len(self.results['possible_flags']),
            'encoded_flags': len(self.results['encoded_flags']),
            'flags': self.results['flags'],
            'all_findings': self.results
        }

        return summary


class FlagExtractor:
    """Extract flags from various CTF challenge types"""

    def __init__(self, flag_format=None):
        self.finder = FlagFinder(flag_format)

    def from_pcap(self, filepath):
        """Extract flags from PCAP file"""
        try:
            from .packet_analysis import PacketAnalyzer
            analyzer = PacketAnalyzer()
            results = analyzer.analyze_pcap(filepath)
            return results.get('flags', [])
        except ImportError:
            # Fallback to basic search
            return self.finder.find_in_file(filepath)

    def from_image(self, filepath):
        """Extract flags from image file"""
        try:
            from .image_analysis import ImageAnalyzer
            analyzer = ImageAnalyzer()
            results = analyzer.analyze(filepath)
            return results.get('flags', [])
        except ImportError:
            return self.finder.find_in_file(filepath)

    def from_binary(self, filepath):
        """Extract flags from binary/forensics file"""
        try:
            from .forensics import ForensicsAnalyzer
            analyzer = ForensicsAnalyzer()
            results = analyzer.analyze_file(filepath)
            return results.get('flags', [])
        except ImportError:
            return self.finder.find_in_file(filepath)

    def from_crypto(self, ciphertext):
        """Extract flags from encrypted/encoded text"""
        flags = self.finder.find_in_string(ciphertext)
        flags.extend(self.finder.bruteforce_decode(ciphertext))
        return list(set(flags))

    def auto_detect_and_extract(self, target):
        """Automatically detect target type and extract flags"""
        if not os.path.exists(target):
            # Treat as raw text
            return self.from_crypto(target)

        # Get file extension
        ext = os.path.splitext(target)[1].lower()

        # Route to appropriate extractor
        if ext in ['.pcap', '.pcapng', '.cap']:
            return self.from_pcap(target)
        elif ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']:
            return self.from_image(target)
        elif ext in ['.bin', '.raw', '.mem', '.img', '.dd']:
            return self.from_binary(target)
        else:
            # Generic file search
            return self.finder.find_in_file(target)


def hunt_flags(target, flag_format=None, verbose=True):
    """
    Main function for flag hunting
    Returns all found flags sorted by confidence
    """
    finder = FlagFinder(flag_format)
    results = finder.comprehensive_search(target)

    if verbose:
        print("\n" + "="*50)
        print("FLAG HUNTER RESULTS")
        print("="*50)

        if results['flags']:
            print(f"\n[+] HIGH CONFIDENCE FLAGS ({len(results['flags'])}):")
            for flag in results['flags']:
                print(f"    {flag}")

        if results['possible_flags']:
            print(f"\n[?] POSSIBLE FLAGS ({len(results['possible_flags'])}):")
            for flag in results['possible_flags']:
                print(f"    {flag}")

        if results['encoded_flags']:
            print(f"\n[*] ENCODED FLAGS ({len(results['encoded_flags'])}):")
            for ef in results['encoded_flags']:
                print(f"    {ef['flag']} (via {ef.get('encoding', 'unknown')})")

        if not any([results['flags'], results['possible_flags'], results['encoded_flags']]):
            print("\n[-] No flags found")
            print("\nSuggestions:")
            print("  - Check for steganography in images")
            print("  - Look for encoded data (base64, hex, etc.)")
            print("  - Try different decryption methods")
            print("  - Analyze network traffic carefully")

    return results


def main():
    """CLI interface"""
    import sys

    if len(sys.argv) < 2:
        print("CTF Flag Hunter")
        print("===============")
        print("\nUsage: python flag_finder.py <target> [options]")
        print("\nTarget can be:")
        print("  - File path (any file type)")
        print("  - Directory path")
        print("  - Raw text/encoded string")
        print("\nOptions:")
        print("  --format <format>   Custom flag format (e.g., 'picoCTF{}')")
        print("  --quiet             Minimal output")
        print("\nExamples:")
        print("  python flag_finder.py challenge.pcap")
        print("  python flag_finder.py ./challenges/ --format 'HTB{}'")
        print("  python flag_finder.py 'ZmxhZ3toZWxsb30='")
        return

    target = sys.argv[1]
    flag_format = None
    verbose = True

    if '--format' in sys.argv:
        idx = sys.argv.index('--format')
        flag_format = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None

    if '--quiet' in sys.argv:
        verbose = False

    results = hunt_flags(target, flag_format, verbose)

    # Exit with status based on findings
    if results['flags']:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
