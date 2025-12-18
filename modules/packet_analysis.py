"""
Packet Analysis Module for CTF Challenges
Analyzes PCAP files for hidden data, credentials, flags, and suspicious traffic
"""

import os
import re
import struct
import binascii
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, Raw, ICMP, HTTP, hexdump
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False


class PacketAnalyzer:
    """Analyze network packet captures for CTF challenges"""

    def __init__(self):
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[A-Za-z0-9_]+\{[^}]+\}',  # Generic flag format
        ]

        self.sensitive_patterns = {
            'password': r'(?:password|passwd|pwd|pass)[=:]\s*([^\s&]+)',
            'username': r'(?:username|user|login|email)[=:]\s*([^\s&]+)',
            'api_key': r'(?:api[_-]?key|apikey|token)[=:]\s*([^\s&]+)',
            'auth': r'(?:auth|authorization)[=:]\s*([^\s&]+)',
            'secret': r'(?:secret|private)[=:]\s*([^\s&]+)',
        }

        self.results = {
            'flags': [],
            'credentials': [],
            'dns_queries': [],
            'http_requests': [],
            'ftp_data': [],
            'suspicious': [],
            'extracted_files': [],
            'streams': [],
        }

    def analyze_pcap(self, filepath):
        """Main entry point for PCAP analysis"""
        if not os.path.exists(filepath):
            return {'error': f'File not found: {filepath}'}

        if not SCAPY_AVAILABLE:
            return {'error': 'scapy not installed. Run: pip install scapy'}

        print(f"[*] Analyzing PCAP: {filepath}")
        self.results = {k: [] for k in self.results}

        try:
            packets = rdpcap(filepath)
            print(f"[*] Loaded {len(packets)} packets")

            # Run all analysis methods
            self._analyze_packets(packets)
            self._extract_tcp_streams(packets)
            self._analyze_dns(packets)
            self._analyze_http(packets)
            self._analyze_icmp(packets)
            self._analyze_ftp(packets)
            self._search_flags_in_raw(packets)
            self._detect_covert_channels(packets)

            return self.results

        except Exception as e:
            return {'error': f'Failed to analyze PCAP: {str(e)}'}

    def _analyze_packets(self, packets):
        """General packet analysis"""
        ip_stats = defaultdict(int)
        port_stats = defaultdict(int)
        protocol_stats = defaultdict(int)

        for pkt in packets:
            if IP in pkt:
                ip_stats[pkt[IP].src] += 1
                ip_stats[pkt[IP].dst] += 1
                protocol_stats[pkt[IP].proto] += 1

            if TCP in pkt:
                port_stats[pkt[TCP].sport] += 1
                port_stats[pkt[TCP].dport] += 1
            elif UDP in pkt:
                port_stats[pkt[UDP].sport] += 1
                port_stats[pkt[UDP].dport] += 1

        # Find anomalies
        avg_packets = sum(ip_stats.values()) / max(len(ip_stats), 1)
        for ip, count in ip_stats.items():
            if count > avg_packets * 3:
                self.results['suspicious'].append({
                    'type': 'high_traffic_ip',
                    'ip': ip,
                    'packet_count': count
                })

    def _extract_tcp_streams(self, packets):
        """Reconstruct TCP streams"""
        streams = defaultdict(bytes)

        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                # Create stream identifier
                if IP in pkt:
                    src = f"{pkt[IP].src}:{pkt[TCP].sport}"
                    dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
                    stream_id = tuple(sorted([src, dst]))
                    streams[stream_id] += bytes(pkt[Raw].load)

        for stream_id, data in streams.items():
            # Check for flags in stream
            try:
                decoded = data.decode('utf-8', errors='ignore')
                for pattern in self.flag_patterns:
                    flags = re.findall(pattern, decoded, re.IGNORECASE)
                    for flag in flags:
                        if flag not in self.results['flags']:
                            self.results['flags'].append(flag)

                # Check for credentials
                for cred_type, pattern in self.sensitive_patterns.items():
                    matches = re.findall(pattern, decoded, re.IGNORECASE)
                    for match in matches:
                        self.results['credentials'].append({
                            'type': cred_type,
                            'value': match,
                            'stream': stream_id
                        })
            except:
                pass

            self.results['streams'].append({
                'endpoints': stream_id,
                'size': len(data),
                'preview': data[:200].hex() if len(data) > 0 else ''
            })

    def _analyze_dns(self, packets):
        """Extract DNS queries and responses"""
        for pkt in packets:
            if DNS in pkt:
                if pkt[DNS].qd:  # DNS query
                    qname = pkt[DNS].qd.qname.decode() if isinstance(pkt[DNS].qd.qname, bytes) else str(pkt[DNS].qd.qname)
                    self.results['dns_queries'].append({
                        'query': qname,
                        'type': 'A'  # Simplified
                    })

                    # Check for flag in DNS query (DNS exfiltration)
                    for pattern in self.flag_patterns:
                        if re.search(pattern, qname, re.IGNORECASE):
                            self.results['flags'].append(f"DNS_EXFIL: {qname}")

                    # Check for encoded data in subdomain
                    subdomain = qname.split('.')[0]
                    if len(subdomain) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', subdomain):
                        self.results['suspicious'].append({
                            'type': 'possible_dns_exfiltration',
                            'subdomain': subdomain,
                            'full_query': qname
                        })

    def _analyze_http(self, packets):
        """Extract HTTP requests and responses"""
        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                payload = bytes(pkt[Raw].load)

                try:
                    decoded = payload.decode('utf-8', errors='ignore')

                    # Check for HTTP request
                    if decoded.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
                        lines = decoded.split('\r\n')
                        request_line = lines[0]

                        http_info = {
                            'method': request_line.split()[0],
                            'path': request_line.split()[1] if len(request_line.split()) > 1 else '',
                            'headers': {},
                            'body': ''
                        }

                        # Parse headers
                        in_body = False
                        for line in lines[1:]:
                            if line == '':
                                in_body = True
                                continue
                            if in_body:
                                http_info['body'] += line
                            elif ':' in line:
                                key, value = line.split(':', 1)
                                http_info['headers'][key.strip()] = value.strip()

                        self.results['http_requests'].append(http_info)

                        # Search for flags in HTTP data
                        for pattern in self.flag_patterns:
                            flags = re.findall(pattern, decoded, re.IGNORECASE)
                            self.results['flags'].extend(flags)

                        # Search for credentials in POST data
                        if http_info['body']:
                            for cred_type, pattern in self.sensitive_patterns.items():
                                matches = re.findall(pattern, http_info['body'], re.IGNORECASE)
                                for match in matches:
                                    self.results['credentials'].append({
                                        'type': cred_type,
                                        'value': match,
                                        'source': 'HTTP POST'
                                    })
                except:
                    pass

    def _analyze_icmp(self, packets):
        """Check for data hidden in ICMP packets (ping tunneling)"""
        icmp_data = []

        for pkt in packets:
            if ICMP in pkt and Raw in pkt:
                data = bytes(pkt[Raw].load)
                if len(data) > 8:  # More than standard ping data
                    icmp_data.append(data)

                    # Check for flags
                    try:
                        decoded = data.decode('utf-8', errors='ignore')
                        for pattern in self.flag_patterns:
                            flags = re.findall(pattern, decoded, re.IGNORECASE)
                            for flag in flags:
                                self.results['flags'].append(f"ICMP: {flag}")
                    except:
                        pass

        if icmp_data:
            combined = b''.join(icmp_data)
            self.results['suspicious'].append({
                'type': 'icmp_tunnel_data',
                'size': len(combined),
                'preview': combined[:100].hex()
            })

    def _analyze_ftp(self, packets):
        """Extract FTP commands and data"""
        ftp_commands = []
        ftp_data = []

        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                if pkt[TCP].sport == 21 or pkt[TCP].dport == 21:
                    try:
                        cmd = bytes(pkt[Raw].load).decode('utf-8', errors='ignore').strip()
                        ftp_commands.append(cmd)

                        # Check for credentials
                        if cmd.startswith('USER '):
                            self.results['credentials'].append({
                                'type': 'ftp_username',
                                'value': cmd[5:]
                            })
                        elif cmd.startswith('PASS '):
                            self.results['credentials'].append({
                                'type': 'ftp_password',
                                'value': cmd[5:]
                            })
                    except:
                        pass

                # FTP data transfer (port 20 or passive mode)
                elif pkt[TCP].sport == 20 or pkt[TCP].dport == 20:
                    ftp_data.append(bytes(pkt[Raw].load))

        if ftp_data:
            combined = b''.join(ftp_data)
            self.results['ftp_data'].append({
                'size': len(combined),
                'preview': combined[:200].hex()
            })

            # Check for flags in FTP data
            try:
                decoded = combined.decode('utf-8', errors='ignore')
                for pattern in self.flag_patterns:
                    flags = re.findall(pattern, decoded, re.IGNORECASE)
                    self.results['flags'].extend(flags)
            except:
                pass

    def _search_flags_in_raw(self, packets):
        """Search all raw packet data for flags"""
        for pkt in packets:
            if Raw in pkt:
                try:
                    data = bytes(pkt[Raw].load)
                    decoded = data.decode('utf-8', errors='ignore')

                    for pattern in self.flag_patterns:
                        flags = re.findall(pattern, decoded, re.IGNORECASE)
                        for flag in flags:
                            if flag not in self.results['flags']:
                                self.results['flags'].append(flag)
                except:
                    pass

    def _detect_covert_channels(self, packets):
        """Detect potential covert channels"""
        # Check for unusual TTL values (data in TTL)
        ttl_sequence = []

        for pkt in packets:
            if IP in pkt:
                ttl = pkt[IP].ttl
                # Standard TTLs are typically 64, 128, 255
                if ttl not in [64, 128, 255, 63, 127, 254]:
                    ttl_sequence.append(ttl)

        if len(ttl_sequence) > 10:
            # Try to decode as ASCII
            try:
                ascii_text = ''.join(chr(t) for t in ttl_sequence if 32 <= t <= 126)
                if len(ascii_text) > 5:
                    self.results['suspicious'].append({
                        'type': 'ttl_covert_channel',
                        'decoded': ascii_text,
                        'raw_ttls': ttl_sequence[:20]
                    })
            except:
                pass

        # Check for TCP urgent pointer abuse
        for pkt in packets:
            if TCP in pkt:
                if pkt[TCP].flags.U and pkt[TCP].urgptr > 0:
                    self.results['suspicious'].append({
                        'type': 'tcp_urgent_pointer',
                        'value': pkt[TCP].urgptr
                    })

    def extract_files(self, packets, output_dir='extracted'):
        """Extract files from packet capture"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Look for common file signatures
        file_signatures = {
            b'\x89PNG\r\n\x1a\n': ('png', 'IEND'),
            b'\xff\xd8\xff': ('jpg', b'\xff\xd9'),
            b'%PDF': ('pdf', '%%EOF'),
            b'PK\x03\x04': ('zip', None),
            b'GIF8': ('gif', b'\x00;'),
            b'\x7fELF': ('elf', None),
        }

        # Combine all TCP stream data
        stream_data = defaultdict(bytes)
        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                if IP in pkt:
                    stream_id = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
                    stream_data[stream_id] += bytes(pkt[Raw].load)

        extracted_count = 0
        for stream_id, data in stream_data.items():
            for sig, (ext, end_marker) in file_signatures.items():
                start = data.find(sig)
                if start != -1:
                    # Find end of file
                    if end_marker:
                        if isinstance(end_marker, bytes):
                            end = data.find(end_marker, start)
                        else:
                            end = data.find(end_marker.encode(), start)
                        if end != -1:
                            file_data = data[start:end + len(end_marker)]
                        else:
                            file_data = data[start:start + 10000]  # Limit size
                    else:
                        file_data = data[start:start + 10000]

                    # Save file
                    filename = f"{output_dir}/extracted_{extracted_count}.{ext}"
                    with open(filename, 'wb') as f:
                        f.write(file_data)

                    self.results['extracted_files'].append({
                        'filename': filename,
                        'type': ext,
                        'size': len(file_data)
                    })
                    extracted_count += 1

        return extracted_count

    def get_statistics(self, packets):
        """Get packet statistics"""
        stats = {
            'total_packets': len(packets),
            'protocols': defaultdict(int),
            'ip_conversations': defaultdict(int),
            'ports': defaultdict(int),
            'packet_sizes': []
        }

        for pkt in packets:
            stats['packet_sizes'].append(len(pkt))

            if IP in pkt:
                stats['protocols'][pkt[IP].proto] += 1
                conv = tuple(sorted([pkt[IP].src, pkt[IP].dst]))
                stats['ip_conversations'][conv] += 1

            if TCP in pkt:
                stats['ports'][pkt[TCP].dport] += 1
            elif UDP in pkt:
                stats['ports'][pkt[UDP].dport] += 1

        stats['avg_packet_size'] = sum(stats['packet_sizes']) / max(len(stats['packet_sizes']), 1)
        stats['top_talkers'] = sorted(stats['ip_conversations'].items(), key=lambda x: x[1], reverse=True)[:10]
        stats['top_ports'] = sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10]

        return stats

    def quick_analysis(self, filepath):
        """Quick analysis focusing on finding flags fast"""
        results = self.analyze_pcap(filepath)

        summary = {
            'flags_found': results.get('flags', []),
            'credentials': results.get('credentials', []),
            'suspicious': results.get('suspicious', []),
            'recommendation': []
        }

        if not summary['flags_found']:
            summary['recommendation'].append("No flags found directly. Try:")
            summary['recommendation'].append("  - Extract files with extract_files()")
            summary['recommendation'].append("  - Check DNS queries for exfiltration")
            summary['recommendation'].append("  - Analyze individual TCP streams")
            summary['recommendation'].append("  - Look for encoded data in HTTP responses")

        return summary


def main():
    """CLI interface for packet analysis"""
    import sys

    if not SCAPY_AVAILABLE:
        print("[!] scapy not installed. Install with: pip install scapy")
        return

    if len(sys.argv) < 2:
        print("Usage: python packet_analysis.py <pcap_file>")
        print("\nOptions:")
        print("  --quick     Quick analysis (flag hunting)")
        print("  --extract   Extract files from PCAP")
        print("  --stats     Show packet statistics")
        return

    analyzer = PacketAnalyzer()
    filepath = sys.argv[1]

    if '--quick' in sys.argv:
        results = analyzer.quick_analysis(filepath)
    else:
        results = analyzer.analyze_pcap(filepath)

    if '--extract' in sys.argv:
        packets = rdpcap(filepath)
        count = analyzer.extract_files(packets)
        print(f"[+] Extracted {count} files")

    if '--stats' in sys.argv:
        packets = rdpcap(filepath)
        stats = analyzer.get_statistics(packets)
        print("\n=== Packet Statistics ===")
        print(f"Total packets: {stats['total_packets']}")
        print(f"Average packet size: {stats['avg_packet_size']:.2f} bytes")
        print(f"\nTop talkers: {stats['top_talkers'][:5]}")
        print(f"Top ports: {stats['top_ports'][:5]}")

    # Print results
    print("\n=== Analysis Results ===")

    if results.get('flags'):
        print(f"\n[+] FLAGS FOUND: {len(results['flags'])}")
        for flag in results['flags']:
            print(f"    {flag}")

    if results.get('credentials'):
        print(f"\n[+] CREDENTIALS: {len(results['credentials'])}")
        for cred in results['credentials']:
            print(f"    {cred['type']}: {cred['value']}")

    if results.get('suspicious'):
        print(f"\n[!] SUSPICIOUS: {len(results['suspicious'])}")
        for sus in results['suspicious']:
            print(f"    {sus['type']}: {sus}")


if __name__ == "__main__":
    main()
