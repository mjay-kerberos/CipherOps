# CipherOps - CTF Toolkit

A comprehensive CTF (Capture The Flag) analysis toolkit for solving crypto, steganography, forensics, and network challenges. Automatically detects file types, searches for flags, and applies appropriate analysis techniques.

## Features

### Crypto Analysis (`cipherOps.py`)
- **Encodings**: Base64, Base32, Base85, ASCII85, Base58, Hex, Binary, Morse, Base36, Base62, Octal, Decimal
- **Ciphers**: Caesar (ROT1-25), Vigenere, Atbash, Baconian, Rail Fence, Substitution
- **Hash identification**: MD5, SHA1, SHA256, SHA512, etc.
- Combined/nested encoding detection
- Flag format support

### Packet Analysis (`modules/packet_analysis.py`)
- PCAP/PCAPNG file analysis
- TCP stream reconstruction
- HTTP request/response extraction
- DNS query analysis (exfiltration detection)
- FTP credential extraction
- ICMP tunnel detection
- Covert channel detection (TTL, urgent pointer)
- File carving from network traffic

### Image/Steganography Analysis (`modules/image_analysis.py`)
- EXIF metadata extraction
- LSB (Least Significant Bit) extraction
- Appended data detection
- PNG chunk analysis
- Embedded file detection
- Color plane analysis
- zsteg-like multi-configuration analysis

### Forensics (`modules/forensics.py`)
- File carving (PNG, JPEG, PDF, ZIP, etc.)
- String extraction (ASCII, Unicode)
- Entropy analysis
- Memory dump analysis
- MBR/partition analysis
- File diffing and XOR detection
- Hash calculation

### Flag Finder (`modules/flag_finder.py`)
- Automated flag hunting across all file types
- Support for common CTF flag formats
- Bruteforce decoding (Base64, Hex, ROT13, etc.)
- Confidence scoring for potential flags
- Recursive directory scanning

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/CipherOps.git
cd CipherOps

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
- `pycryptodome` - Cryptographic functions
- `scapy` - Packet analysis
- `Pillow` - Image processing
- `numpy` - Numerical operations (for stego)

### Optional Tools
For enhanced steganography analysis, install:
```bash
# Steghide (extract hidden data with passwords)
brew install steghide  # macOS
apt install steghide   # Linux

# zsteg (LSB analysis for PNG/BMP)
gem install zsteg

# binwalk (file carving)
pip install binwalk
```

## Usage

### Quick Start - Interactive Mode
```bash
python ctf_toolkit.py
```

### Command Line
```bash
# Auto-detect and analyze any file
python ctf_toolkit.py challenge_file

# Analyze PCAP
python ctf_toolkit.py capture.pcap

# Analyze image for steganography
python ctf_toolkit.py hidden.png

# Fast flag hunting in directory
python ctf_toolkit.py --hunt ./challenge_files/

# Analyze encoded text
python ctf_toolkit.py --crypto "ZmxhZ3toZWxsb30="

# Use custom flag format
python ctf_toolkit.py --format "picoCTF{}" challenge.bin

# Carve embedded files
python ctf_toolkit.py --carve suspicious.bin --output carved/
```

### Python API
```python
from ctf_toolkit import CTFToolkit

# Initialize
toolkit = CTFToolkit(flag_format="flag{}")

# Auto-analyze
results = toolkit.analyze_auto("challenge.pcap")

# Specific analysis
toolkit.analyze_pcap("capture.pcap")
toolkit.analyze_image("stego.png")
toolkit.analyze_crypto("ZmxhZ3tzZWNyZXR9")

# Get results
print(toolkit.get_summary())
```

### Module-Specific Usage

#### Crypto Analysis
```python
from cipherOps import CryptoAnalyzer

analyzer = CryptoAnalyzer()
results = analyzer.analyze("SGVsbG8gV29ybGQ=")
```

#### Packet Analysis
```python
from modules.packet_analysis import PacketAnalyzer

analyzer = PacketAnalyzer()
results = analyzer.analyze_pcap("capture.pcap")
print(results['flags'])
print(results['credentials'])
```

#### Image Analysis
```python
from modules.image_analysis import ImageAnalyzer

analyzer = ImageAnalyzer()
results = analyzer.analyze("suspicious.png")

# Advanced LSB extraction
data = analyzer.extract_lsb_advanced("image.png", channel='blue', bit_plane=0)

# zsteg-like analysis
steg_results = analyzer.zsteg_like_analysis("image.png")
```

#### Forensics
```python
from modules.forensics import ForensicsAnalyzer

analyzer = ForensicsAnalyzer()

# Analyze file
results = analyzer.analyze_file("mystery.bin")

# Carve embedded files
count = analyzer.carve_files("combined.bin", output_dir="carved")

# Deep string analysis
strings = analyzer.analyze_strings_deep("memory.dmp")
```

#### Flag Finder
```python
from modules.flag_finder import hunt_flags, FlagFinder

# Quick hunt
results = hunt_flags("./challenges/", flag_format="CTF{}")

# Custom finder
finder = FlagFinder(flag_format="picoCTF{}")
flags = finder.find_in_directory("./ctf/")
flags = finder.bruteforce_decode("encoded_text")
```

## Project Structure

```
CipherOps/
├── ctf_toolkit.py          # Main orchestrator with CLI
├── cipherOps.py            # Original crypto analyzer
├── requirements.txt        # Python dependencies
├── README.md
├── LICENSE
└── modules/
    ├── __init__.py
    ├── packet_analysis.py  # PCAP analysis
    ├── image_analysis.py   # Steganography
    ├── forensics.py        # File forensics
    └── flag_finder.py      # Automated flag hunting
```

## Example Output

```
   ____ _____ _____   _____           _ _    _ _
  / ___|_   _|  ___| |_   _|__   ___ | | | _(_) |_
 | |     | | | |_      | |/ _ \ / _ \| | |/ / | __|
 | |___  | | |  _|     | | (_) | (_) | |   <| | |_
  \____| |_| |_|       |_|\___/ \___/|_|_|\_\_|\__|

    Crypto | Packets | Images | Forensics | Flags

[*] Auto-analyzing: challenge.pcap
[*] Detected file type: pcap
[*] Analyzing PCAP: challenge.pcap
[*] Loaded 1523 packets
[+] Found 2 flags in PCAP
[+] Found 3 credentials

============================================================
CTF TOOLKIT ANALYSIS RESULTS
============================================================

[+] FLAGS FOUND (2):
    flag{n3tw0rk_tr4ff1c_4n4lys1s}
    flag{h1dd3n_1n_pl41n_s1ght}

[*] RECOMMENDATIONS:
    - Check DNS queries for exfiltration
    - Analyze individual TCP streams

============================================================
```

## CTF Challenge Workflow

1. **Receive challenge file** - Could be anything: pcap, image, binary, text
2. **Run auto-analysis**:
   ```bash
   python ctf_toolkit.py challenge_file
   ```
3. **Check results** - Flags found automatically
4. **Follow recommendations** - If no flags, try suggested tools
5. **Manual investigation** - Use specific modules for deeper analysis

## Common CTF Techniques Covered

| Category | Techniques |
|----------|------------|
| Crypto | Base64, Hex, ROT13, XOR, Caesar, Vigenere |
| Stego | LSB, metadata, appended data, color planes |
| Forensics | File carving, strings, entropy, memory |
| Network | HTTP, DNS exfil, FTP creds, covert channels |
| Misc | Flag patterns, encoding chains, bruteforce |

## Supported Flag Formats

- `flag{...}`
- `FLAG{...}`
- `ctf{...}`
- `CTF{...}`
- `picoCTF{...}`
- `HTB{...}`
- `CSAW{...}`
- And many more competition-specific formats

Custom formats can be specified with `--format` flag.

## Contributing

Contributions welcome! Areas for improvement:
- Additional cipher support
- More steganography techniques
- Memory forensics (Volatility integration)
- Web challenge tools
- Binary exploitation helpers

## License

MIT License - See LICENSE file.

## Acknowledgments

- Built for the CTF community
- Inspired by tools like CyberChef, zsteg, binwalk
- Thanks to all CTF players who provided feedback
