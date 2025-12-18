#!/usr/bin/env python3
"""
CipherOps - CTF Crypto Analyzer
Comprehensive tool for analyzing encodings, ciphers, and hashes in CTF challenges
"""

import re
import base64
import hashlib
import string
import codecs
import binascii
import urllib.parse
from itertools import product
from collections import Counter

try:
    from Crypto.Util.number import inverse
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class CryptoAnalyzer:
    """Comprehensive cryptographic analysis tool for CTF challenges"""

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.recursion_depth = 0
        self.max_recursion = 3

        # Morse code dictionary
        self.morse_code_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
            '9': '----.', '0': '-----', ' ': '/', '.': '.-.-.-', ',': '--..--',
            '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.',
            ')': '-.--.-', '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
            '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-',
            '@': '.--.-.'
        }
        self.reverse_morse = {v: k for k, v in self.morse_code_dict.items()}

        # Atbash cipher mapping
        self.atbash_map = str.maketrans(
            string.ascii_uppercase + string.ascii_lowercase,
            string.ascii_uppercase[::-1] + string.ascii_lowercase[::-1]
        )

        # Baconian cipher dictionary
        self.baconian_dict = {
            'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
            'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
            'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
            'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
            'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
            'BBAAB': 'Z'
        }

        # Common hash lengths
        self.hash_lengths = {
            32: ['MD5', 'MD4', 'MD2', 'NTLM'],
            40: ['SHA1', 'RIPEMD-160'],
            56: ['SHA-224'],
            64: ['SHA-256', 'SHA3-256', 'BLAKE2s'],
            96: ['SHA-384', 'SHA3-384'],
            128: ['SHA-512', 'SHA3-512', 'BLAKE2b', 'Whirlpool'],
        }

        # English letter frequency for analysis
        self.english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }

        # Common CTF keywords for Vigenere
        self.common_keys = [
            'FLAG', 'CTF', 'KEY', 'SECRET', 'CRYPTO', 'HACK', 'CIPHER',
            'PASSWORD', 'HIDDEN', 'CODE', 'PUZZLE', 'ANSWER', 'SECURITY'
        ]

        # Flag patterns
        self.flag_patterns = [
            r'flag\{[^}]+\}', r'FLAG\{[^}]+\}', r'ctf\{[^}]+\}', r'CTF\{[^}]+\}',
            r'picoCTF\{[^}]+\}', r'HTB\{[^}]+\}', r'CSAW\{[^}]+\}'
        ]

    def log(self, message):
        """Print message if verbose mode is enabled"""
        if self.verbose:
            print(message)

    # ==================== MAIN ANALYSIS ====================

    def analyze(self, ciphertext, check_nested=True):
        """Main analysis function - tries all detection and decoding methods"""
        if not ciphertext or not isinstance(ciphertext, str):
            return []

        ciphertext = ciphertext.strip()
        if not ciphertext:
            return []

        self.log(f"Analyzing: {ciphertext[:100]}{'...' if len(ciphertext) > 100 else ''}")
        results = []

        # Check for flags first
        flags = self._find_flags(ciphertext)
        if flags:
            results.append({'type': 'flag_found', 'decoded': flags})

        # Try encodings
        encoding_results = self._try_encodings(ciphertext)
        results.extend(encoding_results)

        # Try number system conversions
        number_results = self._try_number_systems(ciphertext)
        results.extend(number_results)

        # Check if it's a hash
        hash_result = self._identify_hash(ciphertext)
        if hash_result:
            results.append(hash_result)

        # Try ciphers
        cipher_results = self._try_ciphers(ciphertext)
        results.extend(cipher_results)

        # Try nested decoding on successful results
        if check_nested and self.recursion_depth < self.max_recursion:
            self.recursion_depth += 1
            for result in results[:]:  # Copy to avoid modification during iteration
                if 'decoded' in result and isinstance(result['decoded'], str):
                    decoded = result['decoded']
                    if decoded != ciphertext and len(decoded) > 3:
                        nested = self.analyze(decoded, check_nested=True)
                        if nested:
                            results.append({
                                'type': f"nested_{result['type']}",
                                'decoded': nested
                            })
            self.recursion_depth -= 1

        return results

    def analyze_with_flag_format(self, ciphertext, flag_format="flag{}"):
        """Analyze with specific flag format"""
        if '{' in flag_format and '}' in flag_format:
            prefix = flag_format[:flag_format.index('{')]
            suffix = flag_format[flag_format.index('}') + 1:]

            if ciphertext.startswith(prefix) and (not suffix or ciphertext.endswith(suffix)):
                start = len(prefix) + 1
                end = -1 if suffix else len(ciphertext) - 1
                content = ciphertext[start:end]
                self.log(f"Analyzing flag content: {content}")
                return self.analyze(content)

        return self.analyze(ciphertext)

    def _find_flags(self, text):
        """Search for flag patterns"""
        found = []
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            found.extend(matches)
        return list(set(found)) if found else None

    # ==================== ENCODING DETECTION ====================

    def _is_base64(self, text):
        """Check if text is valid Base64"""
        if len(text) < 4:
            return False
        # Must be multiple of 4 or have valid padding
        if len(text) % 4 not in [0, 2, 3]:
            text_check = text.rstrip('=')
        else:
            text_check = text
        return bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', text))

    def _is_base32(self, text):
        """Check if text is valid Base32"""
        return bool(re.match(r'^[A-Z2-7]+=*$', text.upper())) and len(text) >= 8

    def _is_base85(self, text):
        """Check if text is valid Base85"""
        return bool(re.match(r'^[!-u]+$', text)) and len(text) >= 5

    def _is_ascii85(self, text):
        """Check if text is valid ASCII85"""
        return text.startswith('<~') and text.endswith('~>')

    def _is_base58(self, text):
        """Check if text is valid Base58"""
        return bool(re.match(r'^[1-9A-HJ-NP-Za-km-z]+$', text)) and len(text) >= 4

    def _is_hex(self, text):
        """Check if text is valid hexadecimal"""
        return bool(re.match(r'^[0-9a-fA-F]+$', text)) and len(text) >= 2 and len(text) % 2 == 0

    def _is_binary(self, text):
        """Check if text is binary (with or without spaces)"""
        clean = text.replace(' ', '')
        return bool(re.match(r'^[01]+$', clean)) and len(clean) >= 8

    def _is_octal(self, text):
        """Check if text is octal"""
        clean = text.replace(' ', '')
        return bool(re.match(r'^[0-7]+$', clean)) and len(clean) >= 3

    def _is_decimal_ascii(self, text):
        """Check if text is decimal ASCII codes"""
        parts = re.split(r'[\s,;]+', text)
        if len(parts) < 2:
            return False
        try:
            nums = [int(p) for p in parts if p]
            return all(0 <= n <= 127 for n in nums)
        except:
            return False

    def _is_morse(self, text):
        """Check if text is Morse code"""
        return bool(re.match(r'^[\.\-]+(?:[\s/]+[\.\-]+)*$', text))

    def _is_url_encoded(self, text):
        """Check if text is URL encoded"""
        return '%' in text and bool(re.search(r'%[0-9A-Fa-f]{2}', text))

    def _is_unicode_escaped(self, text):
        """Check if text has unicode escapes"""
        return bool(re.search(r'\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}', text))

    # ==================== ENCODING DECODERS ====================

    def _try_encodings(self, text):
        """Try all encoding decoders"""
        results = []

        # Base64
        if self._is_base64(text):
            decoded = self._decode_base64(text)
            if decoded:
                results.append({'type': 'base64', 'decoded': decoded})

        # Base32
        if self._is_base32(text):
            decoded = self._decode_base32(text)
            if decoded:
                results.append({'type': 'base32', 'decoded': decoded})

        # Base85
        if self._is_base85(text):
            decoded = self._decode_base85(text)
            if decoded:
                results.append({'type': 'base85', 'decoded': decoded})

        # ASCII85
        if self._is_ascii85(text):
            decoded = self._decode_ascii85(text)
            if decoded:
                results.append({'type': 'ascii85', 'decoded': decoded})

        # Base58
        if self._is_base58(text):
            decoded = self._decode_base58(text)
            if decoded:
                results.append({'type': 'base58', 'decoded': decoded})

        # Hexadecimal
        if self._is_hex(text):
            decoded = self._decode_hex(text)
            if decoded:
                results.append({'type': 'hex', 'decoded': decoded})

        # Binary
        if self._is_binary(text):
            decoded = self._decode_binary(text)
            if decoded:
                results.append({'type': 'binary', 'decoded': decoded})

        # Octal
        if self._is_octal(text):
            decoded = self._decode_octal(text)
            if decoded:
                results.append({'type': 'octal', 'decoded': decoded})

        # Decimal ASCII
        if self._is_decimal_ascii(text):
            decoded = self._decode_decimal_ascii(text)
            if decoded:
                results.append({'type': 'decimal_ascii', 'decoded': decoded})

        # Morse code
        if self._is_morse(text):
            decoded = self._decode_morse(text)
            if decoded:
                results.append({'type': 'morse', 'decoded': decoded})

        # URL encoding
        if self._is_url_encoded(text):
            decoded = self._decode_url(text)
            if decoded and decoded != text:
                results.append({'type': 'url_encoded', 'decoded': decoded})

        # Unicode escapes
        if self._is_unicode_escaped(text):
            decoded = self._decode_unicode_escapes(text)
            if decoded and decoded != text:
                results.append({'type': 'unicode_escape', 'decoded': decoded})

        # ROT13 (always try)
        decoded = self._decode_rot13(text)
        if decoded and self._looks_like_text(decoded):
            results.append({'type': 'rot13', 'decoded': decoded})

        return results

    def _decode_base64(self, text):
        """Decode Base64"""
        try:
            # Add padding if needed
            padding = 4 - (len(text) % 4)
            if padding != 4:
                text += '=' * padding
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except:
            return None

    def _decode_base32(self, text):
        """Decode Base32"""
        try:
            # Add padding if needed
            text = text.upper()
            padding = 8 - (len(text) % 8)
            if padding != 8:
                text += '=' * padding
            return base64.b32decode(text).decode('utf-8', errors='ignore')
        except:
            return None

    def _decode_base85(self, text):
        """Decode Base85"""
        try:
            return base64.b85decode(text).decode('utf-8', errors='ignore')
        except:
            return None

    def _decode_ascii85(self, text):
        """Decode ASCII85"""
        try:
            if text.startswith('<~') and text.endswith('~>'):
                text = text[2:-2]
            return base64.a85decode(text).decode('utf-8', errors='ignore')
        except:
            return None

    def _decode_base58(self, text):
        """Decode Base58"""
        try:
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            num = 0
            for char in text:
                num = num * 58 + alphabet.index(char)

            result = []
            while num > 0:
                num, rem = divmod(num, 256)
                result.append(rem)

            # Handle leading zeros
            for char in text:
                if char == '1':
                    result.append(0)
                else:
                    break

            return bytes(reversed(result)).decode('utf-8', errors='ignore')
        except:
            return None

    def _decode_hex(self, text):
        """Decode hexadecimal"""
        try:
            return bytes.fromhex(text).decode('utf-8', errors='ignore')
        except:
            return None

    def _decode_binary(self, text):
        """Decode binary"""
        try:
            clean = text.replace(' ', '')
            # Pad to multiple of 8
            if len(clean) % 8 != 0:
                clean = clean.zfill((len(clean) // 8 + 1) * 8)

            chars = []
            for i in range(0, len(clean), 8):
                byte = clean[i:i + 8]
                chars.append(chr(int(byte, 2)))
            return ''.join(chars)
        except:
            return None

    def _decode_octal(self, text):
        """Decode octal"""
        try:
            parts = text.split()
            if len(parts) == 1:
                # Single octal number
                num = int(text, 8)
                byte_len = (num.bit_length() + 7) // 8
                return num.to_bytes(byte_len, 'big').decode('utf-8', errors='ignore')
            else:
                # Multiple octal values
                chars = [chr(int(p, 8)) for p in parts]
                return ''.join(chars)
        except:
            return None

    def _decode_decimal_ascii(self, text):
        """Decode decimal ASCII codes"""
        try:
            parts = re.split(r'[\s,;]+', text)
            chars = [chr(int(p)) for p in parts if p]
            return ''.join(chars)
        except:
            return None

    def _decode_morse(self, text):
        """Decode Morse code"""
        try:
            words = text.split('/')
            decoded_words = []

            for word in words:
                letters = word.strip().split()
                decoded_letters = []
                for letter in letters:
                    if letter in self.reverse_morse:
                        decoded_letters.append(self.reverse_morse[letter])
                decoded_words.append(''.join(decoded_letters))

            return ' '.join(decoded_words)
        except:
            return None

    def _decode_url(self, text):
        """Decode URL encoding"""
        try:
            return urllib.parse.unquote(text)
        except:
            return None

    def _decode_unicode_escapes(self, text):
        """Decode unicode escape sequences"""
        try:
            return text.encode().decode('unicode_escape')
        except:
            try:
                return codecs.decode(text, 'unicode_escape')
            except:
                return None

    def _decode_rot13(self, text):
        """Decode ROT13"""
        try:
            return codecs.decode(text, 'rot_13')
        except:
            return None

    # ==================== NUMBER SYSTEMS ====================

    def _try_number_systems(self, text):
        """Try converting between number systems"""
        results = []

        # Binary to ASCII
        if self._is_binary(text):
            decoded = self._decode_binary(text)
            if decoded and self._looks_like_text(decoded):
                results.append({'type': 'binary_to_ascii', 'decoded': decoded})

        # Hex to ASCII (already covered in encodings)

        # Decimal string to various bases
        if text.isdigit() and len(text) > 4:
            conversions = self._convert_number(int(text))
            if conversions:
                results.append({'type': 'number_conversion', 'decoded': conversions})

        return results

    def _convert_number(self, num):
        """Convert a number to various representations"""
        results = []

        # To ASCII (if valid range)
        try:
            byte_len = (num.bit_length() + 7) // 8
            ascii_text = num.to_bytes(byte_len, 'big').decode('ascii')
            if self._looks_like_text(ascii_text):
                results.append(('ASCII', ascii_text))
        except:
            pass

        # To hex
        results.append(('Hex', hex(num)[2:]))

        # To binary
        results.append(('Binary', bin(num)[2:]))

        # To base36
        results.append(('Base36', self._to_base36(num)))

        return results

    def _to_base36(self, num):
        """Convert number to base36"""
        if num == 0:
            return '0'
        chars = string.digits + string.ascii_lowercase
        result = ''
        while num:
            num, rem = divmod(num, 36)
            result = chars[rem] + result
        return result

    # ==================== HASH DETECTION ====================

    def _identify_hash(self, text):
        """Identify potential hash type"""
        # Must be hex and certain length
        if not self._is_hex(text):
            return None

        length = len(text)
        if length in self.hash_lengths:
            return {
                'type': 'hash',
                'possible_types': self.hash_lengths[length],
                'length': length
            }
        return None

    # ==================== CIPHER ANALYSIS ====================

    def _try_ciphers(self, text):
        """Try various cipher decryption methods"""
        results = []

        # ROT variations (Caesar)
        rot_results = self._try_all_rot(text)
        results.extend(rot_results)

        # Atbash
        atbash = self._decrypt_atbash(text)
        if atbash and atbash != text:
            results.append({'type': 'atbash', 'decoded': atbash})

        # Vigenere with common keys
        vig_results = self._try_vigenere(text)
        results.extend(vig_results)

        # Baconian
        if self._is_baconian(text):
            decoded = self._decode_baconian(text)
            if decoded:
                results.append({'type': 'baconian', 'decoded': decoded})

        # Rail fence
        rail_results = self._try_rail_fence(text)
        results.extend(rail_results)

        # XOR with common single-byte keys
        xor_results = self._try_xor(text)
        results.extend(xor_results)

        # Affine cipher
        affine_results = self._try_affine(text)
        results.extend(affine_results)

        return results

    def _try_all_rot(self, text):
        """Try all ROT/Caesar variations"""
        if not any(c.isalpha() for c in text):
            return []

        results = []
        for shift in range(1, 26):
            decoded = self._caesar_shift(text, shift)
            # Only include if it looks like readable text
            if self._looks_like_text(decoded):
                results.append({
                    'type': f'rot{shift}',
                    'decoded': decoded,
                    'score': self._english_score(decoded)
                })

        # Sort by English score and return top results
        results.sort(key=lambda x: x.get('score', 0), reverse=True)
        return results[:3]  # Return top 3 most likely

    def _caesar_shift(self, text, shift):
        """Apply Caesar cipher shift"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(char)
        return ''.join(result)

    def _decrypt_atbash(self, text):
        """Decrypt Atbash cipher"""
        return text.translate(self.atbash_map)

    def _try_vigenere(self, text):
        """Try Vigenere with common keys"""
        if not text.isalpha():
            return []

        results = []
        for key in self.common_keys:
            decoded = self._vigenere_decrypt(text, key)
            if decoded and self._looks_like_text(decoded):
                results.append({
                    'type': f'vigenere_{key}',
                    'decoded': decoded,
                    'key': key
                })

        return results

    def _vigenere_decrypt(self, text, key):
        """Decrypt Vigenere cipher"""
        result = []
        key_upper = key.upper()
        key_index = 0

        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                key_shift = ord(key_upper[key_index % len(key_upper)]) - ord('A')
                shifted = (ord(char) - base - key_shift) % 26 + base
                result.append(chr(shifted))
                key_index += 1
            else:
                result.append(char)

        return ''.join(result)

    def _is_baconian(self, text):
        """Check if text is Baconian cipher"""
        clean = re.sub(r'[^ABab]', '', text.upper())
        return len(clean) >= 5 and len(clean) % 5 == 0 and set(clean) <= {'A', 'B'}

    def _decode_baconian(self, text):
        """Decode Baconian cipher"""
        clean = re.sub(r'[^ABab]', '', text.upper())
        result = []

        for i in range(0, len(clean), 5):
            chunk = clean[i:i + 5]
            if chunk in self.baconian_dict:
                result.append(self.baconian_dict[chunk])

        return ''.join(result) if result else None

    def _try_rail_fence(self, text):
        """Try Rail Fence cipher with various rail counts"""
        results = []

        for rails in range(2, 6):
            decoded = self._rail_fence_decrypt(text, rails)
            if decoded and self._looks_like_text(decoded):
                results.append({
                    'type': f'rail_fence_{rails}',
                    'decoded': decoded,
                    'rails': rails
                })

        return results

    def _rail_fence_decrypt(self, text, rails):
        """Decrypt Rail Fence cipher"""
        if len(text) < rails * 2:
            return None

        try:
            fence = [['' for _ in range(len(text))] for _ in range(rails)]

            # Mark positions
            rail = 0
            direction = 1
            for i in range(len(text)):
                fence[rail][i] = '*'
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction

            # Fill in characters
            index = 0
            for r in range(rails):
                for c in range(len(text)):
                    if fence[r][c] == '*' and index < len(text):
                        fence[r][c] = text[index]
                        index += 1

            # Read off
            result = []
            rail = 0
            direction = 1
            for i in range(len(text)):
                result.append(fence[rail][i])
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction = -direction

            return ''.join(result)
        except:
            return None

    def _try_xor(self, text):
        """Try XOR with common single-byte keys"""
        results = []

        try:
            # If hex, convert to bytes first
            if self._is_hex(text):
                data = bytes.fromhex(text)
            else:
                data = text.encode()

            # Try single-byte XOR
            for key in range(256):
                decoded_bytes = bytes(b ^ key for b in data)
                try:
                    decoded = decoded_bytes.decode('utf-8', errors='strict')
                    if self._looks_like_text(decoded) and key != 0:
                        results.append({
                            'type': f'xor_key_{key}',
                            'decoded': decoded,
                            'key': key
                        })
                except:
                    pass
        except:
            pass

        return results[:3]  # Return top matches

    def _try_affine(self, text):
        """Try Affine cipher with common multipliers"""
        if not text.isalpha():
            return []

        results = []
        # Coprime values with 26
        multipliers = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

        for a in multipliers:
            for b in range(26):
                decoded = self._affine_decrypt(text, a, b)
                if decoded and self._looks_like_text(decoded):
                    score = self._english_score(decoded)
                    if score > 0.5:  # Only if reasonable English
                        results.append({
                            'type': f'affine_a{a}_b{b}',
                            'decoded': decoded,
                            'a': a,
                            'b': b
                        })

        return results[:3]

    def _affine_decrypt(self, text, a, b):
        """Decrypt Affine cipher"""
        try:
            # Find modular inverse of a
            a_inv = pow(a, -1, 26)

            result = []
            for char in text:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    x = ord(char) - base
                    decrypted = (a_inv * (x - b)) % 26 + base
                    result.append(chr(decrypted))
                else:
                    result.append(char)
            return ''.join(result)
        except:
            return None

    # ==================== FREQUENCY ANALYSIS ====================

    def frequency_analysis(self, text):
        """Perform frequency analysis on text"""
        # Count letters only
        letters = [c.upper() for c in text if c.isalpha()]
        if not letters:
            return {}

        total = len(letters)
        freq = Counter(letters)

        # Convert to percentages
        analysis = {char: (count / total) * 100 for char, count in freq.items()}
        return dict(sorted(analysis.items(), key=lambda x: x[1], reverse=True))

    def crack_substitution(self, text):
        """Attempt to crack substitution cipher using frequency analysis"""
        freq = self.frequency_analysis(text)
        if not freq:
            return None

        # Map most frequent to English frequency order
        english_order = sorted(self.english_freq.keys(), key=lambda x: self.english_freq[x], reverse=True)
        cipher_order = sorted(freq.keys(), key=lambda x: freq[x], reverse=True)

        # Create mapping
        mapping = {}
        for i, cipher_char in enumerate(cipher_order):
            if i < len(english_order):
                mapping[cipher_char] = english_order[i]
                mapping[cipher_char.lower()] = english_order[i].lower()

        # Apply mapping
        result = []
        for char in text:
            if char.upper() in mapping:
                if char.isupper():
                    result.append(mapping[char])
                else:
                    result.append(mapping[char.upper()].lower())
            else:
                result.append(char)

        return ''.join(result)

    # ==================== UTILITY METHODS ====================

    def _looks_like_text(self, text):
        """Check if decoded result looks like readable text"""
        if not text or len(text) < 2:
            return False

        # Check printable ratio
        printable = sum(1 for c in text if c.isprintable())
        if printable / len(text) < 0.8:
            return False

        # Check for common patterns
        alpha_ratio = sum(1 for c in text if c.isalpha()) / len(text)
        if alpha_ratio < 0.3:
            return False

        return True

    def _english_score(self, text):
        """Score how likely text is to be English"""
        if not text:
            return 0

        freq = self.frequency_analysis(text)
        if not freq:
            return 0

        # Compare to expected English frequencies
        score = 0
        for char, expected in self.english_freq.items():
            actual = freq.get(char, 0)
            # Closer frequencies = higher score
            diff = abs(expected - actual)
            score += max(0, 10 - diff)

        return score / 260  # Normalize

    # ==================== COMBINED ENCODINGS ====================

    def try_combined_encodings(self, text, max_depth=3):
        """Try combinations of encodings"""
        encoders = ['base64', 'base32', 'hex', 'rot13', 'url']
        results = []

        def try_decode(data, chain, depth):
            if depth > max_depth:
                return

            for enc in encoders:
                decoded = None
                if enc == 'base64' and self._is_base64(data):
                    decoded = self._decode_base64(data)
                elif enc == 'base32' and self._is_base32(data):
                    decoded = self._decode_base32(data)
                elif enc == 'hex' and self._is_hex(data):
                    decoded = self._decode_hex(data)
                elif enc == 'rot13':
                    decoded = self._decode_rot13(data)
                elif enc == 'url' and self._is_url_encoded(data):
                    decoded = self._decode_url(data)

                if decoded and decoded != data and len(decoded) > 2:
                    new_chain = chain + [enc]
                    if self._looks_like_text(decoded):
                        results.append({
                            'type': ' -> '.join(new_chain),
                            'decoded': decoded,
                            'chain': new_chain
                        })
                    try_decode(decoded, new_chain, depth + 1)

        try_decode(text, [], 0)
        return results

    # ==================== FILE ANALYSIS ====================

    def analyze_file(self, filepath, flag_format=None):
        """Analyze a file containing encoded strings"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except FileNotFoundError:
            return f"Error: File '{filepath}' not found."
        except Exception as e:
            return f"Error reading file: {e}"

        results = []
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            self.log(f"\nLine {i}: {line[:50]}{'...' if len(line) > 50 else ''}")

            if flag_format:
                line_results = self.analyze_with_flag_format(line, flag_format)
            else:
                line_results = self.analyze(line)

            if line_results:
                results.append({
                    'line': i,
                    'original': line,
                    'results': line_results
                })

        return self._generate_report(results)

    def _generate_report(self, results):
        """Generate analysis report"""
        lines = ["=" * 50, "CRYPTO ANALYSIS REPORT", "=" * 50, ""]

        for entry in results:
            lines.append(f"Line {entry['line']}:")
            lines.append(f"  Original: {entry['original'][:80]}...")
            lines.append("  Results:")

            for r in entry['results']:
                if 'decoded' in r:
                    decoded = r['decoded']
                    if isinstance(decoded, list):
                        lines.append(f"    [{r['type']}]")
                        for item in decoded[:5]:
                            lines.append(f"      {item}")
                    else:
                        preview = str(decoded)[:100]
                        lines.append(f"    [{r['type']}]: {preview}")
                elif 'possible_types' in r:
                    lines.append(f"    [Hash]: {', '.join(r['possible_types'])}")
            lines.append("")

        lines.append("=" * 50)
        lines.append(f"Total entries analyzed: {len(results)}")
        lines.append("=" * 50)

        return '\n'.join(lines)

    def save_report(self, report, filepath):
        """Save report to file"""
        try:
            with open(filepath, 'w') as f:
                f.write(report)
            return f"Report saved to {filepath}"
        except Exception as e:
            return f"Error saving report: {e}"


# ==================== CLI INTERFACE ====================

def print_banner():
    """Print banner"""
    print("""
   ____ _       _               ___
  / ___(_)_ __ | |__   ___ _ __/ _ \\ _ __  ___
 | |   | | '_ \\| '_ \\ / _ \\ '__| | | | '_ \\/ __|
 | |___| | |_) | | | |  __/ |  | |_| | |_) \\__ \\
  \\____|_| .__/|_| |_|\\___|_|   \\___/| .__/|___/
         |_|                         |_|
    CTF Crypto Analyzer
    """)


def print_results(results):
    """Pretty print analysis results"""
    if not results:
        print("\n[-] No patterns detected.")
        return

    print("\n[+] Analysis Results:")
    print("-" * 40)

    for r in results:
        rtype = r.get('type', 'unknown')
        decoded = r.get('decoded')

        if decoded:
            if isinstance(decoded, list):
                print(f"\n  [{rtype}]")
                for item in decoded[:10]:
                    if isinstance(item, tuple):
                        print(f"    {item[0]}: {item[1]}")
                    else:
                        print(f"    {item}")
            elif isinstance(decoded, str):
                preview = decoded[:200] + '...' if len(decoded) > 200 else decoded
                print(f"\n  [{rtype}]: {preview}")
            else:
                print(f"\n  [{rtype}]: {decoded}")

        if 'possible_types' in r:
            print(f"\n  [Hash Detection]: {', '.join(r['possible_types'])}")

        if 'key' in r:
            print(f"    Key: {r['key']}")


def main():
    """Main CLI interface"""
    print_banner()
    analyzer = CryptoAnalyzer()

    while True:
        print("\n" + "=" * 40)
        print("CTF Crypto Analyzer")
        print("=" * 40)
        print("1. Analyze text")
        print("2. Try combined encodings")
        print("3. Analyze with flag format")
        print("4. Analyze file")
        print("5. Frequency analysis")
        print("6. Crack substitution cipher")
        print("7. Quit")
        print("=" * 40)

        choice = input("\nSelect option (1-7): ").strip()

        if choice == '7':
            print("\nGoodbye!")
            break

        elif choice == '1':
            text = input("\nEnter ciphertext: ").strip()
            if text:
                results = analyzer.analyze(text)
                print_results(results)

        elif choice == '2':
            text = input("\nEnter ciphertext: ").strip()
            if text:
                results = analyzer.try_combined_encodings(text)
                print_results(results)

        elif choice == '3':
            text = input("\nEnter ciphertext: ").strip()
            fmt = input("Enter flag format (e.g., 'flag{}'): ").strip() or "flag{}"
            if text:
                results = analyzer.analyze_with_flag_format(text, fmt)
                print_results(results)

        elif choice == '4':
            filepath = input("\nEnter file path: ").strip()
            fmt = input("Flag format (press Enter to skip): ").strip() or None
            report = analyzer.analyze_file(filepath, fmt)
            print(report)

            save = input("\nSave report? (y/n): ").strip().lower()
            if save == 'y':
                out_path = input("Output file path: ").strip()
                print(analyzer.save_report(report, out_path))

        elif choice == '5':
            text = input("\nEnter text: ").strip()
            if text:
                freq = analyzer.frequency_analysis(text)
                print("\nFrequency Analysis:")
                for char, pct in list(freq.items())[:15]:
                    print(f"  {char}: {pct:.2f}%")

        elif choice == '6':
            text = input("\nEnter ciphertext: ").strip()
            if text:
                result = analyzer.crack_substitution(text)
                print(f"\nPossible decryption:\n{result}")

        else:
            print("\nInvalid option.")


if __name__ == "__main__":
    main()
