import argparse
from modules import encryption, decryption, key_analysis

def main():
    parser = argparse.ArgumentParser(description="Cryptography Toolkit for CTFs")
    
    subparsers = parser.add_subparsers(dest='command')

    # Encryption Command
    encrypt_parser = subparsers.add_parser('encrypt', help="Encrypt a message")
    encrypt_parser.add_argument('--method', type=str, required=True, help="Encryption method (e.g., caesar, rsa, aes)")
    encrypt_parser.add_argument('--input', type=str, required=True, help="Input message or file")
    encrypt_parser.add_argument('--key', type=str, help="Encryption key")
    encrypt_parser.add_argument('--output', type=str, help="Output file to save the encrypted message")

    # Decryption Command
    decrypt_parser = subparsers.add_parser('decrypt', help="Decrypt a message")
    decrypt_parser.add_argument('--method', type=str, required=True, help="Decryption method (e.g., caesar, rsa, aes)")
    decrypt_parser.add_argument('--input', type=str, required=True, help="Input message or file")
    decrypt_parser.add_argument('--key', type=str, help="Decryption key")
    decrypt_parser.add_argument('--output', type=str, help="Output file to save the decrypted message")

    # Key Analysis Command
    key_parser = subparsers.add_parser('analyze-key', help="Analyze and discover key types")
    key_parser.add_argument('--input', type=str, required=True, help="Input message or ciphertext")
    key_parser.add_argument('--output', type=str, help="Output file to save the analysis result")

    args = parser.parse_args()

    if args.command == 'encrypt':
        encryption.encrypt(args)
    elif args.command == 'decrypt':
        decryption.decrypt(args)
    elif args.command == 'analyze-key':
        key_analysis.analyze(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
