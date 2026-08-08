"""
cli.py
Command-line interface for the steganography tool.

Examples:
    python cli.py encode -i cover.png -o secret.png -m "meet at dawn"
    python cli.py encode -i cover.png -o secret.png -m "meet at dawn" --encrypt
    python cli.py decode -i secret.png
    python cli.py decode -i secret.png --encrypt
    python cli.py capacity -i cover.png
"""

import argparse
import getpass
import sys

import stego
from stego import StegoError


def cmd_encode(args):
    message = args.message.encode("utf-8")

    if args.encrypt:
        import crypto_layer
        password = args.password or getpass.getpass("Password to encrypt message: ")
        message = crypto_layer.encrypt(message, password)

    try:
        stego.encode(args.input, args.output, message)
    except StegoError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[+] Message hidden successfully -> {args.output}")
    if args.encrypt:
        print("[+] Message was encrypted before hiding (password required to decode).")


def cmd_decode(args):
    try:
        raw = stego.decode(args.input)
    except StegoError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if args.encrypt:
        import crypto_layer
        password = args.password or getpass.getpass("Password to decrypt message: ")
        try:
            raw = crypto_layer.decrypt(raw, password)
        except crypto_layer.CryptoError as e:
            print(f"[!] {e}")
            sys.exit(1)

    try:
        print("[+] Hidden message:")
        print(raw.decode("utf-8"))
    except UnicodeDecodeError:
        # message wasn't text (e.g. wrong password produced garbage, or binary payload)
        print("[!] Decoded bytes are not valid UTF-8 text. Raw bytes:")
        print(raw)


def cmd_capacity(args):
    report = stego.capacity_report(args.input)
    print(f"Image: {args.input}")
    print(f"Dimensions: {report['width']}x{report['height']}")
    print(f"Max hidden message size: {report['max_message_bytes']} bytes "
          f"(~{report['max_message_chars_approx']} characters)")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="stego",
        description="Hide and extract secret messages inside PNG images using LSB steganography."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_encode = sub.add_parser("encode", help="Hide a message inside an image")
    p_encode.add_argument("-i", "--input", required=True, help="Path to cover image")
    p_encode.add_argument("-o", "--output", required=True, help="Path to save the stego image (PNG)")
    p_encode.add_argument("-m", "--message", required=True, help="Secret message to hide")
    p_encode.add_argument("--encrypt", action="store_true", help="Encrypt message with a password before hiding")
    p_encode.add_argument("--password", help="Password for --encrypt (omit to be prompted securely)")
    p_encode.set_defaults(func=cmd_encode)

    p_decode = sub.add_parser("decode", help="Extract a hidden message from an image")
    p_decode.add_argument("-i", "--input", required=True, help="Path to stego image")
    p_decode.add_argument("--encrypt", action="store_true", help="Decrypt the extracted payload with a password")
    p_decode.add_argument("--password", help="Password for --encrypt (omit to be prompted securely)")
    p_decode.set_defaults(func=cmd_decode)

    p_capacity = sub.add_parser("capacity", help="Check how much a given image can hide")
    p_capacity.add_argument("-i", "--input", required=True, help="Path to image")
    p_capacity.set_defaults(func=cmd_capacity)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
