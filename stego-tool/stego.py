"""
stego.py
Core LSB (Least Significant Bit) image steganography engine.

How it works:
    Every pixel in an image has color channels (R, G, B[, A]), each stored
    as an 8-bit integer (0-255). The least significant bit (the last bit)
    of each channel barely affects the visible color -- changing it shifts
    a value by at most 1/255. We exploit this: we overwrite the LSB of
    each channel with one bit of our secret message. To the eye, nothing
    changes. To a program reading raw bits, the message is right there.

Message framing:
    [32-bit big-endian length header][message bytes][optional encryption]
    The header tells decode() exactly how many bits to read, so we don't
    need a delimiter sequence that could collide with message content.
"""

from PIL import Image
from utils import bytes_to_bits, bits_to_bytes, calculate_capacity_bytes


class StegoError(Exception):
    """Raised for capacity, format, or corruption problems."""
    pass


HEADER_BITS = 32  # bits used to store the message length


def encode(input_path: str, output_path: str, message: bytes) -> None:
    """
    Hide `message` (bytes) inside the image at input_path, saving the
    result as a lossless PNG at output_path.
    """
    img = Image.open(input_path)
    img = img.convert("RGB")  # normalize; drops alpha, ensures 3 channels
    pixels = img.load()
    width, height = img.size

    capacity = calculate_capacity_bytes(width, height, channels=3, header_bits=HEADER_BITS)
    if len(message) > capacity:
        raise StegoError(
            f"Message too large: {len(message)} bytes, but this image can "
            f"only hold {capacity} bytes. Use a bigger image or shorter message."
        )

    header_bits = format(len(message), f"0{HEADER_BITS}b")
    message_bits = bytes_to_bits(message)
    all_bits = header_bits + message_bits

    bit_index = 0
    total_bits = len(all_bits)

    for y in range(height):
        for x in range(width):
            if bit_index >= total_bits:
                break
            r, g, b = pixels[x, y]
            channel_values = [r, g, b]

            for c in range(3):
                if bit_index >= total_bits:
                    break
                bit = int(all_bits[bit_index])
                # clear the LSB, then set it to our bit
                channel_values[c] = (channel_values[c] & 0xFE) | bit
                bit_index += 1

            pixels[x, y] = tuple(channel_values)
        if bit_index >= total_bits:
            break

    img.save(output_path, "PNG")


def decode(input_path: str) -> bytes:
    """
    Extract a hidden message (bytes) from the image at input_path.
    Raises StegoError if no valid header/message is found.
    """
    img = Image.open(input_path)
    img = img.convert("RGB")
    pixels = img.load()
    width, height = img.size

    bits = []
    needed = HEADER_BITS  # grows once we know the message length
    message_length_bytes = None

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            for channel_value in (r, g, b):
                bits.append(str(channel_value & 1))

                if message_length_bytes is None and len(bits) == HEADER_BITS:
                    header = "".join(bits)
                    message_length_bytes = int(header, 2)
                    needed = HEADER_BITS + message_length_bytes * 8
                    bits = []  # discard header bits, start collecting message

                elif message_length_bytes is not None and len(bits) == message_length_bytes * 8:
                    return bits_to_bytes("".join(bits))

    raise StegoError("No hidden message found (image too small or not encoded by this tool).")


def capacity_report(input_path: str) -> dict:
    """Return capacity info for an image without modifying it."""
    img = Image.open(input_path).convert("RGB")
    width, height = img.size
    capacity_bytes = calculate_capacity_bytes(width, height, channels=3, header_bits=HEADER_BITS)
    return {
        "width": width,
        "height": height,
        "max_message_bytes": capacity_bytes,
        "max_message_chars_approx": capacity_bytes,  # ASCII ~1 byte/char
    }
