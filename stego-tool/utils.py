"""
utils.py
Small, dependency-free helpers used by stego.py.
Kept separate so the bit-twiddling logic is easy to unit test on its own.
"""


def bytes_to_bits(data: bytes) -> str:
    """Convert bytes to a string of '0'/'1' characters, 8 bits per byte."""
    return "".join(format(byte, "08b") for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    """Convert a string of '0'/'1' characters back into bytes."""
    if len(bits) % 8 != 0:
        raise ValueError("Bit string length must be a multiple of 8.")
    byte_chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    return bytes(int(chunk, 2) for chunk in byte_chunks)


def calculate_capacity_bytes(width: int, height: int, channels: int = 3, header_bits: int = 32) -> int:
    """
    How many bytes of message can this image hold, after reserving
    `header_bits` for the length header?
    """
    total_bits = width * height * channels
    usable_bits = total_bits - header_bits
    return max(usable_bits // 8, 0)
