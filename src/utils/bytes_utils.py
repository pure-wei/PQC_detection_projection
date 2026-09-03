"""Byte utility functions."""


def hexify(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def unhexify(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def format_bytes(num_bytes: int) -> str:
    """Format byte count to human-readable string."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    else:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
