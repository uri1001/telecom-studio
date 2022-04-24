"""
Entropy analysis module for information theory calculations.
Simple implementation following KISS principle.
"""

import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy value (0-8 bits per byte)
    """
    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = Counter(data)
    data_len = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)

    return entropy


def file_entropy(filepath: str) -> float:
    """
    Calculate entropy of a file.

    Args:
        filepath: Path to the file

    Returns:
        Entropy value (0-8 bits per byte)
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        return calculate_entropy(data)
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found")
        return 0.0
    except Exception as e:
        print(f"Error reading file: {e}")
        return 0.0


def is_random(data: bytes, threshold: float = 7.0) -> bool:
    """
    Check if data appears to be random based on entropy.

    Args:
        data: Bytes to check
        threshold: Minimum entropy for randomness (default 7.0)

    Returns:
        True if data appears random, False otherwise
    """
    entropy = calculate_entropy(data)
    return entropy >= threshold


# Simple test
if __name__ == "__main__":
    # Test with different types of data
    test_data = [
        (b"AAAAAAAA", "Repetitive"),
        (b"ABCDEFGH", "Sequential"),
        (bytes(range(256)), "All bytes"),
        (b"Hello World!", "Text"),
    ]

    print("Entropy Analysis Tests:")
    print("-" * 40)
    for data, description in test_data:
        entropy = calculate_entropy(data)
        random = is_random(data)
        print(f"{description:15} | Entropy: {entropy:.4f} | Random: {random}")