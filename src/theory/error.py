"""
Error correction module with simple implementations.
Following KISS principle - clear over clever.
"""


def hamming_distance(str1: str, str2: str) -> int:
    """
    Calculate Hamming distance between two strings.

    Args:
        str1: First string
        str2: Second string

    Returns:
        Number of positions where characters differ
    """
    if len(str1) != len(str2):
        raise ValueError("Strings must have equal length")

    distance = 0
    for c1, c2 in zip(str1, str2):
        if c1 != c2:
            distance += 1

    return distance


def add_parity_bit(data: bytes) -> bytes:
    """
    Add even parity bit to each byte.

    Args:
        data: Input bytes

    Returns:
        Data with parity bits added (9 bits per original byte)
    """
    result = []

    for byte in data:
        # Count number of 1 bits
        ones_count = bin(byte).count('1')

        # Add parity bit (1 if odd number of ones, 0 if even)
        parity = ones_count % 2

        # Pack byte and parity bit
        # Store as two bytes: original byte + parity byte (0 or 1)
        result.append(byte)
        result.append(parity)

    return bytes(result)


def check_parity(data: bytes) -> bool:
    """
    Check if data with parity bits is valid.

    Args:
        data: Data with parity bits (must have even length)

    Returns:
        True if all parity checks pass, False otherwise
    """
    if len(data) % 2 != 0:
        return False

    for i in range(0, len(data), 2):
        byte = data[i]
        parity = data[i + 1]

        # Check if parity matches
        ones_count = bin(byte).count('1')
        expected_parity = ones_count % 2

        if parity != expected_parity:
            return False

    return True


def remove_parity_bits(data: bytes) -> bytes:
    """
    Remove parity bits from data.

    Args:
        data: Data with parity bits

    Returns:
        Original data without parity bits
    """
    if len(data) % 2 != 0:
        raise ValueError("Data must have even length")

    result = []
    for i in range(0, len(data), 2):
        result.append(data[i])

    return bytes(result)


# Simple test
if __name__ == "__main__":
    print("Error Correction Tests:")
    print("-" * 40)

    # Test Hamming distance
    pairs = [
        ("000", "111"),
        ("karolin", "kathrin"),
        ("1011101", "1001001"),
    ]

    print("Hamming Distance:")
    for s1, s2 in pairs:
        distance = hamming_distance(s1, s2)
        print(f"  '{s1}' <-> '{s2}': {distance}")

    print("\nParity Bit Tests:")

    # Test parity bits
    test_data = b"Hello"
    print(f"  Original: {test_data}")

    # Add parity
    with_parity = add_parity_bit(test_data)
    print(f"  With parity: {len(with_parity)} bytes")

    # Check parity
    is_valid = check_parity(with_parity)
    print(f"  Parity valid: {is_valid}")

    # Corrupt data
    corrupted = bytearray(with_parity)
    corrupted[0] ^= 1  # Flip one bit
    is_valid_corrupted = check_parity(bytes(corrupted))
    print(f"  Corrupted parity valid: {is_valid_corrupted}")

    # Remove parity
    recovered = remove_parity_bits(with_parity)
    print(f"  Recovered: {recovered}")