"""
Huffman encoding/decoding for data compression.
Simple implementation following KISS principle.
"""

import heapq
from collections import Counter, defaultdict


class HuffmanNode:
    """Simple node for Huffman tree."""

    def __init__(self, char=None, freq=0, left=None, right=None):
        self.char = char
        self.freq = freq
        self.left = left
        self.right = right

    def __lt__(self, other):
        return self.freq < other.freq


def build_huffman_tree(text: str) -> HuffmanNode:
    """
    Build Huffman tree from text.

    Args:
        text: Input text to compress

    Returns:
        Root node of Huffman tree
    """
    # Count character frequencies
    frequency = Counter(text)

    # Create leaf nodes
    heap = []
    for char, freq in frequency.items():
        node = HuffmanNode(char=char, freq=freq)
        heapq.heappush(heap, node)

    # Build tree
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)

        parent = HuffmanNode(freq=left.freq + right.freq, left=left, right=right)
        heapq.heappush(heap, parent)

    return heap[0] if heap else None


def generate_codes(root: HuffmanNode) -> dict:
    """
    Generate Huffman codes from tree.

    Args:
        root: Root of Huffman tree

    Returns:
        Dictionary mapping characters to binary codes
    """
    if not root:
        return {}

    codes = {}

    def traverse(node, code=""):
        if node:
            # Leaf node
            if node.char is not None:
                codes[node.char] = code if code else "0"
            else:
                traverse(node.left, code + "0")
                traverse(node.right, code + "1")

    traverse(root)
    return codes


def huffman_encode(text: str) -> tuple:
    """
    Encode text using Huffman coding.

    Args:
        text: Text to encode

    Returns:
        Tuple of (encoded binary string, Huffman codes dictionary)
    """
    if not text:
        return "", {}

    # Special case: single character
    if len(set(text)) == 1:
        codes = {text[0]: "0"}
        encoded = "0" * len(text)
        return encoded, codes

    # Build tree and generate codes
    root = build_huffman_tree(text)
    codes = generate_codes(root)

    # Encode text
    encoded = "".join(codes[char] for char in text)

    return encoded, codes


def huffman_decode(encoded: str, codes: dict) -> str:
    """
    Decode Huffman encoded data.

    Args:
        encoded: Binary string of encoded data
        codes: Huffman codes dictionary

    Returns:
        Decoded text
    """
    if not encoded or not codes:
        return ""

    # Reverse the codes dictionary
    decode_dict = {code: char for char, code in codes.items()}

    decoded = []
    current_code = ""

    for bit in encoded:
        current_code += bit
        if current_code in decode_dict:
            decoded.append(decode_dict[current_code])
            current_code = ""

    return "".join(decoded)


def compression_ratio(original: bytes, compressed: bytes) -> float:
    """
    Calculate compression ratio.

    Args:
        original: Original data
        compressed: Compressed data

    Returns:
        Compression ratio (1.0 = no compression, higher = better)
    """
    if not compressed:
        return 0.0

    return len(original) / len(compressed)


def encode_to_bytes(encoded: str) -> bytes:
    """
    Convert binary string to bytes.

    Args:
        encoded: Binary string

    Returns:
        Packed bytes
    """
    # Pad to multiple of 8
    padding = 8 - (len(encoded) % 8)
    if padding != 8:
        encoded = encoded + "0" * padding

    # Convert to bytes
    result = []
    for i in range(0, len(encoded), 8):
        byte = int(encoded[i:i+8], 2)
        result.append(byte)

    return bytes(result)


# Simple test
if __name__ == "__main__":
    print("Huffman Compression Tests:")
    print("-" * 40)

    test_texts = [
        "AAAAAAA",
        "ABCDEFGH",
        "Hello World!",
        "the quick brown fox jumps over the lazy dog",
    ]

    for text in test_texts:
        print(f"\nOriginal: '{text}'")
        print(f"  Size: {len(text)} bytes")

        # Encode
        encoded, codes = huffman_encode(text)
        encoded_bytes = encode_to_bytes(encoded)

        print(f"  Encoded bits: {len(encoded)}")
        print(f"  Encoded bytes: {len(encoded_bytes)}")

        # Compression ratio
        ratio = compression_ratio(text.encode(), encoded_bytes)
        print(f"  Compression ratio: {ratio:.2f}x")

        # Decode
        decoded = huffman_decode(encoded, codes)
        print(f"  Decoded: '{decoded}'")
        print(f"  Match: {decoded == text}")

        # Show codes for small texts
        if len(text) <= 12:
            print("  Huffman codes:")
            for char, code in sorted(codes.items()):
                print(f"    '{char}': {code}")