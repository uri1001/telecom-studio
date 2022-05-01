"""Tests for src/theory/huffman.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.theory.huffman import (
    build_huffman_tree,
    compression_ratio,
    encode_to_bytes,
    generate_codes,
    huffman_decode,
    huffman_encode,
)


class TestBuildHuffmanTree(unittest.TestCase):
    """Tests for build_huffman_tree()."""

    def test_single_char(self):
        root = build_huffman_tree('A')
        self.assertIsNotNone(root)
        self.assertEqual(root.char, 'A')
        self.assertEqual(root.freq, 1)

    def test_two_chars(self):
        root = build_huffman_tree('AB')
        self.assertIsNotNone(root)
        self.assertIsNone(root.char)  # internal node
        self.assertEqual(root.freq, 2)

    def test_empty_string(self):
        root = build_huffman_tree('')
        self.assertIsNone(root)

    def test_frequency_sum(self):
        root = build_huffman_tree('AAABBC')
        self.assertEqual(root.freq, 6)


class TestGenerateCodes(unittest.TestCase):
    """Tests for generate_codes()."""

    def test_none_root(self):
        self.assertEqual(generate_codes(None), {})

    def test_single_char_gets_code(self):
        root = build_huffman_tree('A')
        codes = generate_codes(root)
        self.assertIn('A', codes)
        # single char gets '0'
        self.assertEqual(codes['A'], '0')

    def test_all_codes_are_binary(self):
        root = build_huffman_tree('the quick brown fox')
        codes = generate_codes(root)
        for code in codes.values():
            self.assertTrue(all(c in '01' for c in code))

    def test_prefix_free(self):
        """No code should be a prefix of another (prefix-free property)."""
        root = build_huffman_tree('abcdefghij')
        codes = generate_codes(root)
        code_list = sorted(codes.values())
        for i in range(len(code_list)):
            for j in range(i + 1, len(code_list)):
                self.assertFalse(code_list[j].startswith(code_list[i]))


class TestHuffmanEncode(unittest.TestCase):
    """Tests for huffman_encode()."""

    def test_empty_string(self):
        encoded, codes = huffman_encode('')
        self.assertEqual(encoded, '')
        self.assertEqual(codes, {})

    def test_single_char_repeated(self):
        encoded, codes = huffman_encode('AAAAAAA')
        self.assertEqual(encoded, '0000000')
        self.assertEqual(codes, {'A': '0'})

    def test_encodes_to_binary_string(self):
        encoded, codes = huffman_encode('Hello World!')
        self.assertTrue(all(c in '01' for c in encoded))

    def test_all_chars_have_codes(self):
        text = 'ABCDE'
        _, codes = huffman_encode(text)
        for c in set(text):
            self.assertIn(c, codes)


class TestHuffmanDecode(unittest.TestCase):
    """Tests for huffman_decode()."""

    def test_empty_encoded(self):
        self.assertEqual(huffman_decode('', {'A': '0'}), '')

    def test_empty_codes(self):
        self.assertEqual(huffman_decode('010', {}), '')

    def test_roundtrip(self):
        texts = [
            'Hello World!',
            'AAAAAAA',
            'abcdefghijklmnop',
            'the quick brown fox jumps over the lazy dog',
        ]
        for text in texts:
            encoded, codes = huffman_encode(text)
            decoded = huffman_decode(encoded, codes)
            self.assertEqual(decoded, text, f'roundtrip failed for: {text!r}')

    def test_single_char_roundtrip(self):
        encoded, codes = huffman_encode('X')
        decoded = huffman_decode(encoded, codes)
        self.assertEqual(decoded, 'X')


class TestCompressionRatio(unittest.TestCase):
    """Tests for compression_ratio()."""

    def test_empty_compressed(self):
        self.assertEqual(compression_ratio(b'hello', b''), 0.0)

    def test_no_compression(self):
        data = b'hello'
        self.assertAlmostEqual(compression_ratio(data, data), 1.0)

    def test_compression_better_than_one(self):
        original = b'A' * 100
        compressed = b'A' * 10
        self.assertAlmostEqual(compression_ratio(original, compressed), 10.0)

    def test_expansion(self):
        original = b'AB'
        compressed = b'ABCD'
        self.assertAlmostEqual(compression_ratio(original, compressed), 0.5)


class TestEncodeToBytes(unittest.TestCase):
    """Tests for encode_to_bytes()."""

    def test_eight_bits(self):
        result = encode_to_bytes('10000001')
        self.assertEqual(result, bytes([0b10000001]))

    def test_padding(self):
        # 4 bits -> padded to 8 bits
        result = encode_to_bytes('1010')
        self.assertEqual(len(result), 1)
        # '1010' + '0000' padding = 0b10100000 = 160
        self.assertEqual(result[0], 0b10100000)

    def test_empty_string(self):
        result = encode_to_bytes('')
        self.assertEqual(result, b'')

    def test_sixteen_bits(self):
        result = encode_to_bytes('1111111100000000')
        self.assertEqual(result, bytes([0xFF, 0x00]))

    def test_bug4_padding_info_lost(self):
        """Bug #4: encode_to_bytes adds padding but doesn't record how many
        bits were padded. Decoding from bytes cannot reconstruct the exact
        original bitstring."""
        original_bits = '10101'  # 5 bits
        packed = encode_to_bytes(original_bits)
        # unpack back to bits
        unpacked = ''.join(f'{b:08b}' for b in packed)
        # unpacked is 8 bits, not 5 -- padding info is lost
        self.assertEqual(len(unpacked), 8)
        self.assertNotEqual(len(unpacked), len(original_bits))
        # the first 5 bits match, but we have no way to know it was 5
        self.assertTrue(unpacked.startswith(original_bits))


if __name__ == '__main__':
    unittest.main()
