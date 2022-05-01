"""Tests for src/theory/error.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.theory.error import (
    add_parity_bit,
    check_parity,
    hamming_distance,
    remove_parity_bits,
)


class TestHammingDistance(unittest.TestCase):
    """Tests for hamming_distance()."""

    def test_identical_strings(self):
        self.assertEqual(hamming_distance('abc', 'abc'), 0)

    def test_all_different(self):
        self.assertEqual(hamming_distance('000', '111'), 3)

    def test_partial_difference(self):
        self.assertEqual(hamming_distance('karolin', 'kathrin'), 3)

    def test_binary_strings(self):
        self.assertEqual(hamming_distance('1011101', '1001001'), 2)

    def test_single_char(self):
        self.assertEqual(hamming_distance('a', 'b'), 1)
        self.assertEqual(hamming_distance('a', 'a'), 0)

    def test_unequal_length_raises(self):
        with self.assertRaises(ValueError):
            hamming_distance('abc', 'ab')

    def test_empty_strings(self):
        self.assertEqual(hamming_distance('', ''), 0)

    def test_case_sensitive(self):
        self.assertEqual(hamming_distance('A', 'a'), 1)


class TestAddParityBit(unittest.TestCase):
    """Tests for add_parity_bit()."""

    def test_output_length(self):
        data = b'Hello'
        result = add_parity_bit(data)
        self.assertEqual(len(result), len(data) * 2)

    def test_empty_input(self):
        self.assertEqual(add_parity_bit(b''), b'')

    def test_even_ones_parity_zero(self):
        # 0b00000011 has 2 ones (even) => parity = 0
        result = add_parity_bit(bytes([0b00000011]))
        self.assertEqual(result[1], 0)

    def test_odd_ones_parity_one(self):
        # 0b00000001 has 1 one (odd) => parity = 1
        result = add_parity_bit(bytes([0b00000001]))
        self.assertEqual(result[1], 1)

    def test_zero_byte(self):
        # 0x00 has 0 ones => parity = 0
        result = add_parity_bit(bytes([0]))
        self.assertEqual(result[1], 0)

    def test_all_ones_byte(self):
        # 0xFF has 8 ones (even) => parity = 0
        result = add_parity_bit(bytes([0xFF]))
        self.assertEqual(result[1], 0)


class TestCheckParity(unittest.TestCase):
    """Tests for check_parity()."""

    def test_valid_parity(self):
        data = b'Hello'
        with_parity = add_parity_bit(data)
        self.assertTrue(check_parity(with_parity))

    def test_corrupted_data(self):
        data = b'Hello'
        with_parity = bytearray(add_parity_bit(data))
        with_parity[0] ^= 1  # flip one bit in first data byte
        self.assertFalse(check_parity(bytes(with_parity)))

    def test_odd_length_fails(self):
        self.assertFalse(check_parity(b'\x00\x00\x00'))

    def test_empty_data(self):
        self.assertTrue(check_parity(b''))


class TestRemoveParityBits(unittest.TestCase):
    """Tests for remove_parity_bits()."""

    def test_roundtrip(self):
        original = b'Hello World!'
        with_parity = add_parity_bit(original)
        recovered = remove_parity_bits(with_parity)
        self.assertEqual(recovered, original)

    def test_odd_length_raises(self):
        with self.assertRaises(ValueError):
            remove_parity_bits(b'\x00\x00\x00')

    def test_empty_data(self):
        self.assertEqual(remove_parity_bits(b''), b'')

    def test_single_byte_roundtrip(self):
        for byte_val in [0, 1, 127, 255]:
            original = bytes([byte_val])
            recovered = remove_parity_bits(add_parity_bit(original))
            self.assertEqual(recovered, original)

    def test_full_pipeline(self):
        """add -> check -> remove roundtrip."""
        original = bytes(range(256))
        with_parity = add_parity_bit(original)
        self.assertTrue(check_parity(with_parity))
        recovered = remove_parity_bits(with_parity)
        self.assertEqual(recovered, original)


if __name__ == '__main__':
    unittest.main()
