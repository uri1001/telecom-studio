"""Tests for src/theory/entropy.py"""

import math
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.theory.entropy import calculate_entropy, file_entropy, is_random


class TestCalculateEntropy(unittest.TestCase):
    """Tests for calculate_entropy()."""

    def test_empty_data(self):
        self.assertEqual(calculate_entropy(b''), 0.0)

    def test_single_byte_repeated(self):
        # all same bytes => zero entropy
        self.assertEqual(calculate_entropy(b'AAAA'), 0.0)

    def test_two_distinct_bytes_equal(self):
        # 50/50 split => 1 bit of entropy
        data = b'AB' * 100
        self.assertAlmostEqual(calculate_entropy(data), 1.0, places=5)

    def test_all_256_bytes(self):
        # uniform distribution => maximum entropy = 8.0
        data = bytes(range(256))
        self.assertAlmostEqual(calculate_entropy(data), 8.0, places=5)

    def test_entropy_range(self):
        # entropy must be between 0 and 8 for any input
        data = b'Hello World!'
        e = calculate_entropy(data)
        self.assertGreaterEqual(e, 0.0)
        self.assertLessEqual(e, 8.0)

    def test_single_byte(self):
        self.assertEqual(calculate_entropy(b'X'), 0.0)

    def test_two_different_bytes(self):
        # exactly two bytes => 1 bit
        self.assertAlmostEqual(calculate_entropy(b'AB'), 1.0, places=5)

    def test_more_variety_higher_entropy(self):
        low = calculate_entropy(b'AAAB')
        high = calculate_entropy(b'ABCD')
        self.assertGreater(high, low)

    def test_deterministic(self):
        data = os.urandom(256)
        self.assertEqual(calculate_entropy(data), calculate_entropy(data))


class TestFileEntropy(unittest.TestCase):
    """Tests for file_entropy()."""

    def test_readable_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bytes(range(256)))
            path = f.name
        try:
            self.assertAlmostEqual(file_entropy(path), 8.0, places=5)
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        result = file_entropy('/nonexistent/path/file.bin')
        self.assertEqual(result, 0.0)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            result = file_entropy(path)
            self.assertEqual(result, 0.0)
        finally:
            os.unlink(path)

    def test_bug3_ambiguity(self):
        """Bug #3: file_entropy returns 0.0 for both missing and empty files.
        Caller cannot distinguish the two cases."""
        missing = file_entropy('/nonexistent/file')
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            empty = file_entropy(path)
        finally:
            os.unlink(path)
        # both return 0.0 -- this documents the ambiguity bug
        self.assertEqual(missing, empty)
        self.assertEqual(missing, 0.0)


class TestIsRandom(unittest.TestCase):
    """Tests for is_random()."""

    def test_random_data(self):
        data = bytes(range(256)) * 100
        self.assertTrue(is_random(data))

    def test_non_random_data(self):
        self.assertFalse(is_random(b'AAAAAAA'))

    def test_custom_threshold(self):
        data = b'Hello World!'
        # low threshold should pass
        self.assertTrue(is_random(data, threshold=1.0))
        # high threshold should fail
        self.assertFalse(is_random(data, threshold=7.5))

    def test_empty_data(self):
        self.assertFalse(is_random(b''))


if __name__ == '__main__':
    unittest.main()
