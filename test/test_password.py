#!/usr/bin/env python3
"""
test_password.py - Comprehensive tests for password strength analysis module.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.security.password import (
    analyze_strength, estimate_crack_time, check_known_patterns,
    generate_passphrase, hash_check, _format_duration,
    COMMON_PASSWORDS, LEET_MAP, WORD_LIST,
)


class TestAnalyzeStrength(unittest.TestCase):
    """tests for the analyze_strength function."""

    def test_empty_password(self):
        result = analyze_strength('')
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['rating'], 'very_weak')
        self.assertIn('password cannot be empty', result['suggestions'])

    def test_common_password(self):
        result = analyze_strength('password')
        # 'password' is only lowercase, 8 chars -> modest score, no higher than fair
        self.assertIn(result['rating'], ('weak', 'very_weak', 'fair'))
        self.assertLess(result['score'], 60)

    def test_strong_password(self):
        result = analyze_strength('X9#kL2!mP@4q')
        self.assertGreaterEqual(result['score'], 60)
        self.assertIn(result['rating'], ('strong', 'very_strong'))

    def test_score_clamped_lower_bound(self):
        # a very short, terrible password should never go below 0
        result = analyze_strength('a')
        self.assertGreaterEqual(result['score'], 0)

    def test_score_clamped_upper_bound(self):
        # even an extremely strong password should never exceed 100
        result = analyze_strength('X9#kL2!mP@4qZ8&rW5*yT1$oN3^hB7+c')
        self.assertLessEqual(result['score'], 100)

    def test_character_flags(self):
        result = analyze_strength('Abc123!@')
        self.assertTrue(result['has_uppercase'])
        self.assertTrue(result['has_lowercase'])
        self.assertTrue(result['has_digits'])
        self.assertTrue(result['has_special'])

    def test_sequential_chars_detected(self):
        result = analyze_strength('xyzabc999')
        self.assertGreater(result['sequential_chars'], 0)

    def test_repeated_chars_detected(self):
        result = analyze_strength('paAAAsword')
        # 'AAA' is 3 consecutive identical chars -> repeated_chars >= 1
        self.assertGreater(result['repeated_chars'], 0)

    def test_keyboard_walk_in_common_patterns(self):
        result = analyze_strength('myqwertypass')
        pattern_strs = ' '.join(result['common_patterns'])
        self.assertIn('keyboard walk', pattern_strs)

    def test_year_pattern_detected(self):
        result = analyze_strength('secret2024!')
        self.assertIn('year pattern detected', result['common_patterns'])

    def test_long_password_bonus(self):
        short = analyze_strength('Ab1!Ab1!Ab1!')   # 12 chars, no bonus
        long = analyze_strength('Ab1!Ab1!Ab1!X')   # 13 chars, gets bonus
        # the long password has strictly more length points + bonus
        self.assertGreater(long['score'], short['score'])

    def test_status_success(self):
        result = analyze_strength('anypassword')
        self.assertEqual(result['status'], 'success')


class TestEstimateCrackTime(unittest.TestCase):
    """tests for the estimate_crack_time function."""

    def test_empty_password(self):
        result = estimate_crack_time('')
        self.assertEqual(result['entropy_bits'], 0)
        self.assertEqual(result['online_attack'], 'instant')
        self.assertEqual(result['offline_slow'], 'instant')
        self.assertEqual(result['offline_fast'], 'instant')

    def test_short_password_low_entropy(self):
        result = estimate_crack_time('abc')
        self.assertLess(result['entropy_bits'], 20)

    def test_long_mixed_password_high_entropy(self):
        result = estimate_crack_time('X9#kL2!mP@4qR7&z')
        self.assertGreater(result['entropy_bits'], 80)

    def test_entropy_increases_with_more_char_types(self):
        # lowercase only
        lower_only = estimate_crack_time('abcdefgh')
        # lowercase + uppercase + digits + special
        mixed = estimate_crack_time('aBc1!efg')
        self.assertGreater(mixed['entropy_bits'], lower_only['entropy_bits'])

    def test_status_success(self):
        result = estimate_crack_time('somepassword')
        self.assertEqual(result['status'], 'success')

    def test_keyspace_scientific_notation(self):
        result = estimate_crack_time('abcdef')
        self.assertIn('e+', result['keyspace_size'])


class TestCheckKnownPatterns(unittest.TestCase):
    """tests for the check_known_patterns function."""

    def test_common_password_exact_match(self):
        result = check_known_patterns('password')
        self.assertTrue(result['is_common'])
        self.assertEqual(result['risk_level'], 'critical')
        self.assertIn('exact match in common passwords', result['patterns_found'])

    def test_leet_substitution(self):
        result = check_known_patterns('p@ssw0rd')
        self.assertTrue(result['is_common'])
        self.assertEqual(result['risk_level'], 'high')
        self.assertIn(
            'common password with leet substitutions',
            result['patterns_found'],
        )

    def test_keyboard_walk_detected(self):
        result = check_known_patterns('qwerty123abc')
        walks = [p for p in result['patterns_found'] if 'keyboard walk' in p]
        self.assertGreater(len(walks), 0)

    def test_unique_strong_password(self):
        result = check_known_patterns('Z!x8Qm#rP2kW')
        self.assertFalse(result['is_common'])
        self.assertEqual(result['risk_level'], 'none')

    def test_single_repeated_character(self):
        result = check_known_patterns('aaaa')
        self.assertIn('single repeated character', result['patterns_found'])

    def test_phone_number_pattern(self):
        result = check_known_patterns('12345678901')
        self.assertIn('possible phone number', result['patterns_found'])


class TestGeneratePassphrase(unittest.TestCase):
    """tests for the generate_passphrase function."""

    def test_default_returns_four_words(self):
        result = generate_passphrase()
        self.assertEqual(result['status'], 'success')
        words = result['passphrase'].split('-')
        self.assertEqual(len(words), 4)
        self.assertEqual(result['word_count'], 4)

    def test_custom_word_count(self):
        result = generate_passphrase(word_count=6)
        words = result['passphrase'].split('-')
        self.assertEqual(len(words), 6)

    def test_custom_separator(self):
        result = generate_passphrase(separator='_')
        words = result['passphrase'].split('_')
        self.assertEqual(len(words), 4)

    def test_all_words_from_word_list(self):
        result = generate_passphrase(word_count=6)
        words = result['passphrase'].split('-')
        for word in words:
            self.assertIn(word, WORD_LIST)

    def test_entropy_bits_positive(self):
        result = generate_passphrase()
        self.assertGreater(result['entropy_bits'], 0)


class TestHashCheck(unittest.TestCase):
    """tests for the hash_check function."""

    def test_sha256_match(self):
        password = 'test'
        known = hashlib.sha256(password.encode()).hexdigest()
        result = hash_check(password, known, 'sha256')
        self.assertTrue(result['matches'])
        self.assertEqual(result['status'], 'success')

    def test_sha256_no_match(self):
        result = hash_check('test', 'deadbeef' * 8, 'sha256')
        self.assertFalse(result['matches'])

    def test_unsupported_algorithm(self):
        result = hash_check('test', 'abc', 'bcrypt')
        self.assertEqual(result['status'], 'error')
        self.assertIn('Unsupported algorithm', result['error'])

    def test_all_algorithms(self):
        password = 'hello'
        for algo in ('md5', 'sha1', 'sha256', 'sha512'):
            known = hashlib.new(algo, password.encode()).hexdigest()
            result = hash_check(password, known, algo)
            self.assertTrue(result['matches'], f'{algo} should match')
            self.assertEqual(result['algorithm'], algo)


class TestFormatDuration(unittest.TestCase):
    """tests for the _format_duration helper."""

    def test_instant(self):
        self.assertEqual(_format_duration(0.5), 'instant')

    def test_seconds(self):
        self.assertEqual(_format_duration(30), '30 seconds')

    def test_hours(self):
        self.assertEqual(_format_duration(7200), '2 hours')

    def test_very_large_contains_years(self):
        self.assertIn('years', _format_duration(1e18))

    def test_minutes_rounding(self):
        # 90 seconds = 1.5 minutes, :.0f rounds to 2
        self.assertEqual(_format_duration(90), '2 minutes')


if __name__ == '__main__':
    unittest.main()
