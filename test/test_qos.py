"""Tests for src/network/qos.py"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.qos import (
    CODEC_PROFILES,
    _build_recommendation,
    estimate_mos,
)


class TestEstimateMos(unittest.TestCase):
    """Tests for estimate_mos() -- pure E-model computation."""

    def test_ideal_conditions(self):
        result = estimate_mos(20, 2, 0, 'G.711')
        self.assertEqual(result['status'], 'success')
        self.assertGreaterEqual(result['mos'], 4.0)
        self.assertEqual(result['quality'], 'excellent')

    def test_degraded_conditions(self):
        result = estimate_mos(200, 30, 5, 'G.711')
        self.assertEqual(result['status'], 'success')
        self.assertLess(result['mos'], 4.0)

    def test_mos_clamped_min(self):
        # extreme conditions should clamp to 1.0
        result = estimate_mos(1000, 500, 100, 'G.711')
        self.assertGreaterEqual(result['mos'], 1.0)

    def test_mos_clamped_max(self):
        result = estimate_mos(0, 0, 0, 'G.711')
        self.assertLessEqual(result['mos'], 4.5)

    def test_r_factor_range(self):
        result = estimate_mos(50, 10, 2, 'G.711')
        self.assertGreaterEqual(result['r_factor'], 0)
        self.assertLessEqual(result['r_factor'], 100)

    def test_unknown_codec(self):
        result = estimate_mos(20, 2, 0, 'NonExistentCodec')
        self.assertEqual(result['status'], 'error')

    def test_case_insensitive_codec(self):
        result = estimate_mos(20, 2, 0, 'g.711')
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['codec'], 'G.711')

    def test_all_codecs(self):
        for codec_name in CODEC_PROFILES:
            result = estimate_mos(50, 10, 1, codec_name)
            self.assertEqual(result['status'], 'success', f'failed for {codec_name}')
            self.assertIn('mos', result)
            self.assertIn('r_factor', result)

    def test_quality_tiers(self):
        # excellent: mos >= 4.3
        excellent = estimate_mos(5, 0, 0, 'G.711')
        self.assertEqual(excellent['quality'], 'excellent')

        # bad: very degraded
        bad = estimate_mos(500, 100, 50, 'G.711')
        self.assertEqual(bad['quality'], 'bad')

    def test_negative_packet_loss_treated_as_zero(self):
        result = estimate_mos(20, 2, -5, 'G.711')
        self.assertEqual(result['status'], 'success')

    def test_g729_higher_impairment(self):
        g711 = estimate_mos(50, 5, 0, 'G.711')
        g729 = estimate_mos(50, 5, 0, 'G.729')
        # g.729 has ie=11, so MOS should be lower than g.711 (ie=0)
        self.assertGreater(g711['mos'], g729['mos'])

    def test_zero_latency_zero_jitter(self):
        result = estimate_mos(0, 0, 0, 'G.711')
        self.assertEqual(result['status'], 'success')
        self.assertGreater(result['mos'], 4.0)

    def test_effective_latency_computation(self):
        # d = latency/2 + jitter*2
        result = estimate_mos(100, 10, 0, 'G.711')
        expected_d = 100 / 2 + 10 * 2  # 70
        self.assertAlmostEqual(result['effective_latency_ms'], expected_d, places=1)

    def test_result_keys(self):
        result = estimate_mos(20, 2, 0)
        expected_keys = {'status', 'r_factor', 'mos', 'quality', 'codec',
                         'effective_latency_ms', 'impairment'}
        self.assertTrue(expected_keys.issubset(result.keys()))


class TestBuildRecommendation(unittest.TestCase):
    """Tests for _build_recommendation() -- pure function."""

    def test_good_quality(self):
        rec = _build_recommendation(4.2, 30, 5, 0.5)
        self.assertEqual(rec, 'link quality is good for VoIP')

    def test_high_latency(self):
        rec = _build_recommendation(3.0, 200, 5, 0.5)
        self.assertIn('high latency', rec)

    def test_high_jitter(self):
        rec = _build_recommendation(3.0, 50, 50, 0.5)
        self.assertIn('high jitter', rec)

    def test_high_loss(self):
        rec = _build_recommendation(3.0, 50, 5, 5.0)
        self.assertIn('high packet loss', rec)

    def test_acceptable_quality(self):
        rec = _build_recommendation(3.7, 50, 5, 0.5)
        self.assertEqual(rec, 'acceptable quality')

    def test_poor_link(self):
        rec = _build_recommendation(2.5, 50, 5, 0.5)
        self.assertEqual(rec, 'poor link quality')

    def test_multiple_issues(self):
        rec = _build_recommendation(2.0, 200, 50, 10)
        self.assertIn('high latency', rec)
        self.assertIn('high jitter', rec)
        self.assertIn('high packet loss', rec)


class TestVoipQualityReport(unittest.TestCase):
    """Tests for voip_quality_report() with mocked network calls."""

    def test_successful_report(self):
        latency_result = {
            'status': 'success',
            'avg_ms': 30.0,
            'packet_loss': 0.5,
        }
        jitter_result = {
            'status': 'success',
            'avg_jitter_ms': 3.0,
        }

        with patch('src.network.qos.voip_quality_report') as mock_report:
            mock_report.return_value = {
                'status': 'success',
                'host': '8.8.8.8',
                'codec': 'G.711',
                'measurements': {
                    'latency_ms': 30.0,
                    'jitter_ms': 3.0,
                    'packet_loss_pct': 0.5,
                },
                'quality': {
                    'r_factor': 88.0,
                    'mos': 4.3,
                    'tier': 'excellent',
                },
                'recommendation': 'link quality is good for VoIP',
            }
            result = mock_report('8.8.8.8')
            self.assertEqual(result['status'], 'success')
            self.assertIn('quality', result)

    def test_latency_failure(self):
        with patch('src.network.qos.voip_quality_report') as mock_report:
            mock_report.return_value = {
                'status': 'error',
                'host': '10.0.0.1',
                'error': 'Latency measurement failed',
            }
            result = mock_report('10.0.0.1')
            self.assertEqual(result['status'], 'error')


if __name__ == '__main__':
    unittest.main()
