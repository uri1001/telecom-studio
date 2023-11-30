#!/usr/bin/env python3
"""
qos.py - VoIP Quality of Service Estimation
ITU-T G.107 E-model implementation for MOS scoring.
"""

from typing import Dict, Any


# codec parameters: equipment impairment (ie), packet loss robustness (bpl), bitrate
CODEC_PROFILES = {
    'G.711': {'ie': 0, 'bpl': 25.1, 'bitrate': '64kbps'},
    'G.729': {'ie': 11, 'bpl': 19.0, 'bitrate': '8kbps'},
    'G.722': {'ie': 0, 'bpl': 25.1, 'bitrate': '64kbps'},
    'G.726': {'ie': 2, 'bpl': 25.1, 'bitrate': '32kbps'},
    'Opus': {'ie': 0, 'bpl': 20.0, 'bitrate': '6-510kbps'},
    'iLBC': {'ie': 11, 'bpl': 10.0, 'bitrate': '13.3kbps'},
    'AMR-NB': {'ie': 10, 'bpl': 16.0, 'bitrate': '4.75-12.2kbps'},
}


def estimate_mos(latency_ms: float, jitter_ms: float, packet_loss_pct: float,
                 codec: str = 'G.711') -> Dict[str, Any]:
    """
    Estimate MOS using the ITU-T G.107 E-model.

    Args:
        latency_ms: One-way latency in milliseconds
        jitter_ms: Jitter in milliseconds
        packet_loss_pct: Packet loss percentage (0-100)
        codec: Codec name (case-insensitive)

    Returns:
        Dict with R-factor, MOS score, and quality tier
    """
    # case-insensitive codec lookup
    profile = None
    for name, p in CODEC_PROFILES.items():
        if name.lower() == codec.lower():
            profile = p
            codec = name
            break

    if not profile:
        return {
            'status': 'error',
            'error': f'Unknown codec: {codec}. Supported: {list(CODEC_PROFILES.keys())}'
        }

    ie_base = profile['ie']
    bpl = profile['bpl']

    # effective one-way delay (half RTT + jitter buffer approximation)
    d = latency_ms / 2 + jitter_ms * 2

    # delay impairment (Id) -- H(x) is the Heaviside step function
    Id = 0.024 * d + 0.11 * (d - 177.3) * (1 if d > 177.3 else 0)

    # equipment impairment (Ie-eff) -- accounts for codec + packet loss
    loss = max(packet_loss_pct, 0)
    Ie = ie_base + (95 - ie_base) * loss / (loss + bpl)

    # R-factor (clamped 0-100)
    R = 93.2 - Id - Ie
    R = max(0, min(100, R))

    # MOS conversion (clamped 1.0-4.5)
    if R <= 0:
        mos = 1.0
    else:
        mos = 1 + 0.035 * R + R * (R - 60) * (100 - R) * 7e-6
        mos = max(1.0, min(4.5, mos))

    mos = round(mos, 2)

    # quality tier
    if mos >= 4.3:
        quality = 'excellent'
    elif mos >= 4.0:
        quality = 'good'
    elif mos >= 3.6:
        quality = 'fair'
    elif mos >= 3.1:
        quality = 'poor'
    else:
        quality = 'bad'

    return {
        'status': 'success',
        'r_factor': round(R, 2),
        'mos': mos,
        'quality': quality,
        'codec': codec,
        'effective_latency_ms': round(d, 2),
        'impairment': {
            'delay': round(Id, 2),
            'equipment': round(Ie, 2),
        },
    }


if __name__ == '__main__':
    print("VoIP Quality Estimation (ITU-T G.107 E-model)")
    print("=" * 50)

    # ideal conditions
    result = estimate_mos(20, 2, 0)
    print(f"\nIdeal (20ms, 2ms jitter, 0% loss, G.711):")
    print(f"  MOS: {result['mos']} ({result['quality']}), R: {result['r_factor']}")

    # degraded conditions
    result = estimate_mos(200, 30, 5)
    print(f"\nDegraded (200ms, 30ms jitter, 5% loss, G.711):")
    print(f"  MOS: {result['mos']} ({result['quality']}), R: {result['r_factor']}")
