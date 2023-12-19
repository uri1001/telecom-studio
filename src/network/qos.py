#!/usr/bin/env python3
"""
qos.py - VoIP Quality of Service Estimation
ITU-T G.107 E-model implementation for MOS scoring.
"""

import time
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def voip_quality_report(host: str, codec: str = 'G.711', samples: int = 10,
                        timeout: float = 2.0) -> Dict[str, Any]:
    """
    Full VoIP quality assessment against a host.

    Args:
        host: Target hostname or IP
        codec: Codec to evaluate
        samples: Number of measurement samples
        timeout: Timeout per measurement

    Returns:
        Dict with measurements, quality score, and recommendation
    """
    from src.network.performance import measure_latency, jitter_analysis

    latency_result = measure_latency(host, samples=samples, timeout=timeout)
    if latency_result['status'] != 'success':
        return {
            'status': 'error',
            'host': host,
            'error': latency_result.get('error', 'Latency measurement failed'),
        }

    jitter_result = jitter_analysis(host, samples=samples, interval=0.1)
    if jitter_result['status'] != 'success':
        return {
            'status': 'error',
            'host': host,
            'error': jitter_result.get('error', 'Jitter analysis failed'),
        }

    latency_ms = latency_result['avg_ms']
    jitter_ms = jitter_result['avg_jitter_ms']
    packet_loss_pct = latency_result['packet_loss']

    mos_result = estimate_mos(latency_ms, jitter_ms, packet_loss_pct, codec)

    recommendation = _build_recommendation(
        mos_result['mos'], latency_ms, jitter_ms, packet_loss_pct
    )

    return {
        'status': 'success',
        'host': host,
        'codec': codec,
        'measurements': {
            'latency_ms': latency_ms,
            'jitter_ms': jitter_ms,
            'packet_loss_pct': packet_loss_pct,
        },
        'quality': {
            'r_factor': mos_result['r_factor'],
            'mos': mos_result['mos'],
            'tier': mos_result['quality'],
        },
        'recommendation': recommendation,
    }


def _build_recommendation(mos: float, latency: float, jitter: float,
                          loss: float) -> str:
    """Build a human-readable recommendation based on quality metrics."""
    if mos >= 4.0:
        return 'link quality is good for VoIP'

    issues = []
    if latency > 150:
        issues.append(f'high latency ({latency:.0f}ms > 150ms)')
    if jitter > 30:
        issues.append(f'high jitter ({jitter:.0f}ms > 30ms)')
    if loss > 3:
        issues.append(f'high packet loss ({loss:.1f}% > 3%)')

    if issues:
        return 'issues detected: ' + '; '.join(issues)
    if mos >= 3.6:
        return 'acceptable quality'
    return 'poor link quality'


def compare_routes(hosts: List[str], codec: str = 'G.711',
                   samples: int = 5) -> Dict[str, Any]:
    """
    Compare VoIP quality across multiple routes in parallel.

    Args:
        hosts: List of target hostnames or IPs
        codec: Codec to evaluate
        samples: Number of measurement samples per host

    Returns:
        Dict with ranked route comparison
    """
    results = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(voip_quality_report, host, codec, samples): host
            for host in hosts
        }

        for future in as_completed(futures):
            host = futures[future]
            results[host] = future.result()

    routes = []
    for host, result in results.items():
        if result['status'] == 'success':
            routes.append({
                'host': host,
                'mos': result['quality']['mos'],
                'r_factor': result['quality']['r_factor'],
                'quality': result['quality']['tier'],
                'latency_ms': result['measurements']['latency_ms'],
                'jitter_ms': result['measurements']['jitter_ms'],
                'packet_loss_pct': result['measurements']['packet_loss_pct'],
            })

    # sort by MOS descending, assign rank
    routes.sort(key=lambda r: r['mos'], reverse=True)
    for i, route in enumerate(routes):
        route['rank'] = i + 1

    return {
        'status': 'success',
        'codec': codec,
        'routes': routes,
        'best_route': routes[0]['host'] if routes else None,
        'worst_route': routes[-1]['host'] if routes else None,
    }


def monitor_quality(host: str, duration: int = 300, interval: int = 30,
                    codec: str = 'G.711', threshold: float = 3.5) -> Dict[str, Any]:
    """
    Continuously monitor VoIP quality over a time window.

    Args:
        host: Target hostname or IP
        duration: Total monitoring duration in seconds
        interval: Seconds between measurements
        codec: Codec to evaluate
        threshold: MOS threshold for breach detection

    Returns:
        Dict with timeline, stats, and threshold breaches
    """
    import statistics
    from src.network.performance import measure_latency, jitter_analysis

    timeline = []
    breaches = []
    in_breach = False
    breach_start = None
    breach_min_mos = None

    elapsed = 0
    while elapsed < duration:
        # quick measurements
        lat = measure_latency(host, samples=3, timeout=2.0)
        jit = jitter_analysis(host, samples=5, interval=0.1)

        if lat['status'] == 'success' and jit['status'] == 'success':
            latency_ms = lat['avg_ms']
            jitter_ms = jit['avg_jitter_ms']
            packet_loss_pct = lat['packet_loss']

            mos_result = estimate_mos(latency_ms, jitter_ms, packet_loss_pct, codec)
            mos = mos_result['mos']

            entry = {
                'timestamp': time.time(),
                'mos': mos,
                'latency_ms': latency_ms,
                'jitter_ms': jitter_ms,
                'packet_loss_pct': packet_loss_pct,
            }
            timeline.append(entry)

            # breach tracking
            if mos < threshold and not in_breach:
                in_breach = True
                breach_start = entry['timestamp']
                breach_min_mos = mos
            elif mos < threshold and in_breach:
                breach_min_mos = min(breach_min_mos, mos)
            elif mos >= threshold and in_breach:
                breaches.append({
                    'start': breach_start,
                    'end': entry['timestamp'],
                    'duration_s': round(entry['timestamp'] - breach_start, 1),
                    'min_mos': breach_min_mos,
                })
                in_breach = False

        elapsed += interval
        if elapsed < duration:
            time.sleep(interval)

    # close any open breach
    if in_breach and timeline:
        breaches.append({
            'start': breach_start,
            'end': timeline[-1]['timestamp'],
            'duration_s': round(timeline[-1]['timestamp'] - breach_start, 1),
            'min_mos': breach_min_mos,
        })

    # aggregate stats
    mos_values = [e['mos'] for e in timeline]
    stats = {}
    if mos_values:
        stats = {
            'min': min(mos_values),
            'max': max(mos_values),
            'avg': round(statistics.mean(mos_values), 2),
            'stdev': round(statistics.stdev(mos_values), 2) if len(mos_values) > 1 else 0,
        }

    return {
        'status': 'success',
        'host': host,
        'codec': codec,
        'duration_s': duration,
        'samples': len(timeline),
        'threshold': threshold,
        'stats': stats,
        'breaches': breaches,
        'timeline': timeline,
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

    # voip quality report
    print(f"\nVoIP quality report for google.com:")
    report = voip_quality_report('google.com', samples=5)
    if report['status'] == 'success':
        q = report['quality']
        print(f"  MOS: {q['mos']} ({q['tier']}), R: {q['r_factor']}")
        print(f"  Recommendation: {report['recommendation']}")
    else:
        print(f"  Error: {report.get('error')}")

    # short monitoring demo
    print(f"\nMonitoring google.com (60s, 15s interval):")
    mon = monitor_quality('google.com', duration=60, interval=15, threshold=3.5)
    if mon['status'] == 'success':
        print(f"  Samples: {mon['samples']}, Breaches: {len(mon['breaches'])}")
        if mon['stats']:
            print(f"  MOS avg: {mon['stats']['avg']}, min: {mon['stats']['min']}")
