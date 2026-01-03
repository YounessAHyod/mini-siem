from datetime import datetime, timedelta

from src.detector import detect_ssh_bruteforce
from src.normalizer import normalize_ssh_event


def test_detector_flags_bruteforce_on_repeated_fails():
    base = datetime(2026, 1, 1, 0, 0, 0)

    parsed_events = [
        {
            "timestamp": (base + timedelta(seconds=0)).isoformat(),
            "host": "server",
            "message": "Failed password for root from 10.0.0.5 port 22 ssh2",
        },
        {
            "timestamp": (base + timedelta(seconds=10)).isoformat(),
            "host": "server",
            "message": "Failed password for root from 10.0.0.5 port 22 ssh2",
        },
        {
            "timestamp": (base + timedelta(seconds=20)).isoformat(),
            "host": "server",
            "message": "Failed password for root from 10.0.0.5 port 22 ssh2",
        },
    ]

    normalized = [normalize_ssh_event(e) for e in parsed_events]
    alerts = detect_ssh_bruteforce(normalized)

    assert alerts, "Expected at least one brute-force alert"
