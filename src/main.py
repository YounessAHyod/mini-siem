import json
from pathlib import Path

from parser import parse_ssh_log_line
from normalizer import normalize_ssh_event
from detector import detect_ssh_bruteforce, detect_success_after_bruteforce


def main():
    project_root = Path(__file__).resolve().parent.parent  # mini-siem/
    log_path = project_root / "logs" / "raw" / "auth.log"

    events = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parsed = parse_ssh_log_line(line)
            if parsed is None:
                continue

            normalized = normalize_ssh_event(parsed)
            events.append(normalized)

    # Detection
    alerts = detect_ssh_bruteforce(events, threshold=3)
    high_alerts = detect_success_after_bruteforce(events, threshold=3)

    all_alerts = alerts + high_alerts

    # Persist alerts
    alerts_path = project_root / "alerts" / "alerts.json"
    with alerts_path.open("w", encoding="utf-8") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"Alerts written to {alerts_path}")


if __name__ == "__main__":
    main()
