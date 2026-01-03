from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


def _parse_ts(ts: str) -> datetime:
    """
    Parses timestamp strings used in this project.
    Returns timezone-aware UTC datetimes.

    Supports:
      - ISO format (e.g. 2026-01-01T00:00:01 or 2026-01-01T00:00:01+00:00)
      - syslog-like without year (e.g. 'Jan 01 00:00:01')
    """
    # 1) ISO 8601
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # 2) Syslog-like without year: choose a stable year explicitly to avoid Python 3.15 ambiguity warning
    # We pick the current UTC year; good enough for correlation windows.
    current_year = datetime.now(timezone.utc).year

    dt = datetime.strptime(ts, "%b %d %H:%M:%S")
    dt = dt.replace(year=current_year, tzinfo=timezone.utc)
    return dt


def detect_ssh_bruteforce(
    events: list[dict],
    threshold: int = 3,
    window_seconds: int = 60,
) -> list[dict]:
    """
    Detects SSH brute force attempts using a rolling time window:
    triggers when >= threshold failed SSH login events from the same source_ip
    occur within window_seconds.
    """
    alerts: list[dict] = []
    window = timedelta(seconds=window_seconds)

    # source_ip -> deque[datetime] (timestamps of failed attempts in rolling window)
    failed_windows: dict[str, deque] = defaultdict(deque)

    for event in events:
        if event.get("service") != "ssh":
            continue
        if event.get("status") != "failed":
            continue

        ip = event.get("source_ip")
        ts_raw = event.get("timestamp")

        if not ip or not ts_raw:
            continue

        # parse event timestamp
        try:
            ts = _parse_ts(ts_raw)
        except Exception:
            # If timestamp is unexpected, skip (keeps pipeline resilient)
            continue

        dq = failed_windows[ip]
        dq.append(ts)

        # Remove timestamps outside the rolling window
        cutoff = ts - window
        while dq and dq[0] < cutoff:
            dq.popleft()

        # Trigger only once when threshold is reached (avoids alert spam)
        if len(dq) == threshold:
            # Evidence: last `threshold` failed events for that IP (simple and readable)
            evidence = [
                e for e in events
                if e.get("source_ip") == ip and e.get("service") == "ssh" and e.get("status") == "failed"
            ][-threshold:]

            alerts.append({
                "rule": "SSH Brute Force",
                "type": "SSH_BRUTE_FORCE",
                "severity": "medium",
                "source_ip": ip,
                "failed_attempts": threshold,
                "window_seconds": window_seconds,
                "first_seen": dq[0].isoformat(),
                "last_seen": dq[-1].isoformat(),
                "context": {"service": "ssh", "action": "login"},
                "evidence": evidence,

                "rule_id": "SIEM-SSH-001",
                "tags": ["ssh", "bruteforce", "authentication", "blue-team"],
                "recommended_actions": [
                    "Check if the source IP is internal or external.",
                    "Review the evidence events for targeted usernames.",
                    "Block or rate-limit the source IP if confirmed malicious.",
                    "Verify whether the successful login was expected (MFA? known admin activity?)."
                ]
            })

    return alerts


def detect_success_after_bruteforce(events: list[dict], threshold: int = 3) -> list[dict]:
    """
    Detects a successful SSH login after a brute-force pattern (count-based).
    (We can time-window this later in a separate commit.)
    """
    failed_counts = defaultdict(int)
    recent_failed_events = defaultdict(lambda: deque(maxlen=threshold))
    bruteforce_ips = set()
    alerts = []

    for event in events:
        if event.get("service") != "ssh":
            continue

        ip = event.get("source_ip")
        if not ip:
            continue

        if event.get("status") == "failed":
            failed_counts[ip] += 1
            recent_failed_events[ip].append(event)
            if failed_counts[ip] >= threshold:
                bruteforce_ips.add(ip)

        if event.get("status") == "success" and ip in bruteforce_ips:
            evidence = list(recent_failed_events[ip]) + [event]

            alerts.append({
                "rule": "SSH Success After Brute Force",
                "type": "SSH_SUCCESS_AFTER_BRUTEFORCE",
                "severity": "high",
                "source_ip": ip,
                "user": event.get("user"),
                "timestamp": event.get("timestamp"),
                "context": {
                    "service": "ssh",
                    "action": "login",
                    "reason": f"Successful login after >= {threshold} failed attempts from same IP"
                },
                "evidence": evidence,

                "rule_id": "SIEM-SSH-002",
                "tags": ["ssh", "bruteforce", "possible-compromise", "authentication"],
                "recommended_actions": [
                    "Treat as potential compromise: validate the successful login immediately.",
                    "Check the account used for suspicious activity after login (commands, processes, new users).",
                    "Hunt for the same source IP across other systems/log sources.",
                    "Consider isolating the host if suspicious activity is confirmed."
                ]
            })

    return alerts

