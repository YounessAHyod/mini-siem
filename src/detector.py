from collections import defaultdict, deque


def detect_ssh_bruteforce(events: list[dict], threshold: int = 3) -> list[dict]:
    failed_counts = defaultdict(int)
    recent_failed_events = defaultdict(lambda: deque(maxlen=threshold))
    alerts = []

    for event in events:
        if event.get("service") != "ssh":
            continue
        if event.get("status") != "failed":
            continue

        ip = event.get("source_ip")
        if not ip:
            continue

        failed_counts[ip] += 1
        recent_failed_events[ip].append(event)

        if failed_counts[ip] == threshold:
            evidence = list(recent_failed_events[ip])

            alerts.append({
                "rule": "SSH Brute Force",
                "type": "SSH_BRUTE_FORCE",
                "severity": "medium",
                "source_ip": ip,
                "failed_attempts": failed_counts[ip],
                "first_seen": evidence[0].get("timestamp"),
                "last_seen": evidence[-1].get("timestamp"),
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
