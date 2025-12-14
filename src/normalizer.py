def normalize_ssh_event(parsed_event: dict) -> dict:
    """
    Converts parsed SSH log data into a normalized security event.
    """

    message = parsed_event["message"]

    event = {
        "timestamp": parsed_event["timestamp"],
        "host": parsed_event["host"],
        "service": "ssh",
        "action": "login",
        "status": "unknown",
        "user": None,
        "source_ip": None
    }

    if "Failed password" in message:
        event["status"] = "failed"
    elif "Accepted password" in message:
        event["status"] = "success"

    parts = message.split()

    if "user" in parts:
        event["user"] = parts[parts.index("user") + 1]

    if "from" in parts:
        event["source_ip"] = parts[parts.index("from") + 1]

    return event
