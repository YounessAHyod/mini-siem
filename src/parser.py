import re

# Regex for SSH authentication logs
SSH_LOG_REGEX = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'(?P<message>.*)'
)


def parse_ssh_log_line(line: str) -> dict | None:
    """
    Parses a single SSH log line.
    Returns a dictionary with extracted fields or None if no match.
    """
    match = SSH_LOG_REGEX.match(line)
    if not match:
        return None

    return match.groupdict()

