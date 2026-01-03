from src.parser import parse_ssh_log_line

def test_parse_failed_password_keeps_message_and_host():
    line = "Jan 1 00:00:01 server sshd[123]: Failed password for root from 10.0.0.5 port 22 ssh2"
    ev = parse_ssh_log_line(line)

    assert ev is not None
    assert ev["host"] == "server"
    assert "Failed password" in ev["message"]
    assert "root" in ev["message"]
    assert "10.0.0.5" in ev["message"]
