from src.normalizer import normalize_ssh_event

def test_normalizer_extracts_source_ip_from_message():
    parsed = {
        "timestamp": "Jan 1 00:00:01",
        "host": "server",
        "message": "Failed password for root from 10.0.0.5 port 22 ssh2"
    }

    out = normalize_ssh_event(parsed)

    assert out.get("source_ip") == "10.0.0.5"
    assert out.get("service") == "ssh"
    assert out.get("action") == "login"
