# Mini-SIEM Lab

A lightweight Python project simulating a **blue-team / SOC detection pipeline**:
log ingestion → normalization → detection → alerting with evidence.

Focus: **detection engineering**, not dashboards.

---

## What it does

- Parses Linux SSH authentication logs
- Normalizes logs into security events
- Detects:
  - SSH brute-force attacks
  - Successful login after brute force (possible compromise)
- Outputs structured alerts in JSON with evidence and recommended actions

---

## Detections

- **SIEM-SSH-001 | SSH Brute Force**  
  ≥ 3 failed SSH logins from the same IP (medium severity)

- **SIEM-SSH-002 | SSH Success After Brute Force**  
  Successful login after brute force (high severity)

---

## How to run

```bash
python src/main.py

