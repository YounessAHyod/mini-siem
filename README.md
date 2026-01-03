# Mini-SIEM Lab

A lightweight Python **detection engineering lab** simulating a blue-team / SOC pipeline:

**log ingestion → normalization → time-correlated detection → alerting with evidence**

This project focuses on **detection logic and validation**, not dashboards or UI.

---

## Purpose

The goal of this project is to demonstrate how security detections are:
- designed,
- validated,
- and tuned to reduce false positives,

using a simplified SIEM-style pipeline.

---

## What it does

- Parses Linux SSH authentication logs
- Normalizes raw logs into structured security events
- Detects:
  - **SSH brute-force attacks** using a rolling time window
  - **Successful SSH login after brute force** (possible compromise)
- Produces **structured JSON alerts** including:
  - rule metadata
  - severity
  - evidence events
  - recommended analyst actions

---

## Detection logic

### SSH Brute Force — `SIEM-SSH-001`
- Triggers when **≥ 3 failed SSH login attempts**
- From the **same source IP**
- **Within a 60-second time window**
- Designed to reduce false positives caused by slow or accidental failures

**Severity:** Medium

---

### SSH Success After Brute Force — `SIEM-SSH-002`
- Triggers when a **successful SSH login**
- Occurs **after a brute-force pattern** from the same IP
- Indicates **potential credential compromise**

**Severity:** High

---

## Tests & validation

This project includes **unit tests** for:
- log parsing
- event normalization
- detection logic

Detection tests validate:
- **positive cases** (alerts trigger when expected)
- **negative cases** (alerts do NOT trigger outside the time window)

This mirrors how real SOC detection rules are tested before deployment.

---

## ▶️ How to run

```bash
python src/main.py
```