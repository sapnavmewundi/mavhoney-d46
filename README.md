# MAVHoney-D46

**A 46-Day Multi-Sensor Dataset of Network Traffic to an Active Low-Interaction MAVLink Deception Honeypot on Port 5760**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21769462.svg)](https://doi.org/10.5281/zenodo.21769462)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

MAVHoney-D46 is a comprehensive dataset capturing real-world network activity targeting MAVLink-associated TCP port 5760. The dataset was collected over 46 days (April 16 – May 31, 2026) across three geographically distributed sensors deployed on DigitalOcean infrastructure in India (two sensors: S1 Bengaluru, S3 Bengaluru Static) and the United States (one sensor: S2 New York).

### Collector Architecture & Interaction Model

The collector is an **active, low-interaction deception honeypot**:
- **Beaconing**: Upon receiving a TCP connection, the honeypot proactively emits a MAVLink `HEARTBEAT` beacon advertising a live ArduPilot/PX4-style autonomous vehicle endpoint.
- **Decoy Banner**: Presents a decoy "ArduPilot GCS" authentication banner.
- **Crafted Telemetry**: Replies to client MAVLink messages with synthesized telemetry (`HEARTBEAT`, GPS, battery, `ACK`).

Because of this active posture, MAVLink-aware traffic in this dataset is largely **solicited** by the initial beacon, capturing how Internet-wide scanners and specialized probing tools engage a live-appearing drone endpoint.

## Dataset Summary (v1.3.0)

| Metric | Value |
|--------|-------|
| Collection period | 46 days (Apr 16 – May 31, 2026) |
| Sensors | 3 (India ×2, US ×1) |
| Total sessions | 33,207 |
| Classified sessions | 19,767 |
| Unclassified (no app-layer bytes) | 13,440 |
| MAVLink-aware sessions | 368 (RECON 363, CONTROL 5) |
| Unique source IPs | 4,330 |
| Protocol | TCP 100% (UDP 0%) |

### Intent Classification

Intent classification is deterministic and protocol-observable (Table 3 in manuscript). MAVLink v2 trailing-zero truncation is applied to all frames.

| Label | Sessions | Description |
|-------|----------|-------------|
| **SCANNER** | 19,399 (98.1%) | Non-MAVLink generic automated port scans and probes |
| **RECON** | 363 (1.8%) | Valid MAVLink telemetry and PING probes (dominated by 205 sources with constant `seq=1337` tool signature) |
| **CONTROL** | 5 (0.03%) | Active command attempts (e.g., `COMMAND_LONG`, `SET_MODE`) |
| **UNKNOWN** | 0 (0.0%) | Zero unclassified framed traffic (re-identified via v2 truncation) |
| *(unlabeled)* | 13,440 | Sessions that connected and disconnected with no application bytes |

### Session-Level Reconciliation

| Category | SCANNER | UNKNOWN | RECON | CONTROL | (unlabeled) | Total |
|----------|---------|---------|-------|---------|-------------|-------|
| `no_app_bytes` | 0 | 0 | 0 | 0 | 13,440 | 13,440 |
| `non_mavlink` | 19,399 | 0 | 0 | 0 | 0 | 19,399 |
| `valid_mavlink` | 0 | 0 | 363 | 5 | 0 | 368 |
| **Total** | **19,399** | **0** | **363** | **5** | **13,440** | **33,207** |

## Privacy & Pseudonymisation

1. **IP Masking**: All IP addresses across every released file (`connections.csv`, `adaptive_data.csv`, and `honeypot.log`) are sanitized to `A.B.x.x` format.
2. **Keyed Pseudonyms**: The `source_id` field is a keyed HMAC-SHA256 pseudonym. The secret key is intentionally withheld from public release and code to ensure IP irreversibility while preserving cross-server and longitudinal correlation.
3. **No Embedded Credentials**: Production API tokens and secrets have been removed and replaced with environment variables.

## Repository Structure

```
mavhoney-d46/
├── dataset/
│   ├── india/          # Server S1 (Bengaluru)
│   │   ├── connections.csv
│   │   ├── adaptive_data.csv
│   │   ├── honeypot.log
│   │   ├── firewall_blocks.csv  # Header-only (schema compatibility)
│   │   └── ssh_bruteforce.csv   # Header-only (schema compatibility)
│   ├── us/             # Server S2 (New York)
│   │   ├── connections.csv
│   │   ├── adaptive_data.csv
│   │   └── honeypot.log
│   ├── static/         # Server S3 (Bengaluru Static)
│   │   ├── connections.csv
│   │   ├── adaptive_data.csv
│   │   ├── honeypot.log
│   │   ├── firewall_blocks.csv  # Header-only (schema compatibility)
│   │   └── ssh_bruteforce.csv   # Header-only (schema compatibility)
│   └── checksums.sha256
├── classify/
│   ├── classifier.py         # Deterministic rule-based intent classifier
│   └── README.md
├── collector/
│   └── README.md             # Collector architecture & interaction documentation
├── honeypot/                 # Full honeypot implementation
│   ├── mavlink_honeypot.py
│   └── core/protocol.py
├── master_pipeline.py        # Generates manuscript figures & analysis
├── reproduce_statistics.py   # Verifies summary statistics & reconciliation
├── .env.example              # Template for environment configuration
└── README.md
```

## Quick Start

### 1. Verify Dataset Checksums
```bash
cd dataset && shasum -a 256 -c checksums.sha256
```

### 2. Reproduce Summary Statistics & Reconciliation
```bash
python3 reproduce_statistics.py dataset
```

### 3. Verify Intent Classification
```bash
python3 classify/classifier.py dataset
```

### 4. Run Analysis & Figure Generation
```bash
python3 master_pipeline.py
```

## Configuration & Environment Variables

Copy `.env.example` to `.env` to configure optional local settings:
```bash
cp .env.example .env
```

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Optional Telegram bot token for honeypot alerting |
| `TELEGRAM_CHAT_ID` | Optional Telegram chat ID for honeypot alerting |
| `SHODAN_API_KEY` | Optional Shodan API key for threat intelligence lookups |
| `MAVHONEY_HMAC_KEY` | Secret HMAC key (leave unset unless re-deriving pseudonyms from raw data) |
| `MAVHONEY_DATASET` | Path to dataset directory (defaults to `./dataset`) |
| `MAVHONEY_SRC` | Path to raw collection data for `master_pipeline.py` |
| `MAVHONEY_FIG_DIR` | Output directory for generated figures |

## File Schemas

### `connections.csv`
| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | ISO-8601 | Connection event time (UTC, NTP-synced) |
| `event_type` | String | `CONNECT` or `DISCONNECT` |
| `source_ip` | String | Masked `A.B.x.x` format |
| `source_port` | Integer | Ephemeral source port |
| `duration` | Float | Session duration in seconds |
| `packet_count` | Integer | Application-layer MAVLink packets received |
| `intent` | String | Session-level intent (`SCANNER`, `RECON`, `CONTROL`) |
| `source_id` | String | Keyed HMAC-SHA256 pseudonym (stable across sensors/days) |

### `adaptive_data.csv`
| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | ISO-8601 | Packet receive time (UTC) |
| `source_ip` | String | Masked `A.B.x.x` format |
| `msg_name` | String | Decoded MAVLink message type (e.g. `HEARTBEAT`, `PING`) |
| `msg_id` | Integer | MAVLink message ID |
| `intent` | String | Classification label |
| `source_id` | String | Keyed HMAC-SHA256 pseudonym |

## Data Availability

- **Zenodo (Archival Dataset & Code)**: [10.5281/zenodo.21769462](https://doi.org/10.5281/zenodo.21769462)
- **GitHub**: [https://github.com/sapnavmewundi/mavhoney-d46](https://github.com/sapnavmewundi/mavhoney-d46)

## Citation

If you use this dataset or codebase, please cite:

```bibtex
@misc{mavhoney_d46_dataset,
  author       = {Mewundi, Sapna Vikram and Chowdary, Medaramitla Prajwal and Honnavalli, Prasad B.},
  title        = {{MAVHoney-D46: A 46-Day Multi-Sensor Dataset of Network Traffic Targeting MAVLink-Associated Port 5760}},
  month        = oct,
  year         = 2026,
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.21769462},
  url          = {https://doi.org/10.5281/zenodo.21769462}
}
```

## License

- **Dataset**: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- **Code**: [MIT License](LICENSE)

## Authors

- Dr. Sapna Vikram Mewundi — PES University, Bengaluru
- Medaramitla Prajwal Chowdary — PES University, Bengaluru
- Dr. Prasad B. Honnavalli — PES University, Bengaluru
