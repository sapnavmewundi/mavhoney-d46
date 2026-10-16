# MAVHoney-D46

**A 46-Day Multi-Sensor Dataset of Network Traffic to an Active Low-Interaction MAVLink Deception Honeypot on Port 5760**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23416383.svg)](https://doi.org/10.5281/zenodo.23416383)
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

### Intent Classification: Session-Level vs. Packet/Row-Level

The dataset captures 33,207 total TCP sessions (recorded in `connections.csv`) and 19,824 decoded application-layer event rows (recorded in `adaptive_data.csv`). Because a single session may exchange multiple packets, classification metrics exist at both **packet/row level** and **session level**:

#### 1. Packet/Row-Level Distribution (`adaptive_data.csv`)
Counts of individual decoded message rows across all sessions (matches Section 2 of `reproduce_statistics.py`):

| Label | Rows (Packets) | Percentage | Description |
|-------|----------------|------------|-------------|
| **SCANNER** | 19,399 | 97.9% | Generic non-MAVLink probes (`NON_MAVLINK_PROBE`) |
| **RECON** | 397 | 2.0% | Valid MAVLink telemetry & PING probes (`HEARTBEAT`, `PARAM_*`, etc.) |
| **CONTROL** | 21 | 0.1% | Valid MAVLink command messages (`COMMAND_LONG`, `SET_MODE`, etc.) |
| **UNKNOWN** | 7 | <0.1% | Framed packets failing message-definition validation (`MALFORMED_*`) |
| **Total** | **19,824** | **100.0%** | All decoded application-layer records |

#### 2. Session-Level Intent Classification (`connections.csv`)
Sessions inherit the highest-priority intent of their constituent packets using the hierarchy: `CONTROL` (4) > `RECON` (3) > `UNKNOWN` (2) > `SCANNER` (1).

> **Why UNKNOWN = 0 at the session level**: The 7 `UNKNOWN` (`MALFORMED_*`) packet rows occurred within 2 multi-packet sessions (session IDs `52ebde96` and `982ed531`) that also transmitted valid `RECON` telemetry. Under the priority hierarchy, both sessions resolve to `RECON`, leaving exactly 0 sessions whose dominant classification is `UNKNOWN`.

| Label | Sessions | Percentage | Description |
|-------|----------|------------|-------------|
| **SCANNER** | 19,399 | 98.1% of classified | Non-MAVLink generic automated port scans and probes |
| **RECON** | 363 | 1.8% of classified | MAVLink-aware telemetry and PING probes (205 sources with `seq=1337`) |
| **CONTROL** | 5 | 0.03% of classified | Active command attempts (e.g., `COMMAND_LONG`, `SET_MODE`) |
| **UNKNOWN** | 0 | 0.0% of classified | Zero sessions dominated by malformed traffic |
| **Classified Total** | **19,767** | **100.0%** | Sessions with decoded application content |
| *(unlabeled)* | 13,440 | — | Sessions that connected and disconnected with no application bytes |
| **Total Sessions** | **33,207** | — | Total TCP sessions across all 3 sensors |

#### 3. Session-Level Reconciliation Matrix
Cross-tabulation of payload categories and session-level labels (matches Section 6 of `reproduce_statistics.py` and Table 5 in the manuscript):

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
| `ip` | String | Masked `A.B.x.x` client IP address |
| `source_id` | String | Keyed HMAC-SHA256 pseudonym (stable across sensors/days) |
| `port` | Integer | Ephemeral source port |
| `session_id` | String | Unique 8-hex session identifier |
| `event_type` | String | `CONNECT` or `DISCONNECT` |
| `packets` | Integer | Application-layer MAVLink packets received |
| `duration_sec` | Float | Session duration in seconds |

### `adaptive_data.csv`
| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | ISO-8601 | Packet receive time (UTC) |
| `ip` | String | Masked `A.B.x.x` client IP address |
| `source_id` | String | Keyed HMAC-SHA256 pseudonym |
| `port` | Integer | Ephemeral source port |
| `msg_id` | Integer | MAVLink message ID (e.g. 0 for `HEARTBEAT`, 24 for `GPS_RAW_INT`) |
| `msg_name` | String | Decoded MAVLink message name (or `NON_MAVLINK_PROBE`) |
| `intent` | String | Classification label (`SCANNER`, `RECON`, `CONTROL`) |
| `payload_hex` | String | Raw packet payload in hexadecimal |
| `session_id` | String | Unique 8-hex session identifier linking to `connections.csv` |
| `honeypot_state` | String | Honeypot state machine phase (e.g. `NORMAL`, `AUTH_DECOY`) |
| `packet_rate` | Float | Received packet arrival rate (packets/sec) |

### Auxiliary Files
- `honeypot.log`: Collector event logs with all IP addresses sanitized to `A.B.x.x`.
- `firewall_blocks.csv`: Firewall log schema (`timestamp,ip,port,protocol,action`), retained header-only for schema compatibility.
- `ssh_bruteforce.csv`: SSH daemon log schema (`timestamp,ip,port,username,password,success`), retained header-only for schema compatibility.

## Data Availability

- **Zenodo Archival Record (v1.3.0)**: [10.5281/zenodo.23416383](https://doi.org/10.5281/zenodo.23416383)
  - **Concept DOI (resolves to latest version)**: [10.5281/zenodo.21769461](https://doi.org/10.5281/zenodo.21769461)
  - **Archival Version History**: v1.0.0 (`10.5281/zenodo.21769462`), v1.1.0 (`10.5281/zenodo.21990129`), v1.3.0 (`10.5281/zenodo.23416383`)
- **GitHub Repository**: [https://github.com/sapnavmewundi/mavhoney-d46](https://github.com/sapnavmewundi/mavhoney-d46)

## Citation

If you use this dataset or codebase, please cite:

```bibtex
@misc{mavhoney_d46_dataset,
  author       = {Mewundi, Sapna Vikram and Chowdary, Medaramitla Prajwal and Honnavalli, Prasad B.},
  title        = {{MAVHoney-D46: A 46-Day Multi-Sensor Dataset of Network Traffic Targeting MAVLink-Associated Port 5760}},
  month        = oct,
  year         = 2026,
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.23416383},
  url          = {https://doi.org/10.5281/zenodo.23416383}
}
```

## License

- **Dataset**: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- **Code**: [MIT License](LICENSE)

## Authors

- Dr. Sapna Vikram Mewundi — PES University, Bengaluru
- Medaramitla Prajwal Chowdary — PES University, Bengaluru
- Dr. Prasad B. Honnavalli — PES University, Bengaluru
