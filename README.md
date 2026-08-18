# MAVHoney-D46

**A 46-Day Multi-Sensor Dataset of Unsolicited Network Traffic Targeting MAVLink-Associated TCP Port 5760**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21769462.svg)](https://doi.org/10.5281/zenodo.21769462)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

MAVHoney-D46 is, to the best of our knowledge, the first publicly available dataset capturing real-world unsolicited network activity on MAVLink-associated TCP port 5760. The dataset was collected over 46 days (April 16 – May 31, 2026) using three geographically distributed passive listeners deployed on DigitalOcean infrastructure in India (two sensors) and the United States (one sensor).

## Dataset Summary (v1.1.0)

| Metric | Value |
|--------|-------|
| Collection period | 46 days (Apr 16 – May 31, 2026) |
| Sensors | 3 (India ×2, US ×1) |
| Total sessions | 33,207 |
| Classified sessions | 19,771 |
| Unclassified | 13,436 |
| MAVLink-valid sessions | 369 |
| Unique source IPs | 4,330 |
| Protocol | TCP 100% (UDP 0%) |

### Intent Classification

| Label | Sessions | Description |
|-------|----------|-------------|
| SCANNER | 19,402 (98.1%) | Generic automated port scans |
| UNKNOWN | 337 (1.7%) | MAVLink-valid, unclassified intent |
| RECON | 27 (0.1%) | MAVLink-aware passive probes (HEARTBEAT) |
| CONTROL | 5 (0.03%) | Active command attempts |

## Repository Structure

```
mavhoney-d46/
├── dataset/
│   ├── india/          # Server S1 (Bengaluru)
│   │   ├── connections.csv
│   │   ├── adaptive_data.csv
│   │   └── honeypot.log
│   ├── us/             # Server S2 (New York)
│   │   ├── connections.csv
│   │   ├── adaptive_data.csv
│   │   └── honeypot.log
│   ├── static/         # Server S3 (Bengaluru)
│   │   ├── connections.csv
│   │   ├── adaptive_data.csv
│   │   └── honeypot.log
│   └── checksums.sha256
├── master_pipeline.py       # Generates all figures and statistics
├── reproduce_statistics.py  # Reproduces all summary counts
├── dataset_paper/
│   ├── figures/             # All manuscript figures
│   └── generate_figures.py
└── README.md
```

## Quick Start

### Verify checksums
```bash
cd dataset && sha256sum -c checksums.sha256
```

### Reproduce all statistics
```bash
python reproduce_statistics.py
```

### Generate all figures
```bash
python master_pipeline.py
```

## File Schemas

### connections.csv
| Column | Type | Description |
|--------|------|-------------|
| timestamp | ISO-8601 | Connection time (UTC, NTP-synced) |
| event_type | String | CONNECT or DISCONNECT |
| source_ip | String | Masked A.B.x.x format |
| source_port | Integer | Ephemeral source port |
| duration | Float | Session duration (seconds) |
| packet_count | Integer | Application-layer MAVLink packets |
| intent | String | SCANNER/UNKNOWN/RECON/CONTROL |
| source_id | String | HMAC-SHA256 pseudonym (stable across servers/days) |

### adaptive_data.csv
| Column | Type | Description |
|--------|------|-------------|
| timestamp | ISO-8601 | Packet receive time (UTC) |
| source_ip | String | Masked A.B.x.x format |
| msg_name | String | Decoded MAVLink message type |
| severity | Integer | Composite severity score (0–10) |
| intent | String | Session-level intent classification |
| source_id | String | HMAC-SHA256 pseudonym |

## Data Availability

- **Zenodo (archival)**: [10.5281/zenodo.21769462](https://doi.org/10.5281/zenodo.21769462)
- **GitHub (code + mirror)**: This repository

## Citation

If you use this dataset, please cite:

```bibtex
@misc{mavhoney_d46_dataset,
  author       = {Mewundi, Sapna Vikram and Chowdary, Medaramitla Prajwal and Honnavalli, Prasad B.},
  title        = {{MAVHoney-D46: A 46-Day Multi-Sensor Dataset of Unsolicited
                   Network Traffic Targeting MAVLink-Associated Port 5760}},
  month        = jul,
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

- Sapna Vikram Mewundi — PES University, Bengaluru
- Medaramitla Prajwal Chowdary — PES University, Bengaluru
- Prasad B. Honnavalli — PES University, Bengaluru
