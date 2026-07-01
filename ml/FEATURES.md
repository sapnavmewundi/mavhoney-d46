# ML Feature Engineering Documentation

## Overview

The anomaly detection pipeline uses an **Isolation Forest** model trained on
labelled attack datasets.  Six features are extracted from each event.

## Feature Descriptions

| # | Feature | Type | Range | Description | Rationale |
|---|---------|------|-------|-------------|-----------|
| 1 | `severity` | float | 1–10 | Threat severity from semantic analysis | Primary signal; high-severity events are more likely anomalous |
| 2 | `packet_rate` | float | 0–∞ | Packets/sec over a 5 s sliding window | DoS and automated tools produce unnaturally high rates |
| 3 | `msg_id` | float | 0–65535 | MAVLink message ID | Certain message IDs are inherently more suspicious |
| 4 | `intent_encoded` | float | 0–N | Label-encoded intent category | Groups behaviour (RECON, HIJACK, etc.) into a numeric signal |
| 5 | `hour` | float | 0–23 | Hour of day from the event timestamp | Attack campaigns often cluster at specific times |
| 6 | `payload_size` | float | 0–∞ | Decoded payload size in bytes | Abnormally large or small payloads signal fuzzing |

## Intent Categories

The following intent labels are used during encoding:

```
RECON, CONTROL, HIJACK, GPS_SPOOF, MISSION_INJECT,
CONFIG_ATTACK, SENSOR_SPOOF, UNKNOWN
```

Unknown intents default to `"UNKNOWN"` before encoding.

## Feature Importance (typical)

Based on Isolation Forest split frequency on a representative dataset:

1. **severity** — most important split feature (~32 %)
2. **packet_rate** — second (~22 %)
3. **intent_encoded** — third (~18 %)
4. **msg_id** — fourth (~14 %)
5. **payload_size** — fifth (~9 %)
6. **hour** — least (~5 %)

> These values are approximate and vary between training runs.

## Preprocessing

- All features are cast to `float64`.
- Intent is encoded via `sklearn.preprocessing.LabelEncoder` fitted on
  `INTENT_CATEGORIES`.
- Timestamps are converted to hour-of-day (0–23).
- Payload hex strings are decoded to byte length.
- No normalisation or scaling is applied (Isolation Forest is tree-based).

## Training Configuration

| Parameter | Default | Notes |
|-----------|---------|-------|
| `contamination` | 0.10 | Expected fraction of anomalies |
| `n_estimators` | 200 | Number of isolation trees |
| `random_state` | 42 | Reproducibility |
| `max_samples` | "auto" | ≈ min(256, n_samples) |

## Adding New Features

1. Add the feature extraction logic to `AnomalyDetector.predict()`.
2. Append the feature name to `self.feature_names`.
3. Re-train: `python3 ml/train_model.py`.
4. Update this document.
