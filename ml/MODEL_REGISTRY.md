# Model Registry

Tracks all trained anomaly-detection model versions.

## Current Model

| Field | Value |
|-------|-------|
| **Version** | `v1.0.0` |
| **Algorithm** | Isolation Forest |
| **Path** | `ml/trained_model.pkl` |
| **Features** | severity, packet_rate, msg_id, intent_encoded, hour, payload_size |
| **Contamination** | 0.10 |
| **Estimators** | 200 |

## Version History

| Version | Date | Dataset | Rows | Anomaly Rate | Notes |
|---------|------|---------|------|-------------|-------|
| v1.0.0 | Initial | `attack_dataset_*.csv` | varies | ~10 % | Baseline model |

## Versioning Convention

Models follow semantic versioning:
- **Major**: New feature set or algorithm change
- **Minor**: Re-training on significantly larger/different data
- **Patch**: Hyperparameter tuning, same data

## How to Train a New Version

```bash
python3 ml/train_model.py
```

The script will:
1. Find the largest CSV in `datasets/`
2. Train an Isolation Forest with 5-fold cross-validation
3. Save the model to `ml/trained_model.pkl`
4. Print a training summary with anomaly rate and mean score
