# Reproducibility Package

This directory contains everything needed to reproduce the experimental results presented in the paper.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt requirements-dev.txt

# Run all experiments (~2 minutes)
bash reproducibility/run_experiments.sh

# View results
cat reproducibility/results/summary.txt
```

## What Gets Reproduced

| Experiment | Script | Output |
|-----------|--------|--------|
| Synthetic dataset generation | `run_experiments.sh` step 1 | `datasets/synthetic_attacks.csv` |
| Detection accuracy validation | `run_experiments.sh` step 2 | `results/detection_accuracy.txt` |
| ML model cross-validation | `run_experiments.sh` step 3 | `results/ml_metrics.json` |
| Performance benchmarks | `run_experiments.sh` step 4 | `results/performance.txt` |
| Comparison study | `run_experiments.sh` step 5 | `results/comparison.json` |

## Requirements

- Python 3.9+
- All dependencies: `pip install -r requirements.txt requirements-dev.txt`
- ~100MB disk space for datasets
- ~2 minutes runtime on modern hardware

## Results Directory

After running experiments, `results/` will contain:

```
results/
├── summary.txt           # Human-readable summary of all results
├── detection_accuracy.txt # pytest output for detection tests
├── ml_metrics.json        # Cross-validation scores
├── performance.txt        # Throughput and latency metrics
└── comparison.json        # Adaptive vs static vs passive comparison
```

## Verifying Claims

### Claim 1: "Detection accuracy >95% for RECON, >90% for GPS spoofing"
→ Check `results/detection_accuracy.txt`

### Claim 2: "Adaptive honeypot keeps attackers engaged 3× longer"
→ Check `results/comparison.json` → `improvement_pct` field

### Claim 3: "Throughput >5000 msgs/sec"
→ Check `results/performance.txt` → `throughput` line

## Re-running Individual Experiments

```bash
# Just detection accuracy
python3 -m pytest tests/test_detection_accuracy.py -v

# Just performance benchmarks
python3 benchmarks/comparison_study.py

# Just ML training
python3 ml/train_model.py
```
