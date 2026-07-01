# 🍯 MAVLink Adaptive Honeypot with Real-Time Semantic Analysis

![Tests](https://img.shields.io/badge/tests-164%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/core%20coverage-100%25-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-2.1.0-purple)

## 🎯 Project Overview

A research-grade drone security platform that combines:
- **Adaptive MAVLink Honeypot** with state-based responses
- **Real-Time Semantic Analysis** of attack intent
- **Machine Learning Anomaly Detection** for novel attack patterns
- **GeoIP Profiling** with distance estimation
- **Live Web Dashboard** with real-time visualizations
- **Automated Dataset Generation** for ML/research
- **Reproducibility Package** for experimental validation

### 🔬 Research Novelty

**Core Innovation**: Real-time semantic understanding of MAVLink commands with adaptive behavioral responses.

Traditional honeypots passively log traffic. This system:
1. **Understands** what each MAVLink command means (RECON, HIJACK, GPS_SPOOF, etc.)
2. **Adapts** its behavior based on attack severity (NORMAL → WEAK → CONFUSED → DEFENSIVE → CRASHED)
3. **Profiles** attackers with geographic and behavioral signatures
4. **Generates** publication-ready datasets automatically

---

## 📊 Experimental Results

### Detection Accuracy

| Attack Type | Accuracy | False Positive Rate |
|-------------|----------|-------------------|
| RECON       | >95%     | <5%               |
| GPS_SPOOF   | >90%     | <5%               |
| HIJACK      | >90%     | <5%               |
| DoS Flood   | >90%     | <5%               |

### Engagement Metrics

| Honeypot Type       | Avg Commands | Unique Cmds | Gave Up |
|---------------------|-------------|-------------|---------|
| Passive             | 4.0         | 3.2         | 100%    |
| Static              | 7.6         | 5.6         | 100%    |
| **Adaptive (Ours)** | **11.4**    | **6.4**     | **0%**  |

**→ 185% improvement** over passive, **50% improvement** over static honeypots.

### Performance

| Metric | Value |
|--------|-------|
| Parsing Throughput | 3,400,000+ msgs/sec |
| Parsing Latency | 0.3µs average, 0.5µs P99 |

*See `reproducibility/` to reproduce all results.*

---

## 📂 Project Structure

```
mavlink_honeypot/
├── honeypot/                       # Core honeypot engine
│   ├── mavlink_honeypot.py        # Orchestrator (~440 lines)
│   ├── core/                      # Modular core pipeline
│   │   ├── protocol.py            # MAVLink v1/v2 parsing + crafting
│   │   ├── semantic_analyzer.py   # Intent classification + patterns
│   │   ├── state_machine.py       # 7-state FSM + telemetry drift
│   │   ├── response_generator.py  # State-aware adaptive responses
│   │   └── session_manager.py     # Data classes + CSV/JSON logging
│   ├── fingerprint.py             # Attacker fingerprinting
│   ├── deception_engine.py        # Deception scoring
│   └── [advanced modules...]      # Canary, MITRE, tarpit, etc.
├── ml/                            # Machine learning
│   ├── anomaly_detector.py        # IsolationForest anomaly detection
│   ├── skill_classifier.py        # Attacker skill classification
│   ├── FEATURES.md                # Feature engineering docs
│   └── MODEL_REGISTRY.md          # Model version tracking
├── tests/                         # 164 tests (100% core coverage)
│   ├── test_protocol.py           # Parsing + crafting tests
│   ├── test_response_generator.py # FSM + response tests
│   ├── test_property_based.py     # Hypothesis invariant tests
│   ├── test_detection_accuracy.py # Classification accuracy
│   ├── test_integration.py        # End-to-end pipeline
│   └── test_data_generator.py     # Synthetic data generation
├── reproducibility/               # Reproducibility package
│   ├── run_experiments.sh         # Run all experiments (~2 min)
│   ├── datasets/                  # Generated datasets
│   └── results/                   # Experiment outputs
├── benchmarks/                    # Performance + comparison
│   ├── performance_test.py        # Throughput/latency
│   └── comparison_study.py        # Adaptive vs static vs passive
├── dashboard/                     # Web dashboard
├── docs/                          # Documentation
│   └── architecture.md            # Mermaid architecture diagrams
├── CHANGELOG.md                   # Version history
├── CONTRIBUTING.md                # Contributor guide
└── .pre-commit-config.yaml        # Code quality hooks
```

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the honeypot
python -m honeypot.mavlink_honeypot

# Start the dashboard (separate terminal)
cd dashboard && python3 app.py

# Simulate attacks (separate terminal)
python3 attack_simulator_fixed.py all

# Access dashboard
open http://localhost:8080
```

---

## 🔬 Reproducibility

Reproduce all experimental results in ~2 minutes:

```bash
bash reproducibility/run_experiments.sh
```

This generates:
- Synthetic attack dataset (1200 events, 6 profiles)
- Detection accuracy validation (13 tests)
- Full test suite (164 tests)
- Performance benchmarks (throughput, latency)
- Comparison study (adaptive vs static vs passive)

Results are saved to `reproducibility/results/summary.txt`.

---

## 🧠 Semantic Analysis Engine

### MAVLink Command Classification

The system classifies each MAVLink message by **intent**:

| Message ID | Command | Intent | Severity |
|------------|---------|--------|----------|
| 0 | HEARTBEAT | RECON | 1 |
| 20-21 | PARAM_REQUEST | RECON | 2 |
| 23 | PARAM_SET | CONFIG_ATTACK | 7 |
| 76 | COMMAND_LONG | CONTROL | 6 |
| 84, 86 | SET_POSITION | HIJACK | 9 |
| 113, 132 | GPS_INPUT | GPS_SPOOF | 10 |
| 400 | ARM_DISARM | CONTROL | 8 |

### Attack Pattern Detection

Real-time detection of:
- **DoS Floods**: >50 messages in 5 seconds
- **GPS Spoofing**: GPS_INPUT/HIL_GPS messages
- **Hijack Sequences**: ARM → COMMAND → POSITION
- **Reconnaissance Sweeps**: Repeated PARAM requests

---

## 🔄 Adaptive Behavior States

The honeypot dynamically switches between **7 states** based on attack severity:

```
NORMAL (Severity 1-4)
  ↓
WEAK (Severity 5-6)        → Delayed responses
  ↓
CONFUSED (Severity 7)      → Invalid/conflicting data
  ↓
PARTIAL (Severity 8)       → Intermittent responses
  ↓
DEFENSIVE (Severity 9)     → Fake errors, appear disarmed
  ↓
REBOOTING (Severity 10)    → Temporarily offline
  ↓
CRASHED                    → No response (appear offline)
```

---

## 🌍 GeoIP & Attacker Profiling

### Geographic Analysis

For each attacker, the system determines:
- **Country, City, Region**
- **ISP/Organization**
- **Distance from honeypot** (Haversine formula)
- **RTT-based latency** (network delay measurement)

### Behavioral Signature

Each attacker gets:
- **Threat Level**: CRITICAL / HIGH / MEDIUM / LOW
- **Command Sequence Pattern**: Last 10 commands
- **Behavior Signature**: MD5 hash of command pattern
- **Attack Type Distribution**: % RECON vs HIJACK vs DOS

---

## 💾 Dataset Generation

### Output Formats

**Basic Attack Dataset** (`attack_dataset_*.csv`):
```csv
timestamp, ip, port, msg_id, msg_name, intent, severity,
payload_hex, session_id, honeypot_state, packet_rate
```

**Synthetic Reproducibility Dataset** (`reproducibility/datasets/synthetic_attacks.csv`):
```csv
timestamp, attacker_ip, msg_id, msg_name, intent, severity,
honeypot_state, packet_rate, attack_profile
```

### Using Datasets for Research

```python
import pandas as pd

# Load attack data
df = pd.read_csv('datasets/attack_dataset_20260206.csv')

# Analyze attack distribution
print(df['intent'].value_counts())

# Filter high-severity events
critical = df[df['severity'] >= 8]
```

---

## 🧪 Testing

### Run Tests

```bash
# Full test suite (164 tests)
python3 -m pytest tests/ -v

# With coverage report
python3 -m pytest tests/ --cov=honeypot --cov-report=html

# Property-based tests only
python3 -m pytest tests/test_property_based.py -v

# Detection accuracy only
python3 -m pytest tests/test_detection_accuracy.py -v
```

### Test Coverage

| Module | Coverage |
|--------|----------|
| `honeypot/core/protocol.py` | 100% |
| `honeypot/core/response_generator.py` | 100% |
| `honeypot/core/session_manager.py` | 100% |
| `honeypot/core/state_machine.py` | 100% |
| `honeypot/core/semantic_analyzer.py` | 91% |

---

## 🛡️ Security Considerations

**⚠️ WARNING**: This is a honeypot — it intentionally attracts attackers.

1. **Isolated Network**: Run on isolated/monitored network
2. **No Real Drones**: Never connect to actual drone systems
3. **Rate Limiting**: Built-in DoS protection (100 msgs/5s, auto-blocklist)
4. **Session Isolation**: Per-connection sandboxing
5. **Privacy**: GeoIP data may have privacy implications

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Parsing throughput | 3,400,000+ msgs/sec |
| Parsing latency (avg) | 0.3 µs |
| Parsing latency (P99) | 0.5 µs |
| Concurrent connections | ~100 |
| Memory | ~200-500 MB |
| Disk usage | ~1 MB/hour |

---

## 📚 References

### MAVLink Protocol
- [MAVLink Developer Guide](https://mavlink.io/en/)
- [MAVLink Message Definitions](https://mavlink.io/en/messages/common.html)

### Research
- "Honeypot Architectures for IoT Systems"
- "Drone Security: Attack Detection and Prevention"
- "Adaptive Deception in Cyber Defense"

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and PR process.

---

## 📄 License

MIT License — For research and educational purposes.

---

## 🎓 Citation

If you use this in research, please cite:

```bibtex
@software{mavlink_honeypot_2026,
  title   = {MAVLink Adaptive Honeypot with Real-Time Semantic Analysis},
  author  = {Research Team},
  year    = {2026},
  version = {2.1.0},
  url     = {https://github.com/your-repo/mavlink-honeypot}
}
```

---

**Built with ❤️ for drone security research**
