#!/usr/bin/env python3
"""
MAVLink Honeypot — Model Training Script
Finds the largest attack dataset CSV, trains an IsolationForest model,
and saves it for use by the honeypot.
"""

import os
import sys
import glob

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from ml.anomaly_detector import AnomalyDetector


def find_best_dataset(datasets_dir: str) -> str:
    """Find the largest CSV dataset file."""
    csv_files = glob.glob(os.path.join(datasets_dir, "attack_dataset_*.csv"))

    if not csv_files:
        print(f"❌ No CSV datasets found in {datasets_dir}")
        sys.exit(1)

    # Sort by file size (largest first)
    csv_files.sort(key=lambda f: os.path.getsize(f), reverse=True)

    best = csv_files[0]
    size_kb = os.path.getsize(best) / 1024
    print(f"📁 Found {len(csv_files)} datasets")
    print(f"   Selected: {os.path.basename(best)} ({size_kb:.1f} KB)")

    return best


def main():
    print("=" * 60)
    print("🧠 MAVLink Honeypot — Anomaly Detection Model Training")
    print("=" * 60)

    # Paths
    datasets_dir = os.path.join(project_root, "datasets")
    model_dir = os.path.join(project_root, "ml")
    model_path = os.path.join(model_dir, "trained_model.pkl")

    # Find dataset
    dataset_path = find_best_dataset(datasets_dir)

    # Create and train detector
    detector = AnomalyDetector(
        contamination=0.1,
        n_estimators=200,
        random_state=42
    )

    try:
        stats = detector.train(dataset_path)
    except ValueError as e:
        print(f"❌ Training failed: {e}")
        print("   Try running the attack simulator first to generate more data:")
        print("   python3 attack_simulator.py all")
        sys.exit(1)

    # Save model
    detector.save_model(model_path)

    # Summary
    print("\n" + "=" * 60)
    print("📊 Training Summary")
    print("=" * 60)
    print(f"   Dataset:          {os.path.basename(dataset_path)}")
    print(f"   Rows trained:     {stats['rows_trained']}")
    print(f"   Features:         {stats['features']}")
    print(f"   Anomalies found:  {stats['anomalies_found']} ({stats['anomaly_rate']}%)")
    print(f"   Mean score:       {stats['mean_score']}")
    print(f"   Model saved to:   {model_path}")
    print(f"   Trained at:       {stats['trained_at']}")
    print("=" * 60)
    print("\n✅ Model ready! The honeypot will load it automatically on startup.")


if __name__ == "__main__":
    main()
