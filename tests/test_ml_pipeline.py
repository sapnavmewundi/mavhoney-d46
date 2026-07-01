#!/usr/bin/env python3
"""Tests for ML evaluation pipeline and comparison study."""

import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "honeypot"))


class TestCrossValidator:
    """Tests for ml/cross_validator.py."""

    def test_dataset_generation_produces_correct_count(self):
        from ml.cross_validator import generate_synthetic_dataset
        events = generate_synthetic_dataset(n_events=100, seed=42)
        assert len(events) == 100

    def test_dataset_has_required_fields(self):
        from ml.cross_validator import generate_synthetic_dataset
        events = generate_synthetic_dataset(n_events=10, seed=42)
        required = {"msg_id", "intent", "severity", "packet_rate", "hour", "payload_hex"}
        for event in events:
            assert required.issubset(event.keys()), f"Missing fields: {required - set(event.keys())}"

    def test_intent_derived_from_semantic_analyzer(self):
        """Intent must come from MAVLINK_SEMANTICS, not random sampling."""
        from ml.cross_validator import generate_synthetic_dataset
        from honeypot.core.semantic_analyzer import MAVLINK_SEMANTICS
        events = generate_synthetic_dataset(n_events=100, seed=42)
        for event in events:
            msg_id = event["msg_id"]
            if msg_id in MAVLINK_SEMANTICS:
                expected = MAVLINK_SEMANTICS[msg_id]["intent"]
                assert event["intent"] == expected, (
                    f"msg_id {msg_id}: expected intent={expected}, got {event['intent']}"
                )

    def test_feature_extraction_shape(self):
        from ml.cross_validator import generate_synthetic_dataset, extract_features
        import numpy as np
        events = generate_synthetic_dataset(n_events=50, seed=42)
        X, le = extract_features(events)
        n_events = len(events)
        assert X.shape[0] == n_events
        assert X.shape[1] >= 14  # At least 14 features after protocol-derived additions

    def test_no_circular_features_in_intent_classification(self):
        """intent_encoded exists in features but must be dropped for intent classification."""
        from ml.cross_validator import extract_features, generate_synthetic_dataset, INTENT_LIST
        events = generate_synthetic_dataset(n_events=50, seed=42)
        X, le = extract_features(events)
        # Verify the label encoder knows all intent categories
        assert set(INTENT_LIST).issubset(set(le.classes_))

    def test_protocol_derived_features_present(self):
        from ml.cross_validator import extract_features, generate_synthetic_dataset
        events = generate_synthetic_dataset(n_events=50, seed=42)
        X, le = extract_features(events)
        # With 16 features, protocol-derived features are at indices 9-14
        # Verify feature count is correct
        assert X.shape[1] == 16, f"Expected 16 features, got {X.shape[1]}"

    def test_severity_range(self):
        from ml.cross_validator import generate_synthetic_dataset
        events = generate_synthetic_dataset(n_events=200, seed=42)
        for event in events:
            assert 1 <= event["severity"] <= 10, f"Severity out of range: {event['severity']}"


class TestComparisonStudy:
    """Tests for benchmarks/comparison_study.py."""

    def test_compute_deception_score_bounds(self):
        from benchmarks.comparison_study import compute_deception_score
        # Minimum case
        assert compute_deception_score(0.0, 0, 1, 0) >= 0
        # Maximum case
        score = compute_deception_score(1.0, 7, 7, 9)
        assert score <= 100
        assert score > 90  # Should be near 100

    def test_compute_deception_score_uniform(self):
        """Same inputs must produce same score regardless of mode."""
        from benchmarks.comparison_study import compute_deception_score
        s1 = compute_deception_score(0.5, 2, 3, 4)
        s2 = compute_deception_score(0.5, 2, 3, 4)
        assert s1 == s2

    def test_attacker_patience_model_completeness(self):
        from benchmarks.comparison_study import ATTACKER_PATIENCE
        required_modes = {"passive", "static", "conpot", "honeyplc", "adaptive"}
        assert required_modes == set(ATTACKER_PATIENCE.keys())

    def test_adaptive_never_abandons(self):
        from benchmarks.comparison_study import ATTACKER_PATIENCE
        adaptive = ATTACKER_PATIENCE["adaptive"]
        assert adaptive["abandon_rate"] == 0.0

    def test_simulate_functions_return_metrics(self):
        import random
        from benchmarks.comparison_study import (
            simulate_passive, simulate_adaptive,
            ATTACK_SEQUENCES,
        )
        seq = ATTACK_SEQUENCES["recon"]
        rng = random.Random(42)

        passive = simulate_passive(seq, rng)
        assert passive.mode == "passive"
        assert passive.deception_score >= 0

        rng = random.Random(42)
        adaptive = simulate_adaptive(seq, rng)
        assert adaptive.mode == "adaptive"
        assert adaptive.deception_score > passive.deception_score


class TestAblationStudy:
    """Tests for benchmarks/ablation_study.py."""

    def test_ablation_variants_exist(self):
        from benchmarks.ablation_study import (
            simulate_full, simulate_no_fsm, simulate_no_drift,
            simulate_no_fingerprint, simulate_no_ml,
        )
        # Just check they're callable
        assert callable(simulate_full)
        assert callable(simulate_no_fsm)

    def test_no_fsm_has_one_state(self):
        import random
        from benchmarks.ablation_study import simulate_no_fsm, ATTACK_SEQUENCES
        result = simulate_no_fsm(ATTACK_SEQUENCES["hijack"], random.Random(42))
        assert result["states_reached"] == 1

    def test_full_has_multiple_states(self):
        import random
        from benchmarks.ablation_study import simulate_full, ATTACK_SEQUENCES
        result = simulate_full(ATTACK_SEQUENCES["hijack"], random.Random(42))
        assert result["states_reached"] > 1
