from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class ConfusionMatrix:
    actual_benign_true_negative: int
    actual_benign_false_positive: int
    actual_attack_false_negative: int
    actual_attack_true_positive: int

    @property
    def total(self) -> int:
        return (
            self.actual_benign_true_negative
            + self.actual_benign_false_positive
            + self.actual_attack_false_negative
            + self.actual_attack_true_positive
        )


@dataclass(frozen=True)
class MetricRow:
    attack_typology: str
    precision: float
    recall: float
    false_positive_rate: float
    f1_score: float


@dataclass(frozen=True)
class LatencyStage:
    stage: str
    latency_ms: str


@dataclass(frozen=True)
class BaselinePoint:
    architecture: str
    latency_ms: float
    f1_score: float


@dataclass(frozen=True)
class AblationRow:
    label: str
    f1_score: str
    second_metric: str
    third_metric: str


@dataclass(frozen=True)
class AblationStudy:
    title: str
    headers: Tuple[str, str, str, str]
    rows: Tuple[AblationRow, ...]
    starred_label: str


CONFUSION_MATRIX = ConfusionMatrix(
    actual_benign_true_negative=9675,
    actual_benign_false_positive=325,
    actual_attack_false_negative=195,
    actual_attack_true_positive=9805,
)

ATTACK_METRICS = (
    MetricRow("TCP SYN Flood", 0.985, 0.991, 1.2, 0.988),
    MetricRow("UDP Amplification", 0.980, 0.986, 1.8, 0.983),
    MetricRow("HTTP POST Flood", 0.958, 0.963, 4.1, 0.960),
    MetricRow("Slowloris (Layer 7)", 0.941, 0.948, 5.9, 0.944),
    MetricRow("System Weighted Avg", 0.975, 0.973, 3.25, 0.974),
)

LATENCY_BREAKDOWN = (
    LatencyStage("P4 Pipeline Match & CMS Accounting", "< 0.1"),
    LatencyStage("Digest Generation & Switch Queuing", "3.4"),
    LatencyStage("gRPC Network Transmission (Switch -> Controller)", "10.2"),
    LatencyStage("Feature Vector Assembly (Redis Fetch)", "2.1"),
    LatencyStage("XGBoost Algorithmic Inference", "1.8"),
    LatencyStage("P4Runtime Rule Installation (Controller -> Switch)", "10.5"),
    LatencyStage("Total End-to-End Latency", "28.0 ms"),
)

ROC_GOSSIP_FPR = (0.00, 0.05, 0.12, 0.25, 0.50, 1.00)
ROC_GOSSIP_TPR = (0.00, 0.65, 0.78, 0.85, 0.92, 1.00)
ROC_OURS_FPR = (0.00, 0.01, 0.03, 0.08, 0.15, 1.00)
ROC_OURS_TPR = (0.00, 0.88, 0.973, 0.985, 0.992, 1.00)

FEATURE_IMPORTANCE = (
    ("TCP Flags", 0.04),
    ("Size Variance", 0.05),
    ("Port Diversity", 0.07),
    ("Protocol Variance", 0.09),
    ("Inter-Arrival", 0.12),
    ("Duration", 0.16),
    ("Byte Rate", 0.21),
    ("Packet Rate", 0.26),
)

LATENCY_COMPARISON = (
    BaselinePoint("Jaqen", 1.0, 0.890),
    BaselinePoint("P4-XGBoost", 28.0, 0.974),
    BaselinePoint("Gossip (RM)", 70.0, 0.904),
    BaselinePoint("FlowLens", 75.0, 0.950),
    BaselinePoint("POSEIDON", 120.0, 0.980),
    BaselinePoint("Gossip (AE)", 150.0, 0.904),
    BaselinePoint("Gossip (Epi)", 200.0, 0.431),
)

ACCURACY_COMPARISON = (
    BaselinePoint("Gossip (Epi)", 200.0, 0.431),
    BaselinePoint("Jaqen", 1.0, 0.890),
    BaselinePoint("Gossip (RM)", 70.0, 0.904),
    BaselinePoint("Gossip (AE)", 150.0, 0.904),
    BaselinePoint("FlowLens", 75.0, 0.950),
    BaselinePoint("P4-XGBoost", 28.0, 0.974),
    BaselinePoint("POSEIDON", 120.0, 0.980),
)

ABLATION_STUDIES = (
    AblationStudy(
        title="Ablation 1: Impact of Feature Set Dimensionality",
        headers=("Feature Set", "F1-Score", "False Pos.", "Ext. Time"),
        starred_label="Full (8 Features) *",
        rows=(
            AblationRow("Full (8 Features) *", "0.974", "3.25%", "2.1 ms"),
            AblationRow("Basic (4 Features)", "0.932", "7.40%", "1.2 ms"),
            AblationRow("Minimal (2 Features)", "0.891", "14.20%", "0.5 ms"),
        ),
    ),
    AblationStudy(
        title="Ablation 2: Memory Granularity (CMS Register Width)",
        headers=("Register Width", "F1-Score", "False Pos.", "SRAM Constraint"),
        starred_label="Width 1024 *",
        rows=(
            AblationRow("Width 256", "0.880", "12.0%", "Fit"),
            AblationRow("Width 512", "0.920", "8.0%", "Fit"),
            AblationRow("Width 1024 *", "0.974", "3.25%", "Optimal"),
            AblationRow("Width 2048", "0.976", "2.90%", "Exceeds ASIC Limits"),
        ),
    ),
    AblationStudy(
        title="Ablation 3: Impact of Bloom Deduplication Logic",
        headers=("Deduplication Scope", "Max Alerts", "Ctrl CPU Load", "Latency Penalty"),
        starred_label="Standard Bloom *",
        rows=(
            AblationRow("No Deduplication", "Sat. (1.2M/s)", "100% (Crashing)", "High"),
            AblationRow("Standard Bloom *", "1024/s Max", "8%", "Zero"),
        ),
    ),
    AblationStudy(
        title="Ablation 4: XGBoost Maximum Tree Depth",
        headers=("Max Tree Depth", "F1-Score", "Inference", "Latency SLA"),
        starred_label="Depth 6 *",
        rows=(
            AblationRow("Depth 3", "0.910", "0.5 ms", "Compliant"),
            AblationRow("Depth 6 *", "0.974", "1.8 ms", "Compliant"),
            AblationRow("Depth 9", "0.978", "8.4 ms", "Violation Risk"),
        ),
    ),
    AblationStudy(
        title="Ablation 5: Threshold Parameter (T) Tuning",
        headers=("Threshold (T)", "FPR", "Total Delay", "Observation"),
        starred_label="T = 100 *",
        rows=(
            AblationRow("T = 10", "15.20%", "12 ms", "Aggressive but High FP"),
            AblationRow("T = 100 *", "3.25%", "28 ms", "Optimal SLA Balance"),
            AblationRow("T = 500", "0.80%", "85 ms", "SLA Violation (>50ms)"),
        ),
    ),
    AblationStudy(
        title="Ablation 6: Temporal Window Reset Interval (W)",
        headers=("Window Reset (W)", "F1-Score", "Impact / Observation", ""),
        starred_label="W = 1.0s *",
        rows=(
            AblationRow("W = 0.1s", "0.850", "Misses Low-Rate Threats (Slowloris)", ""),
            AblationRow("W = 1.0s *", "0.974", "Optimal Capture Interval", ""),
            AblationRow("W = 5.0s", "0.910", "Accumulates Benign Drops / High FP", ""),
        ),
    ),
)
