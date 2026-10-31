"""
Pipeline Feature Extractor
Part of PS-001: Android Ransomware-Like Activity Early Warning in a Controlled Lab.

DEFENSIVE / CONTROLLED LAB USE ONLY:
Transforms timestamped FileObserver / adb file events into short sliding window features
(1 to 5 seconds) to catch ransomware burst patterns before irreversible damage occurs.
"""

from pathlib import Path
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_ENTROPY = 4.0

def compute_heuristic_risk_score(
    change_rate: float,
    rename_count: int,
    mean_entropy: float,
    note_drops: int
) -> float:
    """
    Weighted baseline rule-based risk score (0.0 to 1.0).
    Inspired by CryptoLock and ShieldFS behavioral indicators:
    - Bursty file modifications (30% weight)
    - Extension modifications / mass renames (30% weight)
    - High Shannon entropy above baseline (25% weight)
    - Ransom note presence (15% weight)
    """
    rate_score = min(change_rate / 15.0, 1.0)
    rename_score = min(rename_count / 8.0, 1.0)
    entropy_score = max(0.0, min((mean_entropy - BASELINE_ENTROPY) / 3.5, 1.0))
    note_score = 1.0 if note_drops > 0 else 0.0

    total_risk = (
        0.30 * rate_score +
        0.30 * rename_score +
        0.25 * entropy_score +
        0.15 * note_score
    )
    return round(float(total_risk), 4)

def extract_sliding_windows(
    events_df: pd.DataFrame,
    window_size: float = 3.0,
    step_size: float = 1.0
) -> pd.DataFrame:
    """
    Extract sliding window features from raw event log.
    
    Parameters:
        events_df: DataFrame with ['timestamp', 'event_type', 'is_rename', 'entropy', 'is_ransom_note', 'label']
        window_size: Duration of analysis window in seconds (1.0 to 5.0 s)
        step_size: Window slide stride in seconds
    
    Returns:
        DataFrame of windowed features.
    """
    if events_df.empty:
        return pd.DataFrame()

    min_time = events_df["timestamp"].min()
    max_time = events_df["timestamp"].max()

    window_records = []
    current_start = min_time

    while current_start + window_size <= max_time + step_size:
        current_end = current_start + window_size
        
        # Filter events falling inside current time slice
        mask = (events_df["timestamp"] >= current_start) & (events_df["timestamp"] < current_end)
        w_events = events_df[mask]

        if not w_events.empty:
            count = len(w_events)
            change_rate = round(count / window_size, 2)
            renames = int(w_events["is_rename"].sum())
            deletes = int((w_events["event_type"] == "DELETE").sum())
            note_drops = int(w_events["is_ransom_note"].sum())
            mean_entropy = round(float(w_events["entropy"].mean()), 3)
            max_entropy = round(float(w_events["entropy"].max()), 3)
            entropy_jump = round(max(0.0, mean_entropy - BASELINE_ENTROPY), 3)
            label = 1 if (w_events["label"] == 1).any() else 0
        else:
            change_rate = 0.0
            renames = 0
            deletes = 0
            note_drops = 0
            mean_entropy = BASELINE_ENTROPY
            max_entropy = BASELINE_ENTROPY
            entropy_jump = 0.0
            label = 0

        risk_score = compute_heuristic_risk_score(
            change_rate=change_rate,
            rename_count=renames,
            mean_entropy=mean_entropy,
            note_drops=note_drops
        )

        window_records.append({
            "window_start": round(current_start, 2),
            "window_end": round(current_end, 2),
            "file_change_rate": change_rate,
            "rename_count": renames,
            "delete_count": deletes,
            "mean_entropy": mean_entropy,
            "max_entropy": max_entropy,
            "entropy_jump": entropy_jump,
            "ransom_note_count": note_drops,
            "heuristic_risk_score": risk_score,
            "label": label
        })

        current_start += step_size

    return pd.DataFrame(window_records)

if __name__ == "__main__":
    from lab.ransomware_simulator import simulate_ransomware_attack
    events = pd.DataFrame(simulate_ransomware_attack(10))
    windows = extract_sliding_windows(events)
    print(windows.head())

