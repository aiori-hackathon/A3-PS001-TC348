"""
Lab Workload Simulator
Part of PS-001: Android Ransomware-Like Activity Early Warning in a Controlled Lab.

DEFENSIVE / CONTROLLED LAB USE ONLY:
Simulates behavioral runtime traces of both benign apps and ransomware-like attacks
on harmless synthetic dummy files in an isolated lab environment.
NO REAL MALWARE, NO REAL CRYPTOGRAPHIC LOCKING, NO NETWORK THREATS.

Generates structured event telemetry matching Android FileObserver / adb logging:
- timestamp
- event_type (CREATE, MODIFY, RENAME, DELETE)
- file_path
- entropy
- file_size
- workload_label (0 = Benign, 1 = Suspicious / Attack)
"""

import math
import time
import random
from pathlib import Path
from collections import Counter
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
DUMMY_DIR = REPO_ROOT / "dummy_files"

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence (0.0 to 8.0).
    Normal plain text is typically 3.0 - 4.5.
    Encrypted / compressed / pseudo-random data is typically 7.2 - 8.0.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)

def simulate_benign_workload(duration_seconds: int = 15, base_time: float = 0.0) -> list:
    """
    Simulates normal Android activity (Gallery photo loading, document editing, backup).
    Characteristics:
    - Low event rate (1-3 events per second)
    - Low or natural entropy (3.0 - 4.8)
    - Normal extensions, no mass renames
    - Zero ransom note drops
    """
    events = []
    current_time = base_time
    file_ids = list(range(1, 101))

    for step in range(duration_seconds):
        current_time += 1.0
        # 1-3 benign operations per second
        op_count = random.randint(1, 3)
        for _ in range(op_count):
            fid = random.choice(file_ids)
            ext = random.choice([".txt", ".docx", ".pdf", ".jpg"])
            event_type = random.choices(["MODIFY", "CREATE", "DELETE"], weights=[0.75, 0.20, 0.05])[0]
            
            # Natural document text entropy
            entropy = round(random.uniform(3.2, 4.6), 3)
            size = random.randint(2048, 16384)
            path = f"/sdcard/TestLab/user_doc_{fid:03d}{ext}"
            
            events.append({
                "timestamp": round(current_time + random.uniform(0.05, 0.95), 3),
                "event_type": event_type,
                "file_path": path,
                "is_rename": 0,
                "entropy": entropy,
                "file_size": size,
                "is_ransom_note": 0,
                "label": 0  # Benign
            })

    events.sort(key=lambda x: x["timestamp"])
    return events

def simulate_ransomware_attack(duration_seconds: int = 15, base_time: float = 0.0) -> list:
    """
    Simulates defensive crypto-ransomware behavioral fingerprint:
    - Phase 1 (Recon/idle): Normal background events (first 3-4 seconds)
    - Phase 2 (Burst Attack): Mass rapid modification and renaming (12-25 files/sec)
    - High entropy jump (7.3 - 7.95)
    - Renames to mock extension (.locked)
    - Mock dummy ransom note drops (e.g., READ_ME_RESTORE.txt)
    """
    events = []
    current_time = base_time
    file_ids = list(range(1, 101))
    random.shuffle(file_ids)

    # Initial recon / quiet phase (seconds 0 to 3)
    for sec in range(3):
        current_time += 1.0
        fid = file_ids[sec]
        events.append({
            "timestamp": round(current_time + 0.1, 3),
            "event_type": "MODIFY",
            "file_path": f"/sdcard/TestLab/user_doc_{fid:03d}.txt",
            "is_rename": 0,
            "entropy": round(random.uniform(3.5, 4.2), 3),
            "file_size": random.randint(2048, 4096),
            "is_ransom_note": 0,
            "label": 0
        })

    # Rapid Attack Burst Phase (starts at second 4)
    attack_start_time = current_time + 1.0
    attacked_files = file_ids[3:60]
    
    t = attack_start_time
    for i, fid in enumerate(attacked_files):
        # High burst frequency (spread over 4-6 seconds)
        t += random.uniform(0.04, 0.12)
        
        # 1. High entropy modification (simulated ciphertext pattern)
        events.append({
            "timestamp": round(t, 3),
            "event_type": "MODIFY",
            "file_path": f"/sdcard/TestLab/user_doc_{fid:03d}.txt",
            "is_rename": 0,
            "entropy": round(random.uniform(7.45, 7.98), 3),  # High entropy jump
            "file_size": random.randint(3000, 8192),
            "is_ransom_note": 0,
            "label": 1  # Ransomware-like
        })
        
        # 2. Rename operation to simulated locked extension
        t += 0.01
        events.append({
            "timestamp": round(t, 3),
            "event_type": "RENAME",
            "file_path": f"/sdcard/TestLab/user_doc_{fid:03d}.txt.locked",
            "is_rename": 1,
            "entropy": round(random.uniform(7.45, 7.98), 3),
            "file_size": random.randint(3000, 8192),
            "is_ransom_note": 0,
            "label": 1
        })

        # 3. Drop dummy simulated notification file periodically
        if i in [5, 20]:
            t += 0.02
            events.append({
                "timestamp": round(t, 3),
                "event_type": "CREATE",
                "file_path": f"/sdcard/TestLab/MOCK_README_RESTORE_{i}.txt",
                "is_rename": 0,
                "entropy": 4.15,
                "file_size": 512,
                "is_ransom_note": 1,
                "label": 1
            })

    events.sort(key=lambda x: x["timestamp"])
    return events

if __name__ == "__main__":
    benign = simulate_benign_workload(10)
    print(f"Generated {len(benign)} benign events.")
    attack = simulate_ransomware_attack(10)
    print(f"Generated {len(attack)} attack events.")

