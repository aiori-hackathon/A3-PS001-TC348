"""
Lab Setup: Synthetic Dummy File Generator
Part of PS-001: Android Ransomware-Like Activity Early Warning in a Controlled Lab.

DEFENSIVE / CONTROLLED LAB USE ONLY:
Creates ~100 harmless synthetic test files with dummy content (text, structured
data, low-entropy repetitive bytes) to represent user shared storage (/sdcard/TestLab).
No real user data is ever touched.
"""

import os
import random
from pathlib import Path

# Base directory for the controlled lab synthetic files
REPO_ROOT = Path(__file__).resolve().parent.parent
LAB_DUMMY_DIR = REPO_ROOT / "dummy_files"

EXTENSIONS = [".txt", ".pdf", ".docx", ".jpg", ".csv", ".xlsx"]

SAMPLE_TEXTS = [
    "Project report draft on network security and distributed consensus protocols.\n",
    "Meeting notes from university research lab discussion on mobile threat detection.\n",
    "Student attendance sheet and evaluation criteria for academic semester.\n",
    "Sample sales telemetry and database migration verification queries.\n",
    "Defensive security lab configuration parameters and firewall baseline.\n"
]

def generate_low_entropy_bytes(size: int = 4096) -> bytes:
    """Generate mock document content with predictable, low Shannon entropy."""
    text = random.choice(SAMPLE_TEXTS)
    repeated = (text * (size // len(text) + 1))[:size]
    return repeated.encode("utf-8")

def setup_dummy_lab(target_dir: Path = LAB_DUMMY_DIR, count: int = 100) -> list:
    """
    Populate target directory with harmless dummy files.
    Returns list of created file paths.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    created_files = []

    print(f"[Lab Setup] Creating {count} synthetic dummy files in {target_dir}...")
    for i in range(1, count + 1):
        ext = EXTENSIONS[i % len(EXTENSIONS)]
        file_path = target_dir / f"user_doc_{i:03d}{ext}"
        
        # Write harmless mock content
        data = generate_low_entropy_bytes(size=random.randint(2048, 8192))
        with open(file_path, "wb") as f:
            f.write(data)
        created_files.append(str(file_path))

    print(f"[Lab Setup] Completed: {len(created_files)} files ready for controlled testing.")
    return created_files

def cleanup_dummy_lab(target_dir: Path = LAB_DUMMY_DIR):
    """Reset lab to clean state."""
    if target_dir.exists():
        for item in target_dir.iterdir():
            if item.is_file():
                item.unlink()
        print(f"[Lab Setup] Cleaned up {target_dir}.")

if __name__ == "__main__":
    setup_dummy_lab()

