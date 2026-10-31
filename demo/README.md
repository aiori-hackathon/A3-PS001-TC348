# 🛡️ PS-001: Demo & Deliverables (Offline Fallback)

**Project Title:** Android Ransomware-Like Activity Early Warning in a Controlled Lab  
**Team Code:** A3-PS001-TC001  
**Team Members:** Jelish G & Swetha C (Karunya Institute of Technology and Sciences)  
**Track:** Defensive Cybersecurity | Controlled Lab Experimentation  

---

## 📌 Overview

This directory contains offline evaluation deliverables and instructions to inspect the demonstration if the live cloud deployment link is temporarily unreachable or undergoing evaluation review.

---

## 📂 Deliverables Included

1. **`PS-001_Early_Warning_Deck.pptx`**:  
   The complete 11-slide presentation deck covering:
   - Problem statement and threat model (Locker vs. Crypto ransomware)
   - Architecture & 5-stage pipeline design
   - Level-1 Data Flow Diagram (DFD)
   - Sliding-window heuristic and Random Forest optimization
   - Evaluation metrics and academic bibliography (HelDroid, CryptoLock, ShieldFS, MITRE ATT&CK T1471)

2. **`dashboard_alert_screenshot.png`**:  
   High-resolution snapshot of the live Streamlit dashboard triggering a **Critical Early Warning Alert** during a burst attack simulation:
   - Early warning fired at **t = 4.0s** (Time-To-Detect: **~2.45 seconds**).
   - Only **7 out of 100 dummy files** (~7.0%) affected before alert interception.
   - Indicators: Burst modification rate (24 ops/s), mass `.locked` renames, Shannon entropy jump (> 7.6).

3. **`dashboard_safe_screenshot.png`**:  
   Snapshot of the dashboard operating under **Normal Safe Baseline** (photo gallery indexing and text editing):
   - Rate < 2.5 ops/s, natural document Shannon entropy (3.5 - 4.2), 0 renames, 0 ransom notes.
   - 0.0% False Positive Rate (FPR).

---

## 🚀 How to Run the Live Dashboard Locally (Offline Mode)

If you have cloned the repository, you can launch the exact interactive dashboard on your local machine with two simple commands:

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch Local Streamlit App
```bash
streamlit run pipeline/dashboard.py
```
The browser will automatically open at `http://localhost:8501`.

### 3. Exploring the Dashboard
- **Sidebar Dropdown**: Switch between the *Attack Run* (demonstrating early warning alert) and *Benign Runs* (demonstrating safe baseline without false alarms).
- **Window Size Slider**: Tune sliding window duration from 1.0s to 5.0s to observe the trade-off between detection latency and stability.
- **Evaluation Tabs**: View the full benchmark table, feature importance ranking, and confusion matrix.

