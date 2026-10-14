# PS-001: Android Ransomware-Like Activity Early Warning in a Controlled Lab

## 1. Problem Statement

Traditional signature-based antivirus tools may fail to detect new or zero-day ransomware because its malicious signature may not yet be available in their databases. On Android devices, application sandboxing also limits security software from directly inspecting other applications' memory. However, ransomware-like activity can be identified through suspicious file-system behaviour, such as rapidly opening, rewriting, and renaming multiple files. Therefore, the problem is to develop a behaviour-based early-warning detection system that monitors file operations in an explicitly accessible test directory within a controlled Android emulator or rooted laboratory device. The system should detect suspicious activity, generate an alert, and stop only the controlled test workload before further file changes occur.

## 2. What the Problem Statement Is Saying

The main idea is to detect ransomware-like behaviour based on what a process does rather than relying only on known malware signatures. When ransomware operates, it may rapidly modify and rename files. By monitoring these observable file-system events, the proposed system should identify suspicious patterns and provide an early warning. The project must be conducted safely in a controlled laboratory environment using harmless simulations rather than real ransomware. It must not claim to protect the entire Android device or monitor other applications on a standard, non-rooted Android device.

## 3. Expectations and Key Requirements

The project is expected to use one Android emulator or rooted laboratory device with documented monitoring capabilities. It must monitor a specific test directory and evaluate the detector using two benign workloads and three harmless ransomware-like simulations. The system must measure detection delay, the number of files changed before an alert, precision, and recall. Detection must be based on observable behaviour, and the system must stop only the controlled test workload responsible for the simulated suspicious activity.

## 4. What We Are Going to Do

We are going to develop a prototype that monitors file-system events within a designated directory in an instrumented Android laboratory environment. First, we will configure the emulator or rooted lab device and create sample test files. Next, we will run two normal workloads and three harmless ransomware-like simulations that imitate rapid file rewriting and renaming without using actual malware. The detector will analyse the observed events, identify suspicious activity based on defined behavioural thresholds, generate an alert, and stop the controlled test workload when necessary. We will record event logs and evaluate the system using detection delay, files changed before alert, precision, and recall.

## 5. Expected Output

The final output will be a working behaviour-based ransomware early-warning prototype demonstrated in a controlled Android lab. It will include safe simulation scripts, file-system event and telemetry logs, alert results, and an evaluation report covering detection delay, files changed before alert, precision, and recall. We will also provide documentation of the Android instrumentation and test setup, pseudocode explaining the detection logic, and a demonstration for the mentor. The project will show how suspicious file activity can be detected early without using real ransomware or making unsupported claims about device-wide protection.
