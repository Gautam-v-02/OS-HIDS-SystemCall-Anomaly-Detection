This project implements a **Host-Based Intrusion Detection System (HIDS)** that detects malicious activity by analyzing **operating system system-call patterns**.  
Instead of relying on predefined attack signatures, the system uses **anomaly detection** to identify abnormal behavior at the OS level.

The project is based on a **machine-learning technique called Isolation Forest**, which isolates anomalous data points faster than normal ones.  
Processes that show unusual system-call frequency patterns are flagged as potential intrusions.

---

## Key Concepts Used
- Operating System System Calls
- Host-Based Intrusion Detection System (HIDS)
- Anomaly Detection
- Isolation Forest Algorithm
- OS-Level Security

---

## Algorithm Used: Isolation Forest
Isolation Forest works on the principle that **anomalies are easier to isolate** than normal data points.

Steps involved:
1. Randomly select system-call features
2. Randomly split data to build isolation trees
3. Calculate isolation path length for each process
4. Convert path length into an anomaly score
5. Classify processes as NORMAL or INTRUSION

---

