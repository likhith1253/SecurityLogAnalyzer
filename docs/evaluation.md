# Evaluation & Performance

The Security Log Analyzer is evaluated based on its detection accuracy, processing efficiency, and data structure performance.

## 1. Detection Metrics

The analysis engine's effectiveness is measured by its ability to correctly categorize events:

| Metric | Measurement Basis |
| :--- | :--- |
| **Precision** | Accuracy of identifying truly malicious requests vs. false positives (e.g., legitimate 404s). |
| **Recall** | Ability to detect all known attack patterns (SQLi, LFI) present in the log. |
| **Threat Sensitivity** | Tuning via `config.properties` allows adjustment of threat score weights. |

## 2. Technical Performance

The system utilizes highly optimized components to handle large datasets:

- **Red-Black Tree Complexity**:
    - **Insertion**: $O(\log n)$
    - **Search**: $O(\log n)$
    - **Range Query**: $O(\log n + k)$, where $k$ is the number of elements in the range. 
    - This ensures that even with 100,000+ logs, query performance remains near-instant.

- **Memory Efficiency**:
    - Log records are stored as lightweight objects.
    - Geolocation data is cached in a Hash Map to avoid redundant calculations.

## 3. Measurements and tests

No benchmark figures are published for this project. The earlier table of timings/memory in this file was illustrative and not backed by recorded measurements, so it was removed.

What is verified today (`java -cp out com.sla.SlaTests`, see the README):
- Red-Black Tree validity and ordering after randomized inserts and deletes
- Log parsing of valid and malformed lines
- Blacklist persistence round-trip
- Password hashing, login and role-based IP redaction
