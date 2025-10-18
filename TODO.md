## QoSD / Telemetry TODOs

- [x] Filter out non-LAN peers in `qosd_live` snapshots (ignore public IP destinations when building host list).
- [ ] Optional: separate view for WAN endpoints if correlation is needed later.
- [x] Implement reference-aligned UCI persona/policy loader inspired by context-aware QoS provisioning (Dong et al., IEEE Access 2019) to hydrate runtime schemas safely.
- [x] Emit structured policy decision traces following self-driving network observability loops (Feamster, ACM Queue 2017) for downstream analytics.
- [x] Real classification: extend flow feature extraction with SNI, QUIC ALPN and JA3/JA4 fingerprints per Morton & Hoeiland-Joergensen 2023 guidance on latency-aware prioritisation.
- [x] Real classification: integrate lightweight DPI signatures (nDPI/Netify style) for encrypted/unencrypted traffic referencing Nichols & Jacobson 2012 bufferbloat mitigation needs.
- [ ] Real classification: stream flow metadata to a TinyML persona model (Al-Somaidai et al., Computer Networks 2022) and add training pipeline hooks.
- [ ] Real classification: fuse OpenSearch telemetry feedback to continuously relabel personas (Feamster 2017 self-driving networks) and update classifier thresholds.
- [ ] Real classification: harden ground-truth capture by tagging flows via LuCI UI actions and storing labels for supervised refinement (Bentaleb et al., IEEE Comms Surveys 2017).
- [x] Real classification: build collector-side enrichment service that correlates conntrack IDs with OpenSearch feedback and exposes `/snapshot/lan` persona snapshots for QoSD/LuCI.
- [x] Real classification: implement conflict-resolution heuristics (e.g. EWMA + min-confidence gates) so personas remain stable across samples (Dong et al. 2019).
- [x] Real classification: extend LuCI dashboard to pull persona snapshots through `L.rpc.declare` and render device type, confidence, RTT, and policy action in real time.
