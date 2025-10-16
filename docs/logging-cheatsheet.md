## Logging & Telemetry Cheatsheet

### QoSD on OpenWrt
- Tail local syslog for structured QoSD events:
  ```sh
  logread | grep qosd
  ```
- Trigger live snapshot and inspect persona output:
  ```sh
  ubus call qosd live '{"limit":25}'
  ```

### Fluent Bit (Ubuntu Docker stack)
- Follow logs and watch HTTP/ES deliveries:
  ```sh
  docker-compose logs -f fluent-bit
  ```
- Fetch Fluent Bit metrics API (CPU, backpressure, retries):
  ```sh
  curl -s http://localhost:2020/api/v1/metrics | jq
  ```

### Collector API
- Recent ingested events:
  ```sh
  curl -s http://localhost:4000/telemetry/recent | jq
  ```
- Persona aggregation / counts:
  ```sh
  curl -s http://localhost:4000/telemetry/persona | jq
  ```
- Policy document for a persona (e.g. streaming):
  ```sh
  curl -s http://localhost:4000/policy/streaming | jq
  ```

### OpenSearch
- Index health / document count:
  ```sh
  curl -s http://localhost:9200/_cat/indices/my-app-logs*?v
  ```
- Search QoSD events (adjust query as needed):
  ```sh
  curl -s http://localhost:9200/my-app-logs*/_search \
    -H 'Content-Type: application/json' \
    -d '{"query":{"match":{"event":"qosd_live"}},"size":5}' | jq
  ```

### LuCI via SSH tunnel (Windows host)
- Forward HTTP/HTTPS (run in PowerShell):
  ```powershell
  ssh -N -L 8080:192.168.10.1:80 -L 8443:192.168.10.1:443 bariscanatakli@10.10.1.104
  ```
- Test tunnel locally:
  ```powershell
  curl.exe http://127.0.0.1:8080/
  curl.exe -k https://127.0.0.1:8443/
  ```
- Browser access: `http://127.0.0.1:8080/cgi-bin/luci/` or `https://127.0.0.1:8443/`.

### Namespace Client (Ubuntu)
- Show interface status inside `lanclient` namespace:
  ```sh
  sudo ip netns exec lanclient ip addr show veth-ns
  ```
- Generate sample traffic (curl, wget, iperf):
  ```sh
  sudo ip netns exec lanclient curl -I https://example.com
  sudo ip netns exec lanclient wget https://speed.hetzner.de/100MB.bin -O /dev/null
  sudo ip netns exec lanclient iperf3 -c <target> -u -b 5M -t 30
  ```
