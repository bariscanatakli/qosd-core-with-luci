## Lab Session Summary (2025-10-16)

### 1. Topology & Infrastructure
- **Windows Host** runs SSH tunnels for LuCI access (`8080 → 192.168.10.1:80`, `8443 → :443`).
- **VirtualBox Ubuntu Server (10.10.1.104)**  
  - WAN NAT bridge: `tap-wan 10.200.0.1/24` → `enp0s3` (MASQUERADE).  
  - LAN bridge: `br-lan-host 192.168.10.254/24` connecting `tap-lan`, optional `tap-client`, and `veth-client`.
  - Namespace `lanclient` emulates an OpenWrt LAN device.
  - Docker Compose stack (Fluent Bit → Collector API → OpenSearch/Dashboards + log-generator) provides telemetry pipeline.
- **QEMU OpenWrt VM**  
  - WAN `eth0` (virtio) static `10.200.0.2/24`, gateway `10.200.0.1`.  
  - LAN `br-lan` (eth1) `192.168.10.1/24`, DHCP server enabled.  
  - `qosd` daemon logs persona metadata via syslog → Fluent Bit.

Supporting diagrams: `docs/network-topology.md`.

### 2. Network Preparation Steps
1. Created TAPs/bridge on Ubuntu:
   ```bash
   sudo ip tuntap add dev tap-wan mode tap user $USER
   sudo ip tuntap add dev tap-lan mode tap user $USER
   sudo ip link add br-lan-host type bridge
   sudo ip addr add 192.168.10.254/24 dev br-lan-host
   sudo ip link set br-lan-host up
   sudo ip link set tap-wan up
   sudo ip link set tap-wan master br-lan-host   # for LAN taps use br-lan-host
   ```
   (Re-run after reboot; consider a systemd script)

2. QEMU OpenWrt launch:
   ```bash
   qemu-system-aarch64 \
     -M virt -cpu cortex-a72 -m 512M -nographic \
     -kernel openwrt-24.10.2-armsr-armv8-generic-kernel.bin \
     -drive if=virtio,file=openwrt-24.10.2-armsr-armv8-generic-ext4-rootfs.img,format=raw \
     -append "root=/dev/vda rootfstype=ext4 console=ttyAMA0" \
     -netdev tap,id=wan,ifname=tap-wan,script=no,downscript=no \
     -device virtio-net-pci,netdev=wan,mac=52:54:00:00:00:01 \
     -netdev tap,id=lan,ifname=tap-lan,script=no,downscript=no \
     -device virtio-net-pci,netdev=lan,mac=52:54:00:00:00:02
   ```

3. OpenWrt network config (summary):
   ```sh
   uci set network.lan.proto='static'
   uci set network.lan.ipaddr='192.168.10.1'
   uci set network.lan.netmask='255.255.255.0'
   uci set network.lan.device='br-lan'
   uci set network.br_lan=device
   uci set network.br_lan.type='bridge'
   uci set network.br_lan.ports='eth1'
   uci set network.wan=interface
   uci set network.wan.device='eth0'
    # static WAN
   uci set network.wan.proto='static'
   uci set network.wan.ipaddr='10.200.0.2'
   uci set network.wan.netmask='255.255.255.0'
   uci set network.wan.gateway='10.200.0.1'
   uci set network.wan.dns='8.8.8.8 1.1.1.1'
   uci commit network
   /etc/init.d/network restart
   ```
   LuCI installed (`opkg install luci luci-ssl`) and uhttpd enabled.

4. Namespace client:
   ```bash
   sudo ip link add veth-client type veth peer name veth-ns
   sudo ip link set veth-client master br-lan-host
   sudo ip link set veth-client up

   sudo ip netns add lanclient
   sudo ip link set veth-ns netns lanclient
   sudo mkdir -p /etc/netns/lanclient
   printf "nameserver 192.168.10.1\nnameserver 8.8.8.8\n" | sudo tee /etc/netns/lanclient/resolv.conf
   sudo ip netns exec lanclient ip link set lo up
   sudo ip netns exec lanclient ip link set veth-ns up
   sudo ip netns exec lanclient /bin/busybox udhcpc -i veth-ns -s /usr/share/udhcpc/default.script
   ```
   (Gerekirse IP/route manuel: `ip addr add 192.168.10.x/24 dev veth-ns`, `ip route add default via 192.168.10.1`)

5. SSH tunnel from Windows:
   ```powershell
   ssh -N -L 8080:192.168.10.1:80 -L 8443:192.168.10.1:443 bariscanatakli@10.10.1.104
   ```
   Browser: `http://127.0.0.1:8080/cgi-bin/luci/`.

### 3. Telemetry Pipeline Verification
- Docker Compose stack (Fluent Bit, Collector API, OpenSearch/Dashboards, log-generator) is up – see `docker-compose logs -f`.
- QoSD logs reach Fluent Bit (HTTP output 200) and OpenSearch indices `my-app-logs-*`.
- Collector aggregation reachable via:
  ```bash
  curl -s http://localhost:4000/telemetry/recent | jq
  curl -s http://localhost:4000/telemetry/persona | jq
  ```
- OpenSearch queries confirm persona metadata:
  ```bash
  curl -s http://localhost:9200/_cat/indices/my-app-logs*?v
  curl -s http://localhost:9200/my-app-logs*/_search \
    -H 'Content-Type: application/json' \
    -d '{"query":{"match":{"event":"qosd_live"}},"size":5,"sort":[{"@timestamp":{"order":"desc"}}]}' | jq
  ```

### 4. Traffic Scenarios Executed
| Scenario | Command(s) | Expected Persona |
|----------|------------|------------------|
| Bulk HTTP download | `wget http://ipv4.download.thinkbroadband.com/100MB.zip -O /dev/null` | Currently falls under `work` (heuristic tweak recommended) |
| VoIP-like UDP | `iperf3 -s -p 3478` + `iperf3 -u -c 192.168.10.254 -b 3M -t 30 -p 3478` | Classified as `latency` |
| Gaming port test | `iperf3 -s -p 27015` + client run | Also `latency` (no `gaming` yet) |
| DNS hints | `dig zoom.us`, `curl -I https://www.netflix.com` | Helps streaming/voip heuristics |
| Manual persona test | `ubus call qosd classify '{"service_hint":"game", ...}'` | Force `gaming` |

### 5. Observations & Next Steps
- QoSD personas logged end-to-end; Collector’s `/telemetry/persona` shows `work`, `latency`, `other`. `gaming`/`streaming` not triggered yet due to current heuristics.
- To classify bulk/gaming correctly, adjust `classify_persona()` (e.g., ensure port/dns signals override default `latency`, lower `bytes_total` threshold for `bulk`).
- `TODO.md` tracks upcoming tasks (filter non-LAN IPs, enhance classifier).
- Logging reference commands are in `docs/logging-cheatsheet.md`.

### 6. Outstanding TODOs
- Filter WAN/public IPs out of `qosd_live` host list (see `TODO.md`).
- Refine persona heuristics (bulk/gaming/streaming).
- Automate network setup scripts on Ubuntu (br-lan-host, taps, iptables).
