## OpenWrt Lab Network Topology

```mermaid
flowchart LR
    subgraph WindowsHost["Windows Host"]
        PS[PowerShell SSH Tunnel<br/>8080→OpenWrt:80<br/>8443→OpenWrt:443]
    end

    subgraph UbuntuVM["VirtualBox Guest: Ubuntu Server"]
        ENP0S3[enp0s3<br/>10.10.1.104/24]
        TAPWAN[tap-wan<br/>10.200.0.1/24]
        TAPLAN[tap-lan]
        TAPCLIENT[tap-client]
        VETHCLIENT[veth-client<br/>(namespace)]
        BRLAN[br-lan-host<br/>192.168.10.254/24]

        ENP0S3 <--->|NAT / Internet| ISP[(Home Router / Internet)]
        TAPWAN -. NAT via enp0s3 .- ISP
        TAPLAN --> BRLAN
        TAPCLIENT -. optional -. BRLAN
        VETHCLIENT --> BRLAN
    end

    subgraph OpenWrtVM["QEMU VM: OpenWrt"]
        WAN[eth0 (virtio)<br/>10.200.0.2/24<br/>proto static]
        LAN[br-lan (eth1)<br/>192.168.10.1/24<br/>DHCP server]
        QoSD[qosd daemon<br/>syslog → Fluent Bit]
    end

    subgraph NetNamespace["lanclient netns (Ubuntu)"]
        VETHNS[veth-ns<br/>DHCP 192.168.10.x]
        TestApps[curl / iperf / wget]
    end

    subgraph DockerStack["Ubuntu Docker Stack"]
        FluentBit[Fluent Bit]
        Collector[Collector API]
        OpenSearch[OpenSearch<br/>Dashboards]
        LogGen[Log Generator]
    end

    %% Connections
    TAPWAN <--->|virtio-net| WAN
    TAPLAN <--->|virtio-net| LAN
    BRLAN <--->|bridge| VETHCLIENT
    VETHCLIENT <---> VETHNS
    VETHNS -->|DHCP traffic| LAN

    QoSD -->|syslog / forward| FluentBit
    FluentBit -->|HTTP ingest| Collector
    FluentBit -->|OpenSearch output| OpenSearch
    Collector -->|policy polling| QoSD
    LogGen -->|Forward input| FluentBit
```

### Summary
- **Windows Host** establishes SSH tunnels (8080/8443) into the Ubuntu guest to reach LuCI.
- **Ubuntu Server** bridges `tap-lan`, `tap-client`, and `veth-client` via `br-lan-host (192.168.10.254/24)`; `tap-wan (10.200.0.1/24)` NATs to enp0s3 for internet.
- **OpenWrt QEMU VM** uses `eth0` (tap-wan) as WAN (`10.200.0.2/24`) and bridges `eth1` into LAN (`192.168.10.1/24`), running `qosd` for telemetry.
- **lanclient namespace** on Ubuntu simulates a LAN client obtaining DHCP from OpenWrt and generating test traffic.
- **Docker Compose stack** (Fluent Bit → Collector API → OpenSearch/Dashboards) receives QoSD logs and feeds persona policies back to the router.
