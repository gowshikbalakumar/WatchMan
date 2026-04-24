# Watchman (Flask + Scapy)

A beginner-friendly, modular network monitoring project inspired by Wireshark concepts and implemented in Python.

## Merged architecture plan

### 1) Control Plane (Flask)
- Serves dashboard and API.
- Starts/stops packet sniffing worker.
- Exposes query/search endpoints for packet history.

### 2) Packet Engine (Scapy)
- Live sniffing (`scapy.sniff`).
- Packet decoding into normalized records.
- Protocol mapping for TCP/UDP/DNS/HTTP heuristic.

### 3) Analysis Layer
- Wireshark-style display filter subset (`protocol==TCP and dst_port==80`).
- Basic IDS heuristics (high packet rates, risky remote ports, DNS anomalies).

### 4) Data Layer
- In-memory queue for fast UI reads.
- SQLite logging for packet history and investigation.

### 5) Frontend Dashboard
- Plain HTML/CSS/JS for live table and counters.
- Polls APIs every few seconds for simple real-time updates.

## Wireshark ideas mapped into Python

| Wireshark concept | Python implementation |
|---|---|
| Dissector pipeline | `SnifferService.decode_packet` normalizes records |
| Display filters | `PacketFilter` mini expression engine |
| Protocol tree summary | `summary` + protocol counters in `/api/stats` |
| Capture + history | Scapy capture + SQLite persistence |
| Expert info/alerts | `SuspiciousDetector` heuristics |

## Folder structure

```text
watchman/
  app/
    __init__.py
    api/routes.py
    core/config.py
    models/packet.py
    services/
      sniffer.py
      detection.py
      packet_store.py
    utils/filter_engine.py
    static/
      index.html
      css/styles.css
      js/dashboard.js
  data/
  tests/
  requirements.txt
  run.py
```

## Getting started

```bash
cd watchman
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`.

> Note: packet capture may require elevated OS permissions depending on interface/OS.
