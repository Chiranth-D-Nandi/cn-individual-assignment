# cn-individual-assignment
CHIRANTH D NANDI; PES2UG24AM048

```markdown
# Multi-Switch Flow Table Analyzer (POX + Mininet + OVS)

A small SDN toolkit to **create a multi-switch Mininet topology**, run a **POX learning-switch style controller**, and **analyze Open vSwitch (OVS) flow tables across all switches** using `ovs-ofctl`.

This project helps inspect **which flow rules are active vs unused/stale**, monitor changes over time, and export reports.

---

## What’s Included

### 1) `topology.py` (Mininet topology)
Creates a network with **3 OVS switches** and **6 hosts** (two per switch) and connects to a **remote POX controller** at `127.0.0.1:6633`.

Topology (full-mesh between switches):
- `s1` ↔ `s2`, `s1` ↔ `s3`, `s2` ↔ `s3`
- Hosts:
  - `s1`: `h1 (10.0.0.1)`, `h2 (10.0.0.2)`
  - `s2`: `h3 (10.0.0.3)`, `h4 (10.0.0.4)`
  - `s3`: `h5 (10.0.0.5)`, `h6 (10.0.0.6)`

Also generates some initial ping traffic to populate flow tables.

### 2) `controller.py` (POX controller component)
A multi-switch POX controller that:
- Learns `MAC -> port` per switch (per DPID)
- Installs flows for known destinations
- Floods unknown destinations
- Installs a **table-miss** rule (priority 0) to send packets to controller
- Installs learned unicast rules (priority 1) with:
  - `idle_timeout = 30s`
  - `hard_timeout = 120s`
- Periodically requests flow stats and writes them to:
  - `/tmp/flow_stats.json`

### 3) `analyzer.py` (Flow table analyzer)
A terminal UI tool that:
- Discovers switches using `ovs-vsctl list-br`
- Dumps flow tables using `ovs-ofctl dump-flows`
- Parses entries and shows:
  - per-switch flow tables
  - detailed rule view
  - summary metrics across switches
  - active vs unused classification
- Supports:
  - **Single snapshot**
  - **Dynamic live monitoring**
  - **Raw dump**
  - **Per-switch inspection**
- Saves reports:
  - `flow_report_<timestamp>.json`
  - `flow_report_<timestamp>.txt`

> Note: `analyzer.py` reads flows **directly from OVS** (via `ovs-ofctl`). It does *not* depend on the controller stats file.

---

## Flow Classification (Analyzer)

Based on `priority`, `n_packets`, and `duration`:

- **DEFAULT**: `priority == 0` (table-miss)
- **ACTIVE / ACTIVE-HIGH**: `n_packets > 0`
- **NEW**: `n_packets == 0` and `duration < 30s`
- **UNUSED**: `n_packets == 0` and `30s <= duration < 120s`
- **STALE**: `n_packets == 0` and `duration >= 120s`

Rule efficiency shown in summary:
- `efficiency = (active_rules / total_rules) * 100`

---

## Requirements

- Linux environment with:
  - **Mininet**
  - **Open vSwitch** (`ovs-vsctl`, `ovs-ofctl`)
  - **POX controller**
- Python 3.x

---

## How to Run (Recommended: 3 Terminals)

### Terminal 1 — Start POX Controller
From your POX directory, ensure `controller.py` is available as a POX component (commonly placed under `pox/ext/`):

```bash
cd ~/pox
./pox.py log.level --INFO ext.controller
```

---

### Terminal 2 — Start Mininet Topology
From the project directory:

```bash
sudo python3 topology.py
```

This opens the Mininet CLI after setting up the topology and generating initial traffic.

---

### Terminal 3 — Run the Analyzer
From the project directory:

```bash
python3 analyzer.py
```

To avoid repeated sudo prompts (since the analyzer runs `sudo ovs-*` commands), you can run:

```bash
sudo -E python3 analyzer.py
```

---

## Analyzer Modes

From the analyzer menu:

1. **Single analysis**: snapshot of current rules (per-switch + summary + report export)
2. **Dynamic monitor**: auto-refresh terminal view every N seconds
3. **Quick dump**: raw `ovs-ofctl dump-flows` output
4. **Per-switch inspect**: choose one switch + optionally show detailed flow
5. **Check OVS status**: verify OVS, switches, and controller port

---

## Output Files

When running **Single analysis**, the analyzer writes:

- `flow_report_<YYYYMMDD_HHMMSS>.json`
- `flow_report_<YYYYMMDD_HHMMSS>.txt`

The POX controller periodically writes:
- `/tmp/flow_stats.json` (controller-side flow stats snapshot)

---

## Project Structure

```text
.
├── analyzer.py     # terminal flow analyzer (ovs-ofctl based)
├── controller.py   # POX controller component (MAC learning + flow installs)
└── topology.py     # Mininet topology (3 switches, 6 hosts, full-mesh switches)
```

---
```
