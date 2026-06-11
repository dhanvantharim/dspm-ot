# OT-DSPM — Requirements Specification

**Project:** Operational Technology Data Security Posture Management (OT-DSPM)  
**Language:** Rust  
**Status:** Draft v0.1  
**Goal:** Production-quality learning project — deployable tool, built to teach Rust

---

## 1. Problem Statement

Operational Technology (OT) environments — manufacturing, utilities, energy, water, transport — contain data assets that are almost entirely invisible to conventional IT security tooling. Engineering configurations, process setpoints, historian data, and PLC firmware are regularly transmitted in cleartext across OT networks using legacy protocols with no authentication, no encryption, and no logging.

This project builds a passive, read-only agent that discovers these data assets by observing network traffic, classifies their sensitivity, maps communication relationships between devices, and produces a machine-readable posture report — without ever injecting traffic or interacting with OT devices directly.

---

## 2. Scope

### In scope
- Passive network traffic capture and OT protocol decoding
- Asset discovery and inventory from observed traffic
- Data flow mapping between observed assets
- Data classification by type and sensitivity
- Risk posture scoring per asset and per network zone
- Structured report export (JSON, CSV, STIX 2.1)
- CLI interface for all operations
- Cross-platform deployment (Linux, Windows)
- Air-gapped, offline operation
- Container-friendly packaging (Docker / Podman)

### Out of scope (v1)
- Active scanning or device probing of any kind
- Web UI or dashboard (CLI only)
- Cloud connectivity or telemetry
- Intrusion detection or real-time alerting
- Incident response workflows
- Compliance mapping (IEC 62443, NERC CIP, NIST 800-82)
- Agent deployment on endpoint devices (network tap / span port only)

---

## 3. Functional Requirements

Requirements are tagged: **[MUST]** (v1 required), **[SHOULD]** (v1 target), **[COULD]** (v2 candidate).

### 3.1 Packet Capture

| ID | Priority | Requirement |
|----|----------|-------------|
| CAP-01 | MUST | Capture raw Ethernet frames from a specified network interface in promiscuous mode using libpcap |
| CAP-02 | MUST | Support span port and network tap deployment models |
| CAP-03 | MUST | Support offline analysis of `.pcap` and `.pcapng` capture files |
| CAP-04 | MUST | Never transmit or inject any packets — read-only operation, enforced in design |
| CAP-05 | MUST | Apply BPF filters to restrict capture to OT protocol ports, reducing load |
| CAP-06 | SHOULD | Support simultaneous capture on multiple interfaces |
| CAP-07 | COULD | Support live ring-buffer capture with configurable file rotation |

### 3.2 Protocol Parsing

| ID | Priority | Requirement |
|----|----------|-------------|
| PRO-01 | MUST | Decode Modbus/TCP (port 502): function codes, coil/register addresses, read/write payloads |
| PRO-02 | MUST | Decode EtherNet/IP / CIP (port 44818 TCP, 2222 UDP): identity objects, explicit messaging |
| PRO-03 | MUST | Decode DNP3 over TCP/UDP (port 20000): application layer function codes, data object types |
| PRO-04 | SHOULD | Decode S7comm / S7comm-plus (port 102, ISO-TSAP): read/write variable requests |
| PRO-05 | SHOULD | Decode IEC 60870-5-104 (port 2404): ASDU types, information objects |
| PRO-06 | SHOULD | Decode BACnet/IP (port 47808 UDP): object types and properties |
| PRO-07 | MUST | Gracefully handle malformed, truncated, or unknown frames — no panics |
| PRO-08 | MUST | Parsers must be zero-copy where possible; no unnecessary heap allocation on the hot path |
| PRO-09 | COULD | Plugin architecture for adding parsers without modifying core |

### 3.3 Asset Inventory

| ID | Priority | Requirement |
|----|----------|-------------|
| AST-01 | MUST | Discover and record each unique endpoint: IP address, MAC address, observed protocols |
| AST-02 | MUST | Track first-seen and last-seen timestamps per asset |
| AST-03 | MUST | Infer device role from protocol behaviour (e.g. Modbus server → likely PLC/RTU; Modbus client → likely HMI/SCADA) |
| AST-04 | MUST | Persist the asset inventory to a local SQLite database |
| AST-05 | SHOULD | Extract and record vendor/manufacturer from MAC OUI prefix |
| AST-06 | SHOULD | Record Modbus device identification responses (function code 43) to enrich device metadata |
| AST-07 | SHOULD | Track open TCP ports observed passively per asset |
| AST-08 | COULD | Support manual annotation of assets via a TOML/YAML override file (e.g. assign a friendly name or override inferred role) |

### 3.4 Data Flow Map

| ID | Priority | Requirement |
|----|----------|-------------|
| DFM-01 | MUST | Record each unique communication pair (source IP → destination IP) with observed protocol |
| DFM-02 | MUST | Count and timestamp flows — first seen, last seen, packet count, byte volume |
| DFM-03 | MUST | Persist the flow map to SQLite |
| DFM-04 | SHOULD | Identify and flag unexpected communication paths (e.g. cross-zone flows, internet-destined OT traffic) |
| DFM-05 | SHOULD | Export the flow map as a graph edge list (CSV) suitable for visualisation in Gephi or similar |
| DFM-06 | COULD | Detect and flag protocol anomalies on a flow (e.g. Modbus write function code appearing on a read-only sensor link) |

### 3.5 Data Classification

| ID | Priority | Requirement |
|----|----------|-------------|
| CLS-01 | MUST | Classify observed OT data by type: process setpoint, coil/discrete state, analogue measurement, configuration read/write, firmware transfer, historian query |
| CLS-02 | MUST | Assign a sensitivity label to each classified data type: L1 (public process state), L2 (operational data), L3 (configuration / engineering), L4 (credentials / firmware) |
| CLS-03 | MUST | Detect and flag cleartext transmission of L3/L4 data |
| CLS-04 | MUST | Detect and flag unauthenticated write commands to setpoints or coils |
| CLS-05 | MUST | Classification rules must be fully configurable in a TOML file — no hardcoded rules in logic |
| CLS-06 | SHOULD | Detect patterns indicative of configuration backup/restore operations |
| CLS-07 | SHOULD | Detect and flag Modbus/DNP3 broadcast writes (destination 0 / all-stations) |
| CLS-08 | COULD | Machine-learning assisted classification for unknown payload patterns (v2) |

### 3.6 Purdue Zone Mapping

| ID | Priority | Requirement |
|----|----------|-------------|
| ZON-01 | SHOULD | Support manual assignment of IP subnets to Purdue model levels (0–4) via TOML config |
| ZON-02 | SHOULD | Automatically infer likely Purdue level from protocol type (e.g. Modbus device → Level 1/2) |
| ZON-03 | SHOULD | Flag any observed flow that crosses Purdue zone boundaries not explicitly permitted in config |
| ZON-04 | COULD | Support ISA-95 functional hierarchy as an alternative zone model |

### 3.7 Risk Posture Scoring

| ID | Priority | Requirement |
|----|----------|-------------|
| SCR-01 | MUST | Compute a posture score (0–100) for each asset based on weighted risk factors |
| SCR-02 | MUST | Risk factors must include: unencrypted sensitive data flows, unauthenticated write commands, unexpected cross-zone communication, stale assets (no traffic in configurable window), and use of deprecated function codes |
| SCR-03 | MUST | Compute a zone-level aggregate posture score |
| SCR-04 | MUST | Scoring weights must be configurable in TOML — defaults provided |
| SCR-05 | SHOULD | Produce a ranked list of top-N highest-risk assets |
| SCR-06 | SHOULD | Produce a human-readable finding for each risk factor (e.g. "192.168.1.5: Modbus write to coil 100 transmitted in cleartext, 47 times in last 24h") |
| SCR-07 | COULD | Track posture score over time — store historical snapshots in SQLite |

### 3.8 Reporting & Export

| ID | Priority | Requirement |
|----|----------|-------------|
| RPT-01 | MUST | Export full posture report as structured JSON |
| RPT-02 | MUST | Export asset inventory as CSV |
| RPT-03 | MUST | Export data flow map as CSV edge list |
| RPT-04 | SHOULD | Export posture findings as STIX 2.1 bundles (JSON-LD) suitable for SIEM ingest |
| RPT-05 | SHOULD | All exports are deterministic and idempotent for the same input state |
| RPT-06 | MUST | All report timestamps use RFC 3339 / ISO 8601 UTC |
| RPT-07 | COULD | Markdown summary report for human review |

---

## 4. Non-Functional Requirements

### 4.1 Safety

| ID | Requirement |
|----|-------------|
| SAF-01 | **The agent MUST NEVER transmit any packet to any address under any circumstances.** This is an architectural constraint, not a configuration option. Network interfaces are opened in read-only / promiscuous mode only. |
| SAF-02 | The codebase must make it structurally impossible to call any send/write path on the capture interface — enforced at the type level in Rust, not by runtime flag. |
| SAF-03 | All error paths must fail safe — on parse failure, log and skip; never crash or disrupt the capture pipeline. |

### 4.2 Performance

| ID | Requirement |
|----|-------------|
| PER-01 | Steady-state memory usage must not exceed 150MB on a system with ≤1Gbps OT traffic |
| PER-02 | No stop-the-world pauses — no GC runtime. Rust's ownership model satisfies this by design. |
| PER-03 | Must sustain 100Mbps sustained capture throughput on a Raspberry Pi 4 (ARM64) without packet loss |
| PER-04 | Packet processing pipeline latency (capture to inventory update) must not exceed 500ms at P99 |
| PER-05 | SQLite writes must be batched — no per-packet database writes |

### 4.3 Deployment

| ID | Requirement |
|----|-------------|
| DEP-01 | Must compile and run on Linux (x86_64, ARM64) and Windows (x86_64) |
| DEP-02 | Must operate fully offline — no network calls at runtime, no cloud dependencies |
| DEP-03 | All threat rules, OUI databases, and classification configs must be bundled with the binary or loaded from a local path |
| DEP-04 | Must be distributable as a single binary (statically linked on Linux) |
| DEP-05 | Must provide an official Dockerfile for containerised deployment |
| DEP-06 | Container image must not require `--privileged`; only the `NET_RAW` and `NET_ADMIN` capabilities are required for live capture |
| DEP-07 | Must function correctly when run from a read-only filesystem (write only to a configured data directory) |

### 4.4 Configuration

| ID | Requirement |
|----|-------------|
| CFG-01 | All configuration via a single TOML file; path configurable via CLI flag or `OT_DSPM_CONFIG` environment variable |
| CFG-02 | Sensible defaults for all settings — tool must be functional with a minimal or absent config file |
| CFG-03 | Config file must be validated on startup with clear, actionable error messages |
| CFG-04 | No credentials, keys, or sensitive values in config files — document this explicitly |

### 4.5 Reliability & Observability

| ID | Requirement |
|----|-------------|
| REL-01 | Structured logging (JSON) via `tracing` crate; log level configurable at runtime |
| REL-02 | Must handle interface disconnection and reconnect gracefully without restarting the process |
| REL-03 | SQLite database must be resilient to unclean shutdown — use WAL mode |
| REL-04 | Expose runtime metrics (packets captured, packets dropped, assets seen, flows recorded) via periodic log output |

---

## 5. CLI Interface

The tool is operated entirely via CLI. Three primary subcommands:

```
ot-dspm capture   # Live capture from a network interface
ot-dspm analyze   # Offline analysis of a pcap file
ot-dspm report    # Generate reports from the local database
```

### Key flags (all subcommands)

| Flag | Description |
|------|-------------|
| `--config <path>` | Path to TOML config file |
| `--db <path>` | Path to SQLite database file |
| `--log-level <level>` | Log level: trace, debug, info, warn, error |

### Capture subcommand

| Flag | Description |
|------|-------------|
| `--interface <iface>` | Network interface to capture on |
| `--duration <secs>` | Stop after N seconds (omit for continuous) |
| `--filter <bpf>` | Additional BPF filter expression |

### Analyze subcommand

| Flag | Description |
|------|-------------|
| `--file <path>` | Path to .pcap or .pcapng file |

### Report subcommand

| Flag | Description |
|------|-------------|
| `--format <fmt>` | Output format: json, csv, stix (default: json) |
| `--output <path>` | Output file path (default: stdout) |
| `--type <type>` | Report type: posture, assets, flows, findings |
| `--top <n>` | For posture: show top N highest-risk assets |

---

## 6. Data Model (Conceptual)

### Asset
```
id            UUID (generated)
ip_address    String
mac_address   String (optional)
vendor        String (from OUI, optional)
inferred_role Enum { Plc, Rtu, Hmi, Scada, Historian, Engineering, Unknown }
protocols     Vec<Protocol>
purdue_level  Option<u8>  (0–4)
first_seen    DateTime<Utc>
last_seen     DateTime<Utc>
posture_score f32  (0.0–100.0)
```

### DataFlow
```
id            UUID
src_ip        String
dst_ip        String
protocol      Protocol
first_seen    DateTime<Utc>
last_seen     DateTime<Utc>
packet_count  u64
byte_volume   u64
findings      Vec<Finding>
```

### Finding
```
id            UUID
asset_id      UUID (optional, if asset-level)
flow_id       UUID (optional, if flow-level)
severity      Enum { Critical, High, Medium, Low, Info }
category      Enum { CleartextSensitiveData, UnauthenticatedWrite, CrossZoneFlow, ... }
description   String
evidence      String  (human-readable excerpt)
first_seen    DateTime<Utc>
count         u64
```

---

## 7. Constraints & Assumptions

- The agent is deployed on a host with access to a SPAN port or network tap — it does not need to be inline.
- The operator has sufficient network visibility to capture traffic between the assets they wish to monitor.
- Physical access to install the agent on an industrial PC or Raspberry Pi is available.
- OT device firmware, PLCs, and RTUs are never modified or interacted with.
- The tool is an observation and reporting system — it does not block, quarantine, or reconfigure anything.

---

## 8. Crate Dependencies (Planned)

| Crate | Purpose |
|-------|---------|
| `pcap` | Live packet capture via libpcap |
| `pnet` | Ethernet / IP / TCP / UDP frame parsing |
| `nom` | Binary protocol parser combinators (Modbus, DNP3, EtherNet/IP) |
| `tokio` | Async runtime for concurrent capture + processing pipeline |
| `dashmap` | Lock-free concurrent hash map for in-memory asset tracker |
| `rusqlite` | SQLite persistence |
| `serde` + `serde_json` | Serialisation / deserialisation |
| `toml` | Config file parsing |
| `clap` | CLI argument parsing |
| `tracing` + `tracing-subscriber` | Structured logging |
| `chrono` | Timestamp handling (RFC 3339) |
| `regex` | Classification rule matching |
| `aho-corasick` | Multi-pattern matching for classification engine |
| `uuid` | Asset and finding ID generation |
| `thiserror` | Structured error types |
| `anyhow` | Error propagation in application code |
| `criterion` | Benchmarking |

---

## 9. Open Questions

1. **Protocol priority order** — Modbus first (simplest), then EtherNet/IP, then DNP3. S7comm and IEC 104 deferred to v1.1. Confirm?
2. **Scoring algorithm** — Weighted sum vs. risk matrix. Needs a small design spike before implementation.
3. **STIX 2.1 mapping** — Which STIX objects best represent OT assets (Custom Object vs. `infrastructure`)? Needs research.
4. **pcap privilege model** — On Linux, `CAP_NET_RAW` is required. Document the recommended `setcap` approach vs. running as root.
5. **Test data** — Identify suitable open OT pcap datasets (4SICS, Cyber Range datasets) for unit and integration tests before Phase 1 begins.

---

## 10. Glossary

| Term | Definition |
|------|------------|
| OT | Operational Technology — hardware and software that monitors/controls physical processes |
| PLC | Programmable Logic Controller — industrial computer controlling machinery |
| RTU | Remote Terminal Unit — data acquisition device in field locations |
| HMI | Human-Machine Interface — operator workstation for process visualisation |
| SCADA | Supervisory Control and Data Acquisition — centralised OT management system |
| Historian | Time-series database for process data (e.g. OSIsoft PI) |
| Modbus | Simple serial/TCP protocol, most widely deployed OT protocol globally |
| DNP3 | Distributed Network Protocol — common in utilities and water treatment |
| EtherNet/IP | Ethernet Industrial Protocol / CIP — common in manufacturing |
| S7comm | Siemens-proprietary protocol for S7 PLC series |
| SPAN port | Switch Port ANalyzer — mirror of network traffic for passive monitoring |
| Purdue model | Reference model layering OT networks into levels 0 (field devices) through 4 (enterprise) |
| STIX 2.1 | Structured Threat Information Expression — standard format for threat intel sharing |
| DSPM | Data Security Posture Management — category of tools for discovering and classifying data assets |
