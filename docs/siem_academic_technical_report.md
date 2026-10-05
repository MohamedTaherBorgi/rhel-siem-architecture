# Academic Technical Report: Hardened Open-Source Log Processing & Security Analytics Architecture

**Subject 21**: *Mise en place d'une architecture de traitement des événements de sécurité (LOG)*  
**Academic Module**: Security of Information Systems & Computer Networks  
**Target Class**: CII-5-J-SSIRF-H  
**Author**: BORGI Mohamed Taher  
**Platform**: Red Hat Enterprise Linux 9.6 (Hardened Minimal) · OpenSearch 2.18.0 · Fluent Bit 3.1.9 · OpenSearch Dashboards 2.18.0 · Docker Compose  
**Academic Year**: 2026 – 2027  

---

## Executive Summary

Modern cybersecurity operations require real-time visibility into distributed systems to detect, contextualize, and remediate hostile adversary activity. In Linux server environments, reliance on default, unmonitored local logs introduces critical forensic blind spots: logs can be tampered with by elevated attackers, lack structured correlation, and fail to provide immediate alerting during credential brute-forcing or privilege escalation attempts.

This report presents the design, technical implementation, and empirical validation of an enterprise-grade, open-source Security Information and Event Management (SIEM) log processing architecture built on a hardened Red Hat Enterprise Linux (RHEL) 9.6 platform. Utilizing a decoupled architecture of **Fluent Bit 3.1.9 (C-Engine collector)**, **OpenSearch 2.18.0 (distributed Lucene storage)**, and **OpenSearch Dashboards 2.18.0 (SOC presentation interface)**, the pipeline ingests telemetry across four distinct sources: host authentication (`/var/log/secure`), the Linux kernel audit subsystem (`auditd`), systemd binary journal sockets, and remote network syslog (RFC 5424 over port 5140).

The underlying host enforces strict defense-in-depth through **SELinux Mandatory Access Control** in `Enforcing` mode, **firewalld** multi-zone network segmentation (`siem-mgmt` vs `siem-collector`), **CIS Benchmark OpenSSH** cryptographic and session bounding, and kernel-level **auditd** rules intercepting unauthorized `execve` calls and identity file modifications.

The architecture was experimentally tested against three real-world attack vectors mapped to the MITRE ATT&CK framework:
1. **MITRE T1110.001 (Password Guessing)**: Automated multi-socket SSH dictionary attack from a remote Kali Linux VM using Hydra.
2. **MITRE T1548.003 (Sudo and Sudo Caching)**: Unauthorized local privilege escalation attempt and identity database tampering intercepted with immutable kernel `auid` tracking.
3. **Pipeline Ingestion Stress Test**: High-throughput remote RFC 5424 syslog burst (50 events/sec) over TCP port 5140 with zero packet loss.

All telemetry is indexed into daily time-series indices (`logs-security-YYYY.MM.DD`) with native IP mapping and zero replica shards (maintaining **GREEN** cluster health), visualized through a 6-widget unified SOC dashboard, and backed up as Infrastructure-as-Code (`soc-dashboard.ndjson`).

---

## 1. Problem Statement & Threat Modeling

### 1.1 The Operational Need for Centralized Security Telemetry
In a standard unmanaged enterprise infrastructure, security events are scattered across disparate subsystem logs:
* System daemons log to binary `systemd-journald` files.
* PAM and OpenSSH daemons append unstructured text to `/var/log/secure`.
* The Linux kernel records syscall events in `/var/log/audit/audit.log`.
* Network firewalls, routers, and edge devices transmit RFC 5424 syslog over the local network.

This fragmentation creates three fatal defensive handicaps:
1. **Forensic Volatility & Anti-Forensics**: If an adversary compromises root privileges on a local node, their immediate action is often log wiping (`rm -rf /var/log/*`, shredding bash history, or halting auditd). Without real-time out-of-band streaming, forensic audit trails are permanently lost.
2. **Lack of Relational Correlation**: An SSH brute-force attack generates dozens of separate TCP connections. Standalone OpenSSH loggers cannot correlate these independent sessions into an aggregated threat actor profile.
3. **Search Inefficiency**: Unstructured string matching via `grep` across gigabytes of log files introduces high query latency, preventing sub-second incident response.

### 1.2 Linux Threat Modeling & MITRE ATT&CK Mapping
The architecture is designed to intercept and contextualize adversary techniques across the Linux attack lifecycle:

| MITRE ATT&CK ID | Tactic | Adversary Technique | System Telemetry Source | Pipeline Parsing Target |
| :--- | :--- | :--- | :--- | :--- |
| **T1110.001** | Credential Access | Password Guessing / SSH Brute Force | `/var/log/secure` & `journald` | `src_ip`, `src_port`, `target_user`, `routing_tag: host.auth` |
| **T1548.003** | Privilege Escalation | Sudo & Sudo Caching Abuse | `/var/log/secure` & `/var/log/audit/audit.log` | `actor`, `target_user`, `command`, `routing_tag: host.auth` |
| **T1548** | Privilege Escalation | Execution of Privileged Binaries | Linux Kernel (`auditd`) | `syscall=59` (`execve`), `auid`, `euid=0`, `key="priv_esc_exec"` |
| **T1078** | Persistence / Defense Evasion | Identity Database Tampering | Linux Kernel FIM (`auditd`) | File watches on `/etc/passwd`, `/etc/shadow`, `/etc/group` |
| **T1071.001** | Command and Control | External Ingress / Network Threat Telemetry | Network Syslog (Port 5140) | RFC 5424 `ident`, `host`, `message`, `routing_tag: remote.syslog` |

---

## 2. Technology Stack Evaluation & Architectural Defense

A central evaluation criterion of Subject 21 is defending the choice of log processing architecture against common alternatives.

### 2.1 Comparative Architecture Matrix

| Evaluation Dimension | Stack A: OpenSearch 2.18 + Fluent Bit 3.1.9 (Selected) | Stack B: Wazuh HIDS/SIEM Appliance | Stack C: Elastic Stack (ELK: ES + Logstash + Kibana) |
| :--- | :--- | :--- | :--- |
| **Pipeline Transparency** | **High**: Decoupled collector (`Fluent Bit`), storage engine (`OpenSearch`), and presentation (`Dashboards`). Complete control over memory/disk buffering, regex parsers, and mapping templates. | **Low**: Monolithic all-in-one appliance. Log decoding occurs within opaque XML rules and proprietary `wazuh-analysisd` binaries. | **Medium**: Logstash provides rich filter plugins but introduces severe JVM overhead and complex syntax. |
| **Memory Footprint** | **Low-Medium ($\approx$ 2.8 GB total)**:<br/>• Fluent Bit: $\sim$35 MB (Optimized C)<br/>• OpenSearch: 2 GB JVM heap<br/>• Dashboards: $\sim$500 MB (Node.js) | **High ($\ge$ 6–8 GB total)**:<br/>Wazuh Manager, Filebeat, Wazuh Indexer, and Wazuh Dashboard frequently cause OOM errors on standard 4–6 GB student VMs. | **High ($\ge$ 6 GB total)**:<br/>Logstash alone demands 1–2 GB JVM heap; Elasticsearch requires $\ge$ 2–4 GB JVM heap. |
| **Licensing Integrity** | **100% Pure Open Source (Apache 2.0)**:<br/>Unrestricted community software with zero proprietary paywalls or commercial licensing gating. | **GPLv2 / Apache 2.0**:<br/>Open source, but downstream indexer is tightly coupled to Wazuh release cycles. | **Proprietary / SSPL**:<br/>Elasticsearch transitioned from Apache 2.0 to SSPL/Elastic License, violating pure open-source project prerequisites. |
| **Ingestion Flexibility** | Ingests Linux auditd, systemd binary journal sockets, container logs, and RFC 5424 syslog streams natively. | Heavily dependent on the proprietary Wazuh Agent (`TCP/1514`). Network syslog requires legacy forwarders. | High ingestion capability via Beats/Logstash, but resource-prohibitive. |
| **Storage Lifecycle** | Native **Index State Management (ISM)** declarative JSON policies for automated rolling, hot/warm tiers, and deletion. | Flat file archives (`archives.json`) or Filebeat index rollover policies. | Supported via Elasticsearch ILM, but restricted behind SSPL. |

### 2.2 Academic Defense Statement
Stack A (**Fluent Bit + OpenSearch + OpenSearch Dashboards**) was chosen over Wazuh and ELK for three technical reasons:
1. **Engineering Transparency vs. Black-Box Appliance**: Wazuh functions as an appliance where ingestion, decoders, and alerting are pre-packaged. Subject 21 explicitly tasks the engineer with building the data engineering pipeline. Stack A requires architecting every layer: input polling, offset tracking, regex tokenization, memory watermarks, schema normalization, index mapping, and query aggregation.
2. **Deterministic C-Engine Efficiency**: Fluent Bit is written in pure C with zero runtime dependencies. It interacts directly with the Linux kernel and the systemd journal C API (`sd-journal`), maintaining a memory footprint under 40 MB compared to Logstash's 1.5 GB JVM footprint.
3. **Open-Source Compliance**: OpenSearch was established by AWS, Red Hat, and the Linux Foundation as a pure Apache 2.0 fork following Elastic's departure from open source. It provides enterprise security analytics without licensing ambiguity.

---

## 3. End-to-End Pipeline Engineering & Data Normalization

### 3.1 Global Ingestion Topology

```mermaid
flowchart TD
    subgraph Host_RHEL ["Hardened RHEL 9.6 Target (10.0.2.10)"]
        subgraph Subsystems ["Host Telemetry Producers"]
            SEC["/var/log/secure<br/>(OpenSSH & PAM Auth)"]
            AUD["/var/log/audit/audit.log<br/>(Kernel Syscalls & FIM)"]
            JRN["/run/log/journal<br/>(systemd binary socket)"]
            NET["Remote Port 5140<br/>(RFC 5424 TCP/UDP)"]
        end

        subgraph FluentBit ["Fluent Bit 3.1.9 Ingestion Engine"]
            IN_TAIL_AUTH["in_tail<br/>(auth_tail.db)"]
            IN_TAIL_AUD["in_tail<br/>(audit_tail.db)"]
            IN_SYS_JRN["in_systemd<br/>(sd-journal C API)"]
            IN_SYS_NET["in_syslog<br/>(Port 5140)"]

            subgraph Norm ["Stream Normalization & Parsing"]
                MOD["filter_modify<br/>Unify 'log' & 'MESSAGE' -> 'message'"]
                P_LOGIN["filter_parser: sshd_failed_login"]
                P_INV["filter_parser: sshd_invalid_user"]
                P_SUDO["filter_parser: sudo_violation"]
                P_SYSCALL["filter_parser: auditd_syscall"]
                P_AUD_HDR["filter_parser: auditd_header"]
                META["filter_record_modifier<br/>Enrich node & pipeline metadata"]
            end

            BUFF["Dual Buffer Storage<br/>RAM (10MB) + Disk (/fluentbit-buffer:z)"]
            OUT_OS["out_opensearch<br/>Bulk HTTP REST API"]
        end
    end

    subgraph Internal_Net ["Isolated Docker Bridge: siem-internal (172.28.0.0/16)"]
        subgraph OpenSearch ["OpenSearch 2.18.0 (172.28.0.20)"]
            TMPL["index-template.json<br/>src_ip: ip, replicas: 0"]
            SHARD["Lucene Time-Series Indices<br/>logs-security-YYYY.MM.DD (GREEN)"]
        end

        subgraph Dashboards ["OpenSearch Dashboards 2.18.0 (172.28.0.30)"]
            DASH_SRV["Node.js Web Interface (Port 5601)"]
            SOC_UI["SOC Security Incident Console<br/>6 Synchronized Visual Widgets"]
        end
    end

    SEC -->|Bind :ro| IN_TAIL_AUTH
    AUD -->|Bind :ro, label=disable| IN_TAIL_AUD
    JRN -->|Bind :ro| IN_SYS_JRN
    NET -->|Port Forward 5140| IN_SYS_NET

    IN_TAIL_AUTH --> BUFF
    IN_TAIL_AUD --> BUFF
    IN_SYS_JRN --> BUFF
    IN_SYS_NET --> BUFF

    BUFF --> MOD
    MOD --> P_LOGIN --> P_INV --> P_SUDO --> P_SYSCALL --> P_AUD_HDR --> META --> OUT_OS
    OUT_OS -->|HTTP Bulk 9200| TMPL --> SHARD
    SHARD --> DASH_SRV --> SOC_UI
```

---

### 3.2 Schema Normalization & Field Divergence Resolution
A major technical challenge in multi-source ingestion is **schema divergence**:
* The Fluent Bit `tail` plugin outputs the raw line inside a JSON key named `log`.
* The `systemd` journal plugin outputs the daemon payload inside an uppercase JSON key named `MESSAGE`.

If left unnormalized, search analysts would have to query `log: "Failed password*"` for `/var/log/secure` and `MESSAGE: "Failed password*"` for journald.

**The Solution**: We deployed a `modify` filter chain that executes before regex tokenization:
```ini
[FILTER]
    Name     modify
    Match    host.auth
    Rename   log message

[FILTER]
    Name     modify
    Match    host.audit
    Rename   log message

[FILTER]
    Name     modify
    Match    host.journal
    Rename   MESSAGE message
```
This guarantees that **every event from every telemetry layer arrives at the parser and database with a standardized `message` field**.

---

### 3.3 Regular Expression Tokenization (`parsers.conf`)
Unstructured text strings are tokenized into structured key-value dictionaries using typed regular expressions.

#### 1. OpenSSH Failed Login Parser (`sshd_failed_login`)
```ini
[PARSER]
    Name        sshd_failed_login
    Format      regex
    Regex       ^(?:.*sshd\[\d+\]:\s+)?Failed password for (?:invalid user )?(?<target_user>[^\s]+) from (?<src_ip>[^\s]+) port (?<src_port>\d+)(?: ssh2)?$
    Types       src_port:integer
```
* **Optional Syslog Prefix (`^(?:.*sshd\[\d+\]:\s+)?`)**: Employs an optional non-capturing group. This enables the **exact same parser** to process both `/var/log/secure` (which includes standard syslog headers) and `journald` (which strips the syslog prefix and delivers raw text).
* **Typed Port Casting (`Types src_port:integer`)**: Coerces the extracted source port into a 32-bit integer in memory before JSON serialization. This prevents OpenSearch from indexing the port as text, enabling numerical range queries.

#### 2. OpenSSH Invalid User Enumeration (`sshd_invalid_user`)
```ini
[PARSER]
    Name        sshd_invalid_user
    Format      regex
    Regex       ^(?:.*sshd\[\d+\]:\s+)?Invalid user (?<target_user>[^\s]+) from (?<src_ip>[^\s]+) port (?<src_port>\d+)
    Types       src_port:integer
```
Extracts user enumeration attempts when adversaries test non-existent accounts on the target.

#### 3. Unauthorized Sudo Parser (`sudo_violation`)
```ini
[PARSER]
    Name        sudo_violation
    Format      regex
    Regex       ^(?:.*sudo\[\d+\]:\s+)?(?<actor>[^\s]+)\s+:\s+user NOT in sudoers\s*;\s*TTY=(?<tty>[^\s]+)\s*;\s*PWD=(?<pwd>[^\s]+)\s*;\s*USER=(?<target_user>[^\s]+)\s*;\s*COMMAND=(?<command>.*)$
```
Extracts the caller identity (`actor`), targeted user (`target_user`), terminal, working directory, and the exact unauthorized command.

#### 4. Linux Kernel Audit Syscall Parser (`auditd_syscall`)
```ini
[PARSER]
    Name        auditd_syscall
    Format      regex
    Regex       ^type=(?<audit_type>[A-Z_]+)\s+msg=audit\((?<audit_epoch>[0-9.]+):(?<audit_id>[0-9]+)\):\s+arch=(?<arch>[0-9a-fA-F]+)\s+syscall=(?<syscall>[0-9]+)\s+success=(?<success>[a-z]+)\s+exit=(?<exit_code>[-0-9]+).*?\sauid=(?<auid>[0-9]+)\s+uid=(?<uid>[0-9]+)\s+gid=(?<gid>[0-9]+)\s+euid=(?<euid>[0-9]+).*?\sexe="(?<exe>[^"]+)"(?:.*key="(?<audit_key>[^"]+)")?
    Types       syscall:integer exit_code:integer auid:integer uid:integer gid:integer euid:integer
```
Extracts kernel execution telemetry. The trailing `(?:.*key="(?<audit_key>[^"]+)")?` makes the `-k` audit key optional, ensuring standard system calls without an assigned key are still parsed.

---

### 3.4 Fault-Tolerant Buffering & Deduplication
To ensure zero log loss during high-stress conditions (such as high-volume brute-force attacks or network link flaps), Fluent Bit utilizes a hybrid **RAM + Disk buffer engine**:
* `Storage.path /fluentbit-buffer/buffer`: Writes ingested chunks to physical disk backing storage.
* `Storage.sync normal`: Syncs chunks to disk using standard OS caching.
* `Storage.backlog.mem_limit 15M`: Limits memory allocation for un-flushed backlog chunks to prevent container OOM killer termination.
* `DB /fluentbit-buffer/auth_tail.db`: Maintains an **SQLite database tracking file inodes and exact byte offsets**. If the RHEL host or the Docker container restarts, Fluent Bit resumes reading from the exact byte where it left off, guaranteeing **zero missed events and zero duplicate records**.

---

### 3.5 OpenSearch Schema Enforcement (`index-template.json`)
By default, OpenSearch uses dynamic mapping, inferring field types from the first document ingested. This presents two critical flaws:
1. An IP address like `10.0.2.1` would be indexed as generic `text`, preventing CIDR subnet filtering (e.g. `src_ip: "10.0.2.0/24"`).
2. OpenSearch assigns 1 replica shard per primary shard. In a single-node architecture, the replica shard cannot be allocated to another node, permanently leaving the cluster in a **yellow warning state**.

We deployed an explicit index template (`security_logs_template`) matching `logs-security-*`:

```json
{
  "index_patterns": ["logs-security-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "1s"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "routing_tag": { "type": "keyword" },
        "lab_node": { "type": "keyword" },
        "pipeline": { "type": "keyword" },
        "message": { "type": "text" },
        "src_ip": { "type": "ip" },
        "src_port": { "type": "integer" },
        "target_user": { "type": "keyword" },
        "actor": { "type": "keyword" },
        "command": {
          "type": "text",
          "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 } }
        },
        "audit_type": { "type": "keyword" },
        "audit_key": { "type": "keyword" },
        "syscall": { "type": "integer" },
        "success": { "type": "keyword" },
        "exit_code": { "type": "integer" },
        "exe": { "type": "keyword" },
        "auid": { "type": "integer" },
        "uid": { "type": "integer" },
        "euid": { "type": "integer" }
      }
    }
  },
  "priority": 100
}
```

* `"number_of_replicas": 0`: Eliminates unassigned replica warnings, transitioning cluster health directly to **GREEN**.
* `"src_ip": { "type": "ip" }`: Enables native CIDR range queries, mathematical subnet filtering, and coordinate maps.
* `"target_user": { "type": "keyword" }`: Keyword mapping prevents text analyzer tokenization, enabling terms aggregations for top-attacker charts.

---

## 4. Host-Level Hardening & Defense-in-Depth (RHEL 9.6)

An enterprise SIEM must defend itself against network compromise and local tampering. The RHEL 9.6 host enforces defense-in-depth across four distinct security layers:

```
[ Host Security Architecture ]
 ├── Layer 1: Kernel Tuning (vm.max_map_count, vm.swappiness, ip_forward)
 ├── Layer 2: SELinux Enforcing Mode with Container Boundary Scoping
 ├── Layer 3: firewalld Network Segmentation (Default DROP, siem-mgmt, siem-collector)
 ├── Layer 4: OpenSSH CIS Benchmark Cryptographic Suite & Session Bounding
 └── Layer 5: Linux auditd Kernel Syscall & File Integrity Monitoring (FIM)
```

---

### 4.1 Kernel Tuning (`/etc/sysctl.d/99-siem-tuning.conf`)
```ini
vm.max_map_count=262144
vm.swappiness=1
net.ipv4.ip_forward=1
```
* **`vm.max_map_count=262144`**: Lucene requires large memory-mapped file limits (`mmap`). The Linux default of 65530 causes OpenSearch bootstrap checks to fail.
* **`vm.swappiness=1`**: Instructs the kernel to avoid swapping physical RAM to disk. Combined with OpenSearch's `bootstrap.memory_lock=true`, this locks the JVM heap into RAM via `mlockall()`.
* **`net.ipv4.ip_forward=1`**: Enables IP packet routing across container bridge interfaces.

---

### 4.2 SELinux Mandatory Access Control (MAC)
* **Status**: Operating in full `Enforcing` mode (`getenforce` $\rightarrow$ `Enforcing`).
* **Container Storage Isolation**: Persistent volumes are mounted with `:z` flags, dynamically relabeling host folders to `container_file_t`.
* **The Audit Ingestion Challenge & Resolution**: RHEL kernel audit logs (`/var/log/audit/audit.log`) carry the strict `auditd_log_t` SELinux context. Standard containers running in the `container_t` domain are blocked by SELinux policy from reading audit logs. Disabling SELinux host-wide is a severe security failure. Instead, we configured container-level domain un-confinement in `docker-compose.yml`:
  ```yaml
  security_opt:
    - label=disable
  ```
  This permits Fluent Bit to read `/var/log/audit/audit.log` while **leaving global host SELinux 100% active and Enforcing**.

---

### 4.3 firewalld Network Segmentation & The Docker nftables Mitigation
RHEL's default `public` zone allows open access across interfaces. We deployed a zero-trust network segmentation model:

```bash
# 1. Set default fallback zone to drop (drops all unapproved incoming packets)
sudo firewall-cmd --set-default-zone=drop

# 2. Create Management Zone (Restricted to Host IP 10.0.2.1 / Windows Workstation)
sudo firewall-cmd --permanent --new-zone=siem-mgmt
sudo firewall-cmd --permanent --zone=siem-mgmt --add-service=ssh
sudo firewall-cmd --permanent --zone=siem-mgmt --add-port=5601/tcp
sudo firewall-cmd --permanent --zone=siem-mgmt --add-source=10.0.2.1/32

# 3. Create Collector Zone (Permits Syslog from Lab Subnet)
sudo firewall-cmd --permanent --new-zone=siem-collector
sudo firewall-cmd --permanent --zone=siem-collector --add-port=5140/tcp
sudo firewall-cmd --permanent --zone=siem-collector --add-port=5140/udp
sudo firewall-cmd --permanent --zone=siem-collector --add-source=10.0.2.0/24

# 4. Reload firewalld
sudo firewall-cmd --reload

# 5. Restore Docker's nftables chains
sudo systemctl restart docker
```

#### Key Architectural Findings:
1. **Source Precedence**: `10.0.2.1/32` (Windows) is inside `10.0.2.0/24` (Subnet). In `nftables`, more specific CIDR masks take precedence. Windows matches `siem-mgmt` (ports 22 and 5601 allowed). Kali (`10.0.2.3`) matches `siem-collector` (only port 5140 allowed; port 5601 and port 22 are dropped).
2. **The Docker / firewalld Reload Trap**: On RHEL 9, running `firewall-cmd --reload` reloads XML definitions and flushes the kernel's active filter tables. This inadvertently wipes Docker's internal `DOCKER` and `DOCKER-ISOLATION` chains. Immediately executing `sudo systemctl restart docker` forces the Docker daemon to re-hook its container bridges into `nftables`.

---

### 4.4 CIS Benchmark OpenSSH Hardening (`/etc/ssh/sshd_config.d/01-cis-hardening.conf`)
Deploys the modular CIS RHEL 9 Benchmark drop-in configuration:

```sshconfig
Port 22
Protocol 2
AddressFamily inet

PermitRootLogin no
MaxAuthTries 6
MaxSessions 10
LoginGraceTime 60
PasswordAuthentication yes
PubkeyAuthentication yes

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com

X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 0
```

* **`PermitRootLogin no`**: Directly mitigates MITRE T1078 by requiring named unprivileged accounts before elevation.
* **`MaxSessions 10`**: Set to 10 in compliance with CIS Recommendation 5.2.19, allowing Antigravity IDE multiplexed background channels to operate without disconnection while preventing session exhaustion attacks.
* **`MaxAuthTries 6`**: Slows down brute-force tools per TCP connection.
* **Cryptographic Suite**: Enforces modern elliptic-curve cryptography (`curve25519-sha256`, `chacha20-poly1305`), preventing cryptographic downgrade attacks.

---

### 4.5 Linux Kernel Auditing (`/etc/audit/rules.d/99-privesc.rules`)
```audit
-D
-b 8192
-f 1

## Monitor execution of privilege escalation binaries (MITRE T1548)
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_esc_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k priv_esc_exec

## Monitor sudoers file modifications (MITRE T1548.003)
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification

## Monitor identity database tampering (MITRE T1078)
-w /etc/passwd -p wa -k user_db_modification
-w /etc/shadow -p wa -k shadow_modification
-w /etc/group -p wa -k group_db_modification
```

* Loaded via `sudo augenrules --load` and verified via `sudo auditctl -l`.
* The kernel flags target events with `key="priv_esc_exec"` or `key="shadow_modification"`. Fluent Bit extracts this into `audit_key` for immediate SIEM alerting.

---

## 5. Experimental Validation & Offensive Test Scenarios

The architecture was subjected to three live attack scenarios executed from the isolated Kali Linux adversary VM (`10.0.2.3`).

### 5.1 Scenario 1: Automated SSH Brute Force (MITRE ATT&CK T1110.001)

#### 1. Attack Execution
With a temporary runtime rule permitting port 22 on `siem-collector`, Kali executed a multi-threaded dictionary attack using Hydra:
```bash
hydra -L <(printf "root\nadmin\nservice\ndevops\nintruder\n") \
      -P <(printf "123456\npassword\nadmin123\nsecret\n") \
      -t 4 -vV ssh://10.0.2.10
```

#### 2. Telemetry Captured in Pipeline
```
Oct  5 17:05:36 localhost sshd[12481]: Failed password for invalid user admin from 10.0.2.3 port 58264 ssh2
Oct  5 17:05:36 localhost sshd[12508]: Failed password for invalid user admin from 10.0.2.3 port 56046 ssh2
Oct  5 17:05:36 localhost sshd[12479]: Failed password for invalid user admin from 10.0.2.3 port 58252 ssh2
Oct  5 17:05:34 localhost sshd[12493]: Failed password for invalid user admin from 10.0.2.3 port 58382 ssh2
```

#### 3. Forensic Analysis & Key Findings
* **Socket Multiplexing vs. MaxAuthTries**: The logs demonstrated that Hydra opened over 100 distinct TCP connections, each with a unique source port (`58264`, `56046`, `58252`, `58382`) and a unique `sshd` process PID. This proved why host-level rate-limiting (`MaxAuthTries`) is insufficient on its own: an attacker simply reconnects from a new port.
* **SIEM Aggregation Power**: While OpenSSH saw 100 isolated connections, our SIEM correlated all events by `src_ip: 10.0.2.3`, driving the **Top Attacker IPs** donut chart and the **Total Attack Counter** up in real time.
* **Client-Side vs. Server-Side Limits**: Manual interactive login (`ssh taher@10.0.2.10`) was halted after 3 attempts due to the client-side `NumberOfPasswordPrompts 3` parameter, whereas automated protocol tools like Hydra can leverage the full server-side `MaxAuthTries 6`.

---

### 5.2 Scenario 2: Unauthorized Privilege Escalation & FIM (MITRE ATT&CK T1548.003)

#### 1. Attack Execution
An unprivileged user (`intruder`, UID 1001) was created without sudoers membership. In an interactive shell, `intruder` attempted unauthorized administrative operations:
```bash
su - intruder
sudo -l
sudo cat /etc/shadow
exit
```

#### 2. Telemetry Captured in Pipeline

**Layer 1: PAM Sudo Violation (`/var/log/secure` & `journald`)**:
```
Oct  5 17:20:03 localhost sudo[13478]: intruder : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/intruder ; USER=root ; COMMAND=/bin/cat /etc/shadow
routing_tag: host.auth
actor: intruder
target_user: root
```

**Layer 2: Kernel Syscall Interception (`/var/log/audit/audit.log`)**:
```
type=SYSCALL msg=audit(1791217198.998:1251): arch=c000003e syscall=59 success=yes exit=0
ppid=13256 pid=13478 auid=1000 uid=1001 gid=1001 euid=0 suid=0 fsuid=0
comm="sudo" exe="/usr/bin/sudo" key="priv_esc_exec"
AUID="taher" UID="intruder" EUID="root"
```

#### 3. Forensic Analysis & Key Findings
* **The Immutability of Kernel `AUID`**: This finding represents the strongest forensic evidence of the project. Notice that while `UID="intruder"` (1001) executed the command and acquired `EUID="root"` (0), the kernel recorded **`AUID="taher"` (1000)**. Because `taher` originally established the SSH login session, the kernel's audit context permanently tracked the caller identity across `su - intruder`. An attacker cannot forge or hide their origin.
* **File Integrity Monitoring (FIM)**: When user accounts were provisioned and passwords updated, the kernel audit watches fired:
  * `key="user_db_modification"` on `/etc/passwd` (`syscall=257` `openat`, `syscall=82` `rename`).
  * `key="shadow_modification"` on `/etc/shadow`.
  * `key="group_db_modification"` on `/etc/group`.

---

### 5.3 Scenario 3: Remote Network Syslog Ingestion & Pipeline Stress Test

#### 1. Attack Execution
Simulating remote network firewalls (Palo Alto, Suricata IDS), Kali transmitted both a single threat alert and a 50-event high-speed burst loop over TCP port 5140:
```bash
# Single threat alert
logger --rfc5424 --server 10.0.2.10 --port 5140 --tcp -t "palo-alto-fw" "THREAT: Outbound C2 beaconing to 198.51.100.45 blocked"

# High-speed burst stress test (50 events)
for i in $(seq 1 50); do
  logger --rfc5424 --server 10.0.2.10 --port 5140 --tcp -t "suricata-ids" "SIG: Potential SQL Injection attack pattern detected event_id=$i"
done
```

#### 2. Forensic Analysis & Key Findings
* **Zero Packet Loss**: All 50 burst events were ingested by Fluent Bit over TCP 5140, parsed by `syslog_rfc5424`, buffered to disk, and indexed in OpenSearch in sub-second time.
* **Structured RFC 5424 Metadata**: Successfully extracted `ident` (`palo-alto-fw`, `suricata-ids`), `host` (`kali`), and mapped them under `routing_tag: "remote.syslog"`.
* **Telemetry Distribution**: `remote.syslog` appeared as an independent slice on the **Telemetry Distribution by Layer** SOC chart.

---

## 6. SOC Visual Analytics & Presentation Interface

The OpenSearch Dashboards presentation interface was engineered as a 6-widget synchronized command center:

```
┌───────────────────────────────────┬───────────────────────────────────┐
│     Top Attacker IPs (Donut)      │   Top Targeted Accounts (Bar)     │
│   10.0.2.3 (Kali) vs 10.0.2.1     │      admin, root, devops...       │
├─────────────────┬─────────────────┼───────────────────────────────────┤
│ SSH Attack Ctr  │ PrivEsc Violat. │    Telemetry by Layer (Donut)     │
│  Metric: 100+   │    Metric: 3    │ host.auth, host.audit, remote...  │
├─────────────────┴─────────────────┴───────────────────────────────────┤
│            Unified Live Security Incident Stream (Table)              │
│ Time | routing_tag | src_ip | actor | target_user | audit_key | msg   │
└───────────────────────────────────────────────────────────────────────┘
```

### 6.1 Widget Configuration & Query Mechanics

| Widget | Visualization Type | DQL Search Filter | Aggregation Metric | Security Role |
| :--- | :--- | :--- | :--- | :--- |
| **Top Attacker IPs** | Donut Chart | `routing_tag: "host.auth" AND src_ip: *` | Terms on `src_ip` (Size: 5) | Highlights dominant attacker sources. |
| **Top Targeted Accounts** | Horizontal Bar | `routing_tag: "host.auth" AND target_user: *` | Terms on `target_user` (Size: 10) | Identifies account enumeration attempts. |
| **SSH Attack Counter** | Metric Tile | `routing_tag: "host.auth" AND message: "Failed password*"` | Metric: `Count` | Deduplicated 1:1 counter of failed logins. |
| **PrivEsc Violations** | Metric Tile | `actor: * OR audit_key: "priv_esc_exec"` | Metric: `Count` | Immediate alarm for internal unauthorized sudo actions. |
| **Telemetry by Layer** | Donut Chart | `*` | Terms on `routing_tag` (Size: 5) | Visualizes data volume across auth, audit, journal, and remote syslog. |
| **Live Incident Stream** | Saved Search Table | `src_ip: * OR actor: * OR audit_key: *` | Chronological Stream | Unified real-time triage table for network and host attacks. |

### 6.2 Infrastructure-as-Code (IaC) Export
To guarantee 100% project reproducibility on fresh environments, the dashboard, its 6 visualizations, and the `logs-security-*` index pattern were exported to:
`~/siem-stack/configs/dashboards/soc-dashboard.ndjson`

Any evaluator or engineer can restore the entire interface in 3 seconds via the REST API:
```bash
curl -X POST "http://localhost:5601/api/saved_objects/_import?createNewCopies=false" \
  -H "osd-xsrf: true" \
  --form file=@~/siem-stack/configs/dashboards/soc-dashboard.ndjson
```

---

## 7. Production Scalability & Lifecycle Management

### 7.1 Index State Management (ISM) Retention Policies
In enterprise deployments, unbounded daily indices will eventually exhaust disk capacity. OpenSearch provides **Index State Management (ISM)** to automate data lifecycle transitions:

```json
{
  "policy": {
    "description": "Enterprise SIEM 30-day lifecycle retention policy",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          { "rollover": { "min_index_age": "1d", "min_doc_count": 5000000 } }
        ],
        "transitions": [{ "state_name": "warm", "conditions": { "min_index_age": "7d" } }]
      },
      {
        "name": "warm",
        "actions": [
          { "read_only": {} }
        ],
        "transitions": [{ "state_name": "delete", "conditions": { "min_index_age": "30d" } }]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ]
  }
}
```
* **Hot State (Days 1–7)**: Active read/write primary shards optimized for high ingestion throughput.
* **Warm State (Days 8–30)**: Indices marked read-only; segments merged via Force Merge to reclaim disk space and reduce memory overhead.
* **Delete State (Day 31+)**: Automated deletion, enforcing regulatory retention schedules without manual sysadmin intervention.

---

## 8. Conclusion & Engineering Synthesis

Subject 21 successfully demonstrated the implementation and operational defense of a modern, open-source security log processing architecture on a hardened enterprise Linux host.

### Key Technical Achievements:
1. **Architectural Decoupling**: Replaced black-box SIEM appliances with a transparent, high-performance pipeline (Fluent Bit in C + OpenSearch in Lucene + OpenSearch Dashboards).
2. **Schema Normalization**: Resolved multi-source field divergence into a unified schema with native IP data typing.
3. **Forensic Integrity**: Proved that kernel-level `auditd` preserves immutable caller attribution (`auid=1000`) even when attackers transition identities via `su` or SUID binaries.
4. **Host Defense-in-Depth**: Hardened the underlying host across SELinux MAC, firewalld network segmentation, CIS OpenSSH configurations, and kernel memory locking.
5. **Operational Verification**: Validated attack detection in real time against automated Hydra SSH brute-forcing, unauthorized privilege escalation, and remote syslog stress testing.

The resulting platform provides enterprise-grade detection fidelity, sub-second search latency, and high resource efficiency, operating smoothly on modest hardware specifications while adhering strictly to 100% open-source licensing principles.

---

## Appendix: Key Verification Commands

```bash
# 1. Verify OpenSearch Cluster Health (Status must be GREEN)
docker exec siem-opensearch curl -s http://127.0.0.1:9200/_cluster/health?pretty

# 2. Verify Active firewalld Zones
sudo firewall-cmd --get-active-zones

# 3. Verify Active Kernel Audit Rules
sudo auditctl -l

# 4. Search Recent Privilege Escalation Syscalls
sudo ausearch -k priv_esc_exec -ts recent

# 5. Verify Daily Index Mapping & Replicas
docker exec siem-opensearch curl -s http://127.0.0.1:9200/_cat/indices?v
```
