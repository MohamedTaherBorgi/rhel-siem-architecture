# Complete Deployment Guide & Technical Reference
**Hardened Open-Source Log Processing Architecture on RHEL 9.6**  
**Target Audience**: Students, Evaluators, and DevOps/SecOps Engineers building the stack from a fresh VM  
**Primary Stack**: OpenSearch 2.18.0 · OpenSearch Dashboards 2.18.0 · Fluent Bit 3.1.9 · RHEL 9.6 Minimal  
**Author**: BORGI Mohamed Taher  

---

## Executive Summary & Architecture Overview

This project implements a multi-source, fault-tolerant, open-source Security Information and Event Management (SIEM) log pipeline on a hardened Red Hat Enterprise Linux 9.6 host using Docker Compose. 

The pipeline ingests security events from four distinct telemetry layers:
1. **Linux Audit Subsystem (`auditd`)**: Kernel syscalls, executable executions, and sudoers modifications.
2. **Host Authentication (`/var/log/secure`)**: PAM authentication challenges and OpenSSH login decisions.
3. **systemd Journal Socket (`/run/log/journal`)**: Binary daemon unit logs and process execution context.
4. **Remote Syslog (RFC 5424 over TCP/UDP Port 5140)**: Network device and remote adversary telemetry.

The ingested stream is normalized into a unified schema, parsed with regular expressions into typed entities (`src_ip`, `src_port`, `target_user`), buffered across RAM and disk, indexed into a single-node OpenSearch 2.18 cluster (with **GREEN** health and native `ip` data types), and visualized on a multi-widget OpenSearch Dashboards SOC interface.

---

## Complete End-to-End Build Guide (Fresh VM Checklist)

```
[Phase 0: Hypervisor Network] ──► [Phase 1: Kernel Tuning] ──► [Phase 2: Docker & Storage]
                                                                        │
[Phase 5: Dashboards]         ◄── [Phase 4: Host Hardening] ◄── [Phase 3: Configurations]
```

### Phase 0: VirtualBox Network & Static IP Setup
*Objective: Guarantee consistent, offline inter-VM communication without Windows driver bugs.*

1. In VirtualBox Manager $\rightarrow$ **Tools** $\rightarrow$ **NAT Networks** tab $\rightarrow$ click **`+` (Create)**.
2. Name: `NatNetwork`, CIDR: `10.0.2.0/24`, DHCP: **Enabled**.
3. Under **Port Forwarding**, add these 3 rules:
   - **SSH**: Host IP `127.0.0.1`, Host Port `2222` $\rightarrow$ Guest IP `10.0.2.10`, Guest Port `22`
   - **Dashboards**: Host IP `127.0.0.1`, Host Port `5601` $\rightarrow$ Guest IP `10.0.2.10`, Guest Port `5601`
   - **Syslog**: Host IP `127.0.0.1`, Host Port `5140` $\rightarrow$ Guest IP `10.0.2.10`, Guest Port `5140`
4. Attach **RHEL 9.6 VM** Network Adapter 1 to `NAT Network` (Name: `NatNetwork`).
5. Attach **Kali Linux VM** Network Adapter 1 to `NAT Network` (Name: `NatNetwork`).
6. Boot RHEL 9.6 and lock its static IP to `10.0.2.10`:
   ```bash
   sudo nmcli connection modify enp0s3 ipv4.addresses 10.0.2.10/24 ipv4.gateway 10.0.2.1 ipv4.dns "10.0.2.1 8.8.8.8" ipv4.method manual
   sudo nmcli connection up enp0s3
   ```
7. Boot Kali Linux and verify connectivity:
   ```bash
   ping -c 3 10.0.2.10
   ```

---

### Phase 1: Host Operating System & Kernel Tuning
*Objective: Meet OpenSearch Lucene memory-mapping prerequisites and enable packet routing.*

1. Apply kernel parameters:
   ```bash
   sudo tee /etc/sysctl.d/99-siem-tuning.conf << 'EOF'
   vm.max_map_count=262144
   vm.swappiness=1
   net.ipv4.ip_forward=1
   EOF

   sudo sysctl --system
   ```
2. Verify:
   ```bash
   sysctl vm.max_map_count
   # Must output: vm.max_map_count = 262144
   ```

---

### Phase 2: Container Runtime & Storage Scaffolding
*Objective: Install Docker CE, configure user permissions, and establish persistent storage.*

1. Install Docker Engine & Compose plugin:
   ```bash
   # Remove conflicting default packages
   sudo dnf remove -y podman buildah

   # Add official Docker repository and install
   sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
   sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

   # Enable Docker daemon and add user to docker group
   sudo systemctl enable --now docker
   sudo usermod -aG docker $USER
   newgrp docker
   ```

2. Create directory tree and set ownership:
   ```bash
   mkdir -p ~/siem-stack/configs/fluent-bit
   mkdir -p ~/siem-stack/configs/opensearch
   mkdir -p ~/siem-stack/storage/opensearch-data
   mkdir -p ~/siem-stack/storage/fluent-bit-buffer

   # OpenSearch runs as UID 1000:GID 1000
   sudo chown -R 1000:1000 ~/siem-stack/storage/opensearch-data

   # Apply SELinux container_file_t context
   sudo chcon -Rt container_file_t ~/siem-stack/configs
   ```

---

### Phase 3: Deploy Configuration Files & Launch Containers
*Objective: Write the orchestration spec, parsers, pipeline, and index template.*

1. Deploy **`~/siem-stack/docker-compose.yml`** (see Section 1 below).
2. Deploy **`~/siem-stack/configs/fluent-bit/parsers.conf`** (see Section 2 below).
3. Deploy **`~/siem-stack/configs/fluent-bit/fluent-bit.conf`** (see Section 3 below).
4. Deploy **`~/siem-stack/configs/opensearch/index-template.json`** (see Section 4 below).
5. Validate configuration syntax:
   ```bash
   cd ~/siem-stack
   docker compose config
   ```
6. Start OpenSearch and Dashboards first:
   ```bash
   docker compose up -d opensearch opensearch-dashboards
   ```
7. Wait 20 seconds for OpenSearch bootstrap, then push the index template:
   ```bash
   docker exec -i siem-opensearch curl -s -X PUT "http://127.0.0.1:9200/_index_template/security_logs_template" \
     -H "Content-Type: application/json" -d @- < ~/siem-stack/configs/opensearch/index-template.json
   # Must output: {"acknowledged":true}
   ```
8. Start Fluent Bit:
   ```bash
   docker compose up -d fluent-bit
   docker compose ps
   # All 3 containers must show status: Up
   ```

---

### Phase 4: Apply Host Hardening Baseline
*Objective: Enforce defense-in-depth across SELinux, firewalld, CIS OpenSSH, and auditd.*

1. Configure **firewalld** zones and restore Docker chains (see Section 5 below).
2. Deploy **CIS OpenSSH** drop-in and restart sshd (see Section 6 below).
3. Deploy **Linux auditd** privilege escalation rules (see Section 7 below).

---

### Phase 5: Build SOC Dashboard & Validate Telemetry
*Objective: Create the presentation interface and verify real-time attack detection.*

1. Open your browser on Windows: **`http://localhost:5601`**.
2. **Method A (Automated 1-Click Restore)**:
   * Go to **Stack Management** $\rightarrow$ **Saved Objects** $\rightarrow$ Click **Import** $\rightarrow$ select `configs/dashboards/soc-dashboard.ndjson`.
   * All 6 SOC widgets and the `logs-security-*` index pattern are restored instantly!
3. **Method B (Manual Build)**:
   * Go to **Stack Management** $\rightarrow$ **Index Patterns** $\rightarrow$ Create index pattern `logs-security-*` with time field `@timestamp`.
   * Construct the 6 SOC widgets outlined in Section 8 below.
4. Simulate attacks from Windows and Kali to verify live detection.

---

## Detailed File-by-File Technical Reference

---

### 1. File: `~/siem-stack/docker-compose.yml`

#### Purpose
Defines the multi-container topology, memory resource allocations, volume bindings, and private software bridge network for the three core services: `siem-opensearch`, `siem-dashboards`, and `siem-fluent-bit`.

#### Complete Code
```yaml
services:
  opensearch:
    image: opensearchproject/opensearch:2.18.0
    container_name: siem-opensearch
    environment:
      - cluster.name=siem-cluster
      - node.name=siem-node1
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"
      - DISABLE_SECURITY_PLUGIN=true
      - DISABLE_INSTALL_DEMO_CONFIG=true
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - ./storage/opensearch-data:/usr/share/opensearch/data:z
    networks:
      siem-internal:
        ipv4_address: 172.28.0.20
    restart: unless-stopped

  opensearch-dashboards:
    image: opensearchproject/opensearch-dashboards:2.18.0
    container_name: siem-dashboards
    environment:
      - OPENSEARCH_HOSTS=["http://172.28.0.20:9200"]
      - DISABLE_SECURITY_DASHBOARDS_PLUGIN=true
    ports:
      - "5601:5601"
    networks:
      siem-internal:
        ipv4_address: 172.28.0.30
    depends_on:
      - opensearch
    restart: unless-stopped

  fluent-bit:
    image: fluent/fluent-bit:3.1.9
    container_name: siem-fluent-bit
    user: "0:0"
    security_opt:
      - label=disable
    volumes:
      - ./configs/fluent-bit:/fluent-bit/etc:ro,z
      - /var/log:/var/log:ro
      - /run/log/journal:/run/log/journal:ro
      - /etc/machine-id:/etc/machine-id:ro
      - ./storage/fluent-bit-buffer:/fluentbit-buffer:z
    ports:
      - "5140:5140/tcp"
      - "5140:5140/udp"
    networks:
      siem-internal:
        ipv4_address: 172.28.0.10
    depends_on:
      - opensearch
    restart: unless-stopped

networks:
  siem-internal:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.28.0.0/16
```

#### Detailed Directive Mechanics
- `discovery.type=single-node`: Disables multi-node cluster quorum election, enabling rapid single-node startup without needing master-eligible peer voting.
- `bootstrap.memory_lock=true` & `ulimits: memlock: -1`: Works with the host kernel setting `vm.swappiness=1` to lock the JVM heap into physical RAM using the Linux `mlockall()` syscall, ensuring database memory pages are never swapped to disk.
- `"OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"`: Sets initial heap (`-Xms`) equal to maximum heap (`-Xmx`) at 2 GB. This prevents runtime JVM heap resizing pauses, which cause node-unresponsive timeouts during heavy indexing bursts.
- `DISABLE_SECURITY_PLUGIN=true`: Disables the internal demo TLS/HTTPS layer on port 9200. This is an architectural optimization for this lab: port 9200 is unexposed to the host and restricted strictly to the private `siem-internal` bridge network (`172.28.0.0/16`), providing network-level isolation without TLS overhead.
- `security_opt: [ "label=disable" ]`: Instructs Docker/SELinux not to confine the `siem-fluent-bit` container within the standard `container_t` domain. This is required because Fluent Bit must read `/var/log/audit/audit.log`, which is labeled with `auditd_log_t`. Without this, SELinux Mandatory Access Control blocks audit log reading.
- `./storage/fluent-bit-buffer:/fluentbit-buffer:z`: Mounts Fluent Bit's buffer folder to an independent path rather than `/var/log/fluentbit`. This avoids the Linux container runtime error caused by attempting to create a writable sub-mount inside a read-only parent mount (`/var/log:ro`).

---

### 2. File: `~/siem-stack/configs/fluent-bit/parsers.conf`

#### Purpose
Defines the regular expression tokenizers that transform unstructured text strings into structured, typed key-value dictionaries.

#### Complete Code
```ini
[PARSER]
    Name        sshd_failed_login
    Format      regex
    Regex       ^(?:.*sshd\[\d+\]:\s+)?Failed password for (?:invalid user )?(?<target_user>[^\s]+) from (?<src_ip>[^\s]+) port (?<src_port>\d+)(?: ssh2)?$
    Types       src_port:integer

[PARSER]
    Name        sshd_invalid_user
    Format      regex
    Regex       ^(?:.*sshd\[\d+\]:\s+)?Invalid user (?<target_user>[^\s]+) from (?<src_ip>[^\s]+) port (?<src_port>\d+)
    Types       src_port:integer

[PARSER]
    Name        sudo_violation
    Format      regex
    Regex       ^(?:.*sudo\[\d+\]:\s+)?(?<actor>[^\s]+)\s+:\s+user NOT in sudoers\s*;\s*TTY=(?<tty>[^\s]+)\s*;\s*PWD=(?<pwd>[^\s]+)\s*;\s*USER=(?<target_user>[^\s]+)\s*;\s*COMMAND=(?<command>.*)$

[PARSER]
    Name        auditd_syscall
    Format      regex
    Regex       ^type=(?<audit_type>[A-Z_]+)\s+msg=audit\((?<audit_epoch>[0-9.]+):(?<audit_id>[0-9]+)\):\s+arch=(?<arch>[0-9a-fA-F]+)\s+syscall=(?<syscall>[0-9]+)\s+success=(?<success>[a-z]+)\s+exit=(?<exit_code>[-0-9]+).*?\sauid=(?<auid>[0-9]+)\s+uid=(?<uid>[0-9]+)\s+gid=(?<gid>[0-9]+)\s+euid=(?<euid>[0-9]+).*?\sexe="(?<exe>[^"]+)"(?:.*key="(?<audit_key>[^"]+)")?
    Types       syscall:integer exit_code:integer auid:integer uid:integer gid:integer euid:integer

[PARSER]
    Name        auditd_header
    Format      regex
    Regex       ^type=(?<audit_type>[A-Z_]+)\s+msg=audit\((?<audit_epoch>[0-9.]+):(?<audit_id>[0-9]+)\):\s+(?<audit_body>.*)$

[PARSER]
    Name        syslog_rfc5424
    Format      regex
    Regex       ^\<(?<pri>[0-9]{1,5})\>1 (?<time>[^ ]+) (?<host>[^ ]+) (?<ident>[^ ]+) (?<pid>[-0-9]+) (?<msgid>[^ ]+) (?<extradata>(\[(.*)\]|-)) (?<message>.+)$
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L%z
```

#### Detailed Directive Mechanics
- `^(?:.*sshd\[\d+\]:\s+)?`: Makes the leading syslog header optional via non-capturing group `(?: ... )?`. This allows the same parser to match both `/var/log/secure` (which includes `Oct 1 23:13:40 localhost sshd[12620]: `) and `systemd-journald` (which strips the syslog prefix and begins directly with `Failed password...`).
- `Types src_port:integer`: Explicitly casts the parsed port string into a 32-bit integer in the Fluent Bit C engine before serializing to JSON. This prevents OpenSearch from indexing the port as text, enabling range and terms queries.
- `auditd_syscall`: Extracts the core fields of Linux kernel `type=SYSCALL` audit records. The trailing `(?:.*key="(?<audit_key>[^"]+)")?` makes the `-k` audit rule key optional, ensuring standard system calls without an assigned key are still parsed.
- `auditd_header`: A fallback parser for non-syscall audit records (`USER_LOGIN`, `CRYPTO_KEY_USER`, `NETFILTER_CFG`). It captures `audit_type`, `audit_epoch`, and `audit_id` so all audit events share standard correlation IDs.

---

### 3. File: `~/siem-stack/configs/fluent-bit/fluent-bit.conf`

#### Purpose
Configures the stream processing engine: input pollers, offset tracking databases, schema normalization filters, parser execution pipelines, and OpenSearch bulk output routing.

#### Complete Code
```ini
[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf
    Storage.path  /fluentbit-buffer/buffer
    Storage.sync  normal
    Storage.checksum off
    Storage.backlog.mem_limit 15M

# 1. Ingest /var/log/secure (SSH & PAM events)
[INPUT]
    Name              tail
    Tag               host.auth
    Path              /var/log/secure
    DB                /fluentbit-buffer/auth_tail.db
    Mem_Buf_Limit     10MB
    Skip_Long_Lines   On
    Refresh_Interval  1

# 2. Ingest /var/log/audit/audit.log (Linux kernel audit subsystem)
[INPUT]
    Name              tail
    Tag               host.audit
    Path              /var/log/audit/audit.log
    DB                /fluentbit-buffer/audit_tail.db
    Mem_Buf_Limit     10MB
    Skip_Long_Lines   On
    Refresh_Interval  1

# 3. Ingest systemd-journald socket
[INPUT]
    Name              systemd
    Tag               host.journal
    Path              /run/log/journal
    Read_From_Tail    On

# 4. Ingest Remote Syslog (TCP & UDP on Port 5140)
[INPUT]
    Name              syslog
    Tag               remote.syslog
    Mode              tcp
    Port              5140
    Parser            syslog_rfc5424

[INPUT]
    Name              syslog
    Tag               remote.syslog
    Mode              udp
    Port              5140
    Parser            syslog_rfc5424

# --- SCHEMA NORMALIZATION FILTERS ---
[FILTER]
    Name              modify
    Match             host.auth
    Rename            log message

[FILTER]
    Name              modify
    Match             host.audit
    Rename            log message

[FILTER]
    Name              modify
    Match             host.journal
    Rename            MESSAGE message

# --- PARSING & TOKENIZATION FILTERS ---
[FILTER]
    Name              parser
    Match             *
    Key_Name          message
    Parser            sshd_failed_login
    Reserve_Data      On
    Preserve_Key      On

[FILTER]
    Name              parser
    Match             *
    Key_Name          message
    Parser            sshd_invalid_user
    Reserve_Data      On
    Preserve_Key      On

[FILTER]
    Name              parser
    Match             *
    Key_Name          message
    Parser            sudo_violation
    Reserve_Data      On
    Preserve_Key      On

[FILTER]
    Name              parser
    Match             host.audit
    Key_Name          message
    Parser            auditd_syscall
    Reserve_Data      On
    Preserve_Key      On

[FILTER]
    Name              parser
    Match             host.audit
    Key_Name          message
    Parser            auditd_header
    Reserve_Data      On
    Preserve_Key      On

# Metadata enrichment
[FILTER]
    Name              record_modifier
    Match             *
    Record            lab_node rhel-9.6-siem
    Record            pipeline fluent-bit-c-engine

# Output: Route into OpenSearch 2.18
[OUTPUT]
    Name                opensearch
    Match               *
    Host                172.28.0.20
    Port                9200
    Suppress_Type_Name  On
    Generate_ID         On
    Logstash_Format     On
    Logstash_Prefix     logs-security
    Logstash_DateFormat %Y.%m.%d
    Time_Key            @timestamp
    Include_Tag_Key     On
    Tag_Key             routing_tag
    Workers             2
    Trace_Error         On
```

#### Detailed Directive Mechanics
- `DB /fluentbit-buffer/auth_tail.db`: Maintains an SQLite database on disk tracking file inode numbers and byte offsets. If the VM reboots or the container is restarted, Fluent Bit resumes reading from the exact byte offset where it stopped, guaranteeing zero duplicate logs and zero missed events.
- `Flush 1`: Flushes internal memory buffers to OpenSearch every 1 second, providing sub-second event streaming to the SOC dashboard.
- `Rename log message` / `Rename MESSAGE message`: **Schema Normalization**. `systemd-journald` produces uppercase `MESSAGE`, while `in_tail` produces lowercase `log`. This filter standardizes every log line from every source into a single unified `message` field.
- `Preserve_Key On`: Critical setting. By default, Fluent Bit deletes the source key (`Key_Name message`) upon successful regex matching. Setting `Preserve_Key On` ensures both the structured extracted fields (`src_ip`, `target_user`) and the original raw text string (`message`) are indexed together.
- `Suppress_Type_Name On`: Enforces OpenSearch 2.x compliance by stripping the legacy `_type: _doc` field from the HTTP bulk payload action headers, preventing `unknown parameter [_type]` errors.
- `Logstash_Format On` & `Logstash_Prefix logs-security`: Partitions data into daily time-series indices (`logs-security-YYYY.MM.DD`). This is the industry-standard storage pattern for SIEM architectures, allowing automated retention and lifecycle rotation.

---

### 4. File: `~/siem-stack/configs/opensearch/index-template.json`

#### Purpose
Enforces an explicit schema contract across all new daily indices matching `logs-security-*`. Prevents schema drift, turns cluster health **GREEN**, and sets native data types.

#### Complete Code
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
        "pwd": { "type": "keyword" },
        "tty": { "type": "keyword" },
        "audit_type": { "type": "keyword" },
        "audit_id": { "type": "keyword" },
        "audit_epoch": { "type": "double" },
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

#### Detailed Directive Mechanics
- `"number_of_replicas": 0`: **Turns Cluster Health from Yellow to Green**. By default, OpenSearch allocates 1 replica shard per primary shard. In a single-node lab, the replica shard cannot be placed on another node, leaving the cluster permanently in `yellow` warning state. Setting replicas to `0` resolves this immediately.
- `"src_ip": { "type": "ip" }`: Maps `src_ip` as a native IPv4/IPv6 address rather than generic text. This enables CIDR mask queries (e.g., `src_ip: "10.0.2.0/24"`), IP range filtering, and geographical map aggregations.
- `"target_user": { "type": "keyword" }`: Maps usernames as non-analyzed keywords. Unlike `text` fields (which are split by analyzers into lowercase word tokens), `keyword` preserves the exact case and whitespace, enabling fast terms aggregations for bar charts and pie charts.

---

### 5. File: `/etc/firewalld/` Segmentation Script

#### Purpose
Enforces network segmentation by replacing RHEL's default permissive `public` zone with dedicated management and collection zones, following the principle of least privilege.

#### Complete Execution Script
```bash
# 1. Set default fallback zone to drop (drops all unapproved incoming packets)
sudo firewall-cmd --set-default-zone=drop

# 2. Create Management Zone (Restricted to Host IP 10.0.2.1 / Windows Workstation)
sudo firewall-cmd --permanent --new-zone=siem-mgmt 2>/dev/null || true
sudo firewall-cmd --permanent --zone=siem-mgmt --add-service=ssh
sudo firewall-cmd --permanent --zone=siem-mgmt --add-port=5601/tcp
sudo firewall-cmd --permanent --zone=siem-mgmt --add-source=10.0.2.1/32

# 3. Create Collector Zone (Permits Syslog from the Lab Subnet)
sudo firewall-cmd --permanent --new-zone=siem-collector 2>/dev/null || true
sudo firewall-cmd --permanent --zone=siem-collector --add-port=5140/tcp
sudo firewall-cmd --permanent --zone=siem-collector --add-port=5140/udp
sudo firewall-cmd --permanent --zone=siem-collector --add-source=10.0.2.0/24

# 4. Reload firewalld rules into memory
sudo firewall-cmd --reload

# 5. CRITICAL: Restart Docker daemon to restore DOCKER nftables/iptables chains
sudo systemctl restart docker
```

#### Detailed Directive Mechanics
- `--set-default-zone=drop`: Any packet arriving from an unknown source or targeting an unauthorized port is silently discarded at the kernel netfilter layer without returning an ICMP port unreachable response.
- `siem-mgmt` zone with source `10.0.2.1/32`: Restricts administration interfaces (SSH port 22 and Dashboards port 5601) strictly to the Windows host. An attacker on Kali (`10.0.2.3`) cannot access port 5601.
- `sudo systemctl restart docker`: **Mitigates the RHEL 9 Docker chain flush trap**. Reloading firewalld wipes Docker's internal container routing chains. Restarting Docker re-injects the container bridges into nftables cleanly.

---

### 6. File: `/etc/ssh/sshd_config.d/01-cis-hardening.conf`

#### Purpose
Aligns the OpenSSH server with the CIS (Center for Internet Security) RHEL Benchmark, disabling insecure ciphers, root logins, and session abuses.

#### Complete Code
```sshconfig
# Protocol & Port
Port 22
Protocol 2
AddressFamily inet

# Authentication Controls
PermitRootLogin no
MaxAuthTries 6
MaxSessions 10
LoginGraceTime 60
PasswordAuthentication yes
PubkeyAuthentication yes

# Modern Cryptographic Suites (Curve25519 & ChaCha20-Poly1305)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com

# Channel & Forwarding Lockdown
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 0
```

#### Detailed Directive Mechanics
- `PermitRootLogin no`: Mitigates **MITRE ATT&CK T1078 (Valid Accounts)** by requiring administrative access via unprivileged named accounts first.
- `MaxAuthTries 6`: Limits authentication attempts per TCP connection, slowing down brute-force tools while avoiding immediate client disconnects during automated checks.
- `MaxSessions 10`: Bounded session limit aligned with CIS Recommendation 5.2.19. Prevents session exhaustion while allowing IDE multiplexed background channels (file watchers, terminal splits, language servers) to operate without disconnection.
- `KexAlgorithms curve25519-sha256...`: Restricts key exchange to modern elliptic-curve cryptography, removing vulnerable legacy Diffie-Hellman group 1 and SHA-1 algorithms.

---

### 7. File: `/etc/audit/rules.d/99-privesc.rules`

#### Purpose
Instructs the Linux kernel audit subsystem (`auditd`) to monitor system calls and files associated with privilege escalation and identity tampering.

#### Complete Code
```audit
## Delete all previous rules
-D

## Set kernel audit buffer size
-b 8192

## Failure mode: printk (log to kernel ring buffer on audit failure)
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

#### Detailed Directive Mechanics
- `-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000`: Triggers an audit record whenever a non-root user (`auid >= 1000`) executes a binary that runs with root effective privileges (`euid = 0`, such as `sudo`, `su`, or SUID binaries).
- `-k priv_esc_exec`: Tags the event with a searchable key string (`priv_esc_exec`), which Fluent Bit extracts into `audit_key` for immediate SIEM alerting.
- `-w /etc/sudoers -p wa`: Monitors the sudoers configuration file for write (`w`) and attribute (`a`) modifications, alerting on persistence establishment.

---

### 8. OpenSearch Dashboards SOC Interface Architecture

#### SOC Incident Dashboard Configuration
**Dashboard Name**: `SOC Security Incident Dashboard`  
**Target Index Pattern**: `logs-security-*`  

| Widget | Visualization Type | Query / DQL Filter | Bucket / Metric Configuration | Security Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Total Attack Counter** | Metric Tile | `routing_tag: "host.auth" AND message: "Failed password*"` | Metric: **Count** | Real-time deduplicated counter for failed SSH password attempts. |
| **Privilege Escalation Violations** | Metric Tile | `actor: * OR audit_key: "priv_esc_exec"` | Metric: **Count** | Real-time counter for local unauthorized sudo and kernel privesc calls. |
| **Telemetry Distribution by Layer** | Donut / Pie Chart | `*` | Aggregation: **Terms**, Field: `routing_tag`, Size: 5 | Shows log volume breakdown across `host.auth`, `host.audit`, `host.journal`, and `remote.syslog`. |
| **Top Attacker IPs** | Donut / Pie Chart | `routing_tag: "host.auth" AND src_ip: *` | Aggregation: **Terms**, Field: `src_ip`, Size: 5 | Visualizes external attack origin (e.g., `10.0.2.3` from Kali vs `10.0.2.1`). |
| **Top Targeted Usernames** | Horizontal Bar | `routing_tag: "host.auth" AND target_user: *` | Aggregation: **Terms**, Field: `target_user`, Size: 10 | Identifies brute-forced accounts (`admin`, `root`, `kali`, `taher`). |
| **Live Security Incident Stream** | Saved Search Table | `src_ip: * OR actor: * OR audit_key: *` (or `*`) | **Columns (in order)**:<br/>`Time`, `message`, `target_user`, `routing_tag`, `src_ip`, `actor`, `audit_key` | Unified live forensic incident stream capturing external network attacks, local privilege escalations, and remote syslog bursts. |

#### Infrastructure-as-Code (IaC) Dashboard Export & Import
To guarantee 100% automated reproducibility on fresh VM deployments without manually rebuilding charts:

1. **Export (Backup)**:
   In OpenSearch Dashboards $\rightarrow$ **Stack Management** $\rightarrow$ **Saved Objects** $\rightarrow$ Select `SOC Security Incident Dashboard` $\rightarrow$ Click **Export** (with *"Include related objects"* enabled) $\rightarrow$ Save as:
   `~/siem-stack/configs/dashboards/soc-dashboard.ndjson`

2. **Automated Import (Fresh Install Restore)**:
   A fresh installer can restore the entire dashboard and all 6 widgets in 3 seconds via curl:
   ```bash
   curl -X POST "http://localhost:5601/api/saved_objects/_import?createNewCopies=false" \
     -H "osd-xsrf: true" \
     --form file=@~/siem-stack/configs/dashboards/soc-dashboard.ndjson
   ```

---

## Health Verification Commands

Use these exact terminal commands to prove every subsystem is operational:

```bash
# 1. Verify Kernel Memory Map
sysctl vm.max_map_count
# Expected: vm.max_map_count = 262144

# 2. Verify Container Health
docker compose ps
# Expected: All 3 containers Up

# 3. Verify OpenSearch Cluster Health (Must be GREEN)
docker exec siem-opensearch curl -s http://127.0.0.1:9200/_cluster/health?pretty
# Expected: "status" : "green"

# 4. Verify Index Mapping & Document Counts
docker exec siem-opensearch curl -s http://127.0.0.1:9200/_cat/indices?v
# Expected: logs-security-YYYY.MM.DD status green with 0 replicas

# 5. Verify firewalld Active Zones
sudo firewall-cmd --get-active-zones
# Expected: siem-mgmt and siem-collector active

# 6. Verify auditd Rules Active in Kernel
sudo auditctl -l
# Expected: priv_esc_exec and sudoers_modification rules listed
```
