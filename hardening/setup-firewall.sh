#!/usr/bin/env bash
set -euo pipefail
echo "[+] Applying firewalld zero-trust zone segmentation..."
# Set fallback default zone to drop
sudo firewall-cmd --set-default-zone=drop
# Create Management Zone (Restricted to 10.0.2.1/32)
sudo firewall-cmd --permanent --new-zone=siem-mgmt 2>/dev/null || true
sudo firewall-cmd --permanent --zone=siem-mgmt --add-service=ssh
sudo firewall-cmd --permanent --zone=siem-mgmt --add-port=5601/tcp
sudo firewall-cmd --permanent --zone=siem-mgmt --add-source=10.0.2.1/32
# Create Collector Zone (Permits Syslog from 10.0.2.0/24)
sudo firewall-cmd --permanent --new-zone=siem-collector 2>/dev/null || true
sudo firewall-cmd --permanent --zone=siem-collector --add-port=5140/tcp
sudo firewall-cmd --permanent --zone=siem-collector --add-port=5140/udp
sudo firewall-cmd --permanent --zone=siem-collector --add-source=10.0.2.0/24
# Reload firewalld rules
sudo firewall-cmd --reload
# CRITICAL: Restart Docker daemon to restore container nftables routing chains
echo "[+] Restoring Docker nftables chains..."
sudo systemctl restart docker
echo "[+] Firewall segmentation successfully applied!"
sudo firewall-cmd --get-active-zones
