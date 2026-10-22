#!/usr/bin/env bash
set -euo pipefail

# Restrictive baseline: deny unsolicited traffic and permit only explicitly approved services.
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw default deny routed

# Administrative Access: VPN access strictly for maintenance or security checks

# Replace **192.168.0.1** with VPN subnet
sudo ufw limit from 192.168.0.1/24 to any port 22 proto tcp comment 'SSH using VPN'


# Replace these rules with the host's documented management and service requirements.

# DNS
sudo ufw allow out to 8.8.8.8 port 53 proto udp comment 'DNS'
# For large DNS Response
sudo ufw allow out to 8.8.8.8 port 53 proto tcp comment 'DNS TCP Fallback'

# NTP
sudo ufw allow out to 162.159.200.1 port 123 proto udp comment 'NTP'

sudo ufw logging medium
sudo ufw --force enable
sudo ufw status verbose
