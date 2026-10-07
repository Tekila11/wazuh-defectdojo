#!/bin/bash
# Wazuh agent installer — Ubuntu 22.04
# Run on each VM as root:
#   sudo WAZUH_MANAGER=<ip> AGENT_NAME=<name> bash install_wazuh_agent.sh

set -euo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER:?Set WAZUH_MANAGER=<manager_ip>}"
AGENT_NAME="${AGENT_NAME:?Set AGENT_NAME=<vm_name>}"
WAZUH_VERSION="4.11.2"
WAZUH_GROUP="${WAZUH_GROUP:-servers-linux}"   # agent group in Wazuh manager

echo "=== Installing Wazuh agent ${WAZUH_VERSION} on ${AGENT_NAME} ==="

# 1. Add Wazuh repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --no-default-keyring \
        --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
        --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list

apt-get update -qq

# 2. Install agent — manager IP and agent name set at install time
WAZUH_MANAGER="${WAZUH_MANAGER}" \
WAZUH_MANAGER_PORT="1514" \
WAZUH_AGENT_NAME="${AGENT_NAME}" \
WAZUH_AGENT_GROUP="${WAZUH_GROUP}" \
  apt-get install -y wazuh-agent="${WAZUH_VERSION}-*"

# 3. Enable and start
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "=== Done. Agent status ==="
systemctl status wazuh-agent --no-pager -l

echo ""
echo "Verify enrollment on Wazuh manager:"
echo "  GET https://${WAZUH_MANAGER}:55000/agents?name=${AGENT_NAME}"
