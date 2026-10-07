# wazuh-agent-install

Unattended Wazuh agent installer for Ubuntu 22.04. Not part of the cron pipeline; run it once per
host you want [`wazuh-to-defectdojo`](..) to collect vulnerabilities from.

## Usage

```bash
sudo WAZUH_MANAGER=<manager_ip> AGENT_NAME=<host_name> bash install_wazuh_agent.sh
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `WAZUH_MANAGER` | yes | | Manager IP or hostname the agent enrolls with |
| `AGENT_NAME` | yes | | Name the agent registers under, which becomes the DefectDojo product name |
| `WAZUH_GROUP` | no | `servers-linux` | Agent group on the manager, which becomes the DefectDojo product type |

The script adds the Wazuh APT repository, installs the pinned agent version, then enables and starts
the service.

Pick `AGENT_NAME` deliberately. `wazuh-to-defectdojo` creates one DefectDojo product per agent name,
and `defectdojo-to-opencti` turns that name into the OpenCTI `System` entity. A rename later leaves
orphaned products behind.

## Verifying enrollment

The script prints the check on completion:

```bash
curl -k -u <user>:<pass> "https://<manager_ip>:55000/agents?name=<host_name>"
```

An agent in `active` status with a recent `lastKeepAlive` is enrolled correctly.

## Windows hosts

Windows agents are installed from the MSI rather than this script. Two things catch people out: the
installer needs an elevated prompt, and the Windows service is named `Wazuh`, not `WazuhSvc`.

```powershell
Restart-Service -Name Wazuh
Get-Service -Name Wazuh
```
