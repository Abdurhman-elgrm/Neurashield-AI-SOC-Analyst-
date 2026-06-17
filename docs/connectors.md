# External Connector Setup Guide

All connectors use the same endpoint pattern:

```
POST https://backend-production-a9cb4.up.railway.app/api/v1/connectors/{source}/ingest
X-API-Key: <your-api-key>
Content-Type: application/json
```

Get your API key from the dashboard → Settings → API Keys → Create Key.

Supported sources: `wazuh` · `suricata` · `defender` · `syslog` · `generic` · `webhook`

---

## Wazuh

Wazuh can forward alerts to HTTP endpoints via the **Custom Integration** module.

### 1. Create integration script

Create `/var/ossec/integrations/custom-neurashield`:

```bash
#!/usr/bin/env python3
import sys
import json
import requests

alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()

API_KEY = "ns_your_api_key_here"
URL = "https://backend-production-a9cb4.up.railway.app/api/v1/connectors/wazuh/ingest"

requests.post(URL, json=alert, headers={"X-API-Key": API_KEY}, timeout=10)
```

```bash
chmod 750 /var/ossec/integrations/custom-neurashield
chown root:wazuh /var/ossec/integrations/custom-neurashield
```

### 2. Add to ossec.conf

```xml
<integration>
  <name>custom-neurashield</name>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

### 3. Restart Wazuh manager

```bash
systemctl restart wazuh-manager
```

**Payload format:**
```json
{
  "id": "1700000000.12345",
  "timestamp": "2024-01-01T00:00:00.000+0000",
  "rule": { "level": 10, "description": "SSH brute force", "groups": ["authentication_failure"] },
  "agent": { "name": "prod-server-01", "id": "001" },
  "data": { "srcip": "1.2.3.4", "dstuser": "root" },
  "full_log": "Jan  1 00:00:00 prod-server-01 sshd[1234]: Failed password for root"
}
```

---

## Suricata

### Via HTTP (eve-http output plugin)

Install the `suricata-output-http` plugin or configure `suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: http
      url: https://backend-production-a9cb4.up.railway.app/api/v1/connectors/suricata/ingest
      extra-headers:
        X-API-Key: "ns_your_api_key_here"
      types:
        - alert
        - dns
        - http
        - tls
        - ssh
```

### Via Filebeat / Vector

If using Filebeat to ship `/var/log/suricata/eve.json`:

```yaml
# filebeat.yml
output.http:
  hosts: ["https://backend-production-a9cb4.up.railway.app"]
  path: "/api/v1/connectors/suricata/ingest"
  headers:
    X-API-Key: "ns_your_api_key_here"
  codec.json:
    pretty: false
```

**Payload format (EVE JSON):**
```json
{
  "timestamp": "2024-01-01T00:00:00.000000+0000",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "10.0.0.1",
  "dest_port": 443,
  "proto": "TCP",
  "host": "suricata-sensor",
  "alert": {
    "action": "allowed",
    "signature": "ET MALWARE Suspicious User-Agent",
    "severity": 2
  }
}
```

---

## Microsoft Defender ATP

### Configure a Logic App webhook

1. Go to **Microsoft Defender Security Center** → Settings → Notifications
2. Create a custom connector pointing to:
   ```
   POST https://backend-production-a9cb4.up.railway.app/api/v1/connectors/defender/ingest
   X-API-Key: ns_your_api_key_here
   ```
3. Select alert severity levels to forward (Informational, Low, Medium, High, Critical)

### Via Microsoft Sentinel / Logic Apps

In your Logic App, add an HTTP action after the Defender alert trigger:

```json
{
  "method": "POST",
  "uri": "https://backend-production-a9cb4.up.railway.app/api/v1/connectors/defender/ingest",
  "headers": {
    "X-API-Key": "ns_your_api_key_here",
    "Content-Type": "application/json"
  },
  "body": "@triggerBody()"
}
```

**Payload format:**
```json
{
  "id": "da637990777642407787_-739974532",
  "title": "Suspicious PowerShell command line",
  "severity": "High",
  "status": "Active",
  "category": "Execution",
  "computerDnsName": "WORKSTATION-01",
  "createdTime": "2024-01-01T00:00:00Z",
  "detectionSource": "WindowsDefenderAtp",
  "evidence": [
    {
      "entityType": "Process",
      "processCommandLine": "powershell.exe -enc BASE64...",
      "fileName": "powershell.exe"
    }
  ]
}
```

---

## Syslog

Forward syslog messages to the connector via rsyslog or any HTTP forwarder.

### Via rsyslog (omhttp module)

```
# /etc/rsyslog.d/99-neurashield.conf
module(load="omhttp")

action(
  type="omhttp"
  server="backend-production-a9cb4.up.railway.app"
  serverport="443"
  useHttps="on"
  template="RSYSLOG_SyslogProtocol23Format"
  restpath="api/v1/connectors/syslog/ingest"
  httpheaders="X-API-Key: ns_your_api_key_here\nContent-Type: text/plain"
)
```

Restart: `systemctl restart rsyslog`

### Direct HTTP (plain text body)

```bash
curl -X POST \
  https://backend-production-a9cb4.up.railway.app/api/v1/connectors/syslog/ingest \
  -H "X-API-Key: ns_your_api_key_here" \
  -H "Content-Type: text/plain" \
  --data '<134>Jan  1 00:00:00 myhost sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2'
```

### JSON wrapper

```bash
curl -X POST \
  https://backend-production-a9cb4.up.railway.app/api/v1/connectors/syslog/ingest \
  -H "X-API-Key: ns_your_api_key_here" \
  -H "Content-Type: application/json" \
  --data '{"message": "<134>Jan 1 00:00:00 myhost sshd[1234]: Failed password for root"}'
```

---

## Generic / Webhook

Use this for any custom source — scripts, alerting tools, SIEM exports.

```bash
curl -X POST \
  https://backend-production-a9cb4.up.railway.app/api/v1/connectors/generic/ingest \
  -H "X-API-Key: ns_your_api_key_here" \
  -H "Content-Type: application/json" \
  --data '{
    "timestamp": "2024-01-01T00:00:00Z",
    "hostname": "my-server",
    "category": "auth",
    "severity": 3,
    "username": "root",
    "source_ip": "1.2.3.4",
    "message": "Suspicious login attempt"
  }'
```

**Accepted fields:**

| Field | Type | Description |
|---|---|---|
| `event_id` | string | Optional dedup ID |
| `timestamp` | ISO-8601 | Event time (defaults to now) |
| `hostname` | string | Source hostname |
| `category` | string | `process\|network\|file\|auth\|registry\|dns\|other` |
| `severity` | int or string | `1-4` or `low\|medium\|high\|critical` |
| `source_ip` | string | Source IP address |
| `dest_ip` | string | Destination IP address |
| `username` | string | Associated user |
| `process_name` | string | Process name |
| `command_line` | string | Full command |
| `os_type` | string | `windows\|linux\|other` |
| Any other fields | any | Passed through to raw payload |

---

## Verify ingestion

Check that events appear in the Events page, or test the endpoint directly:

```bash
# Should return {"data": {"accepted": 1, "rejected": 0, "source_type": "generic"}}
curl -X POST \
  https://backend-production-a9cb4.up.railway.app/api/v1/connectors/generic/ingest \
  -H "X-API-Key: ns_your_api_key_here" \
  -H "Content-Type: application/json" \
  --data '{"hostname":"test","category":"auth","severity":2,"message":"test event"}'
```
