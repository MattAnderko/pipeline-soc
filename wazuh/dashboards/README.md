# Wazuh Dashboard Setup

After the stack is running, access the dashboard at https://localhost:443
Login: wazuh-wui / MyS3cr3tP@ss

## Dashboards to Create

### 1. Attack Chain Overview
- **Type:** Saved search + visualization
- **Index pattern:** wazuh-alerts-*
- **Filter:** rule.groups contains "attack-chain"
- **Visualization:** Timeline (date histogram on timestamp, split by rule.groups)
- Shows all attack phases on a single timeline

### 2. Log4Shell Detection
- **Filter:** rule.id is one of [100100, 100101]
- **Columns:** timestamp, agent.name, rule.description, data.srcip
- **Visualization:** Metric count + data table

### 3. ExifTool RCE Detection
- **Filter:** rule.id is one of [100200, 100201, 100202]
- **Columns:** timestamp, agent.name, rule.description, full_log
- **Visualization:** Metric count + data table

### 4. Privilege Escalation Detection
- **Filter:** rule.id is one of [100300, 100301, 100302]
- **Columns:** timestamp, agent.name, rule.description, full_log
- **Visualization:** Metric count + event timeline

### 5. Persistence Detection
- **Filter:** rule.id is one of [100400, 100401, 100402, 100403]
- **Columns:** timestamp, agent.name, rule.description, syscheck.path
- **Visualization:** Metric count + file change timeline

### 6. Alert Severity Distribution
- **Type:** Pie chart
- **Aggregation:** Terms on rule.level
- **Shows:** Distribution of alert severities during attack

## NDJSON Export

After creating the dashboards manually, export them from the Wazuh Dashboard UI via Management → Stack Management → Saved Objects → Export.

Save the export to `wazuh/dashboards/export.ndjson` for reproducibility.
