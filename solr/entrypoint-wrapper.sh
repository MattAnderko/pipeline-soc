#!/bin/bash

# Configure Wazuh agent to point to manager
if [ -n "$WAZUH_MANAGER" ]; then
  sed -i "s|<address>MANAGER_IP</address>|<address>${WAZUH_MANAGER}</address>|g" /var/ossec/etc/ossec.conf
  # If the placeholder doesn't exist, set it directly
  sed -i "s|<server>|<server>\n      <address>${WAZUH_MANAGER}</address>|g" /var/ossec/etc/ossec.conf 2>/dev/null || true

  # Configure agent to monitor Solr logs
  cat >> /var/ossec/etc/ossec.conf <<'AGENTEOF'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/solr/logs/solr.log</location>
  </localfile>
</ossec_config>
AGENTEOF

  # Start Wazuh agent
  /var/ossec/bin/wazuh-control start &
fi

# Start Solr as the solr user
exec gosu solr solr-foreground
