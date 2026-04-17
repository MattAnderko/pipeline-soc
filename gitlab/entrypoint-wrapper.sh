#!/bin/bash

# Configure Wazuh agent
if [ -n "$WAZUH_MANAGER" ]; then
  sed -i "s|<address>MANAGER_IP</address>|<address>${WAZUH_MANAGER}</address>|g" /var/ossec/etc/ossec.conf
  sed -i "s|<server>|<server>\n      <address>${WAZUH_MANAGER}</address>|g" /var/ossec/etc/ossec.conf 2>/dev/null || true

  # Monitor GitLab logs and auth logs
  cat >> /var/ossec/etc/ossec.conf <<'AGENTEOF'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/gitlab/gitlab-rails/production.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <syscheck>
    <directories check_all="yes" realtime="yes">/root/.ssh,/var/spool/cron,/etc/crontab</directories>
  </syscheck>
</ossec_config>
AGENTEOF

  /var/ossec/bin/wazuh-control start &
fi

# Run the original GitLab entrypoint
exec /assets/wrapper
