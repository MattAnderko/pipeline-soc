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

# Ensure the CVE-2023-22809 sudoedit target file exists. GitLab's
# reconfigure can sweep /etc/gitlab, so re-create the trusted file on
# every boot so the sudoers rule has a valid target.
mkdir -p /etc/gitlab
[ -f /etc/gitlab/trusted.conf ] || touch /etc/gitlab/trusted.conf

# Start cron so Phase 4 (T1053.003) persistence works out of the box.
service cron start || true

# Run the original GitLab entrypoint
exec /assets/wrapper
