#!/bin/bash
# Wazuh integration script for Microsoft Teams webhook
# Placed in: /var/ossec/integrations/custom-teams

ALERT_FILE=$1
WEBHOOK_URL=$3

# Parse alert JSON
ALERT_LEVEL=$(jq -r '.rule.level' "$ALERT_FILE")
ALERT_DESC=$(jq -r '.rule.description' "$ALERT_FILE")
ALERT_AGENT=$(jq -r '.agent.name // "N/A"' "$ALERT_FILE")
ALERT_RULE_ID=$(jq -r '.rule.id' "$ALERT_FILE")
ALERT_TIME=$(jq -r '.timestamp' "$ALERT_FILE")
ALERT_MITRE=$(jq -r '.rule.mitre.id[0] // "N/A"' "$ALERT_FILE")
ALERT_GROUPS=$(jq -r '.rule.groups | join(", ")' "$ALERT_FILE")

# Color based on severity
if [ "$ALERT_LEVEL" -ge 15 ]; then
    COLOR="FF0000"
    SEVERITY="CRITICAL"
elif [ "$ALERT_LEVEL" -ge 12 ]; then
    COLOR="FF8C00"
    SEVERITY="HIGH"
else
    COLOR="FFD700"
    SEVERITY="MEDIUM"
fi

# Build Teams Adaptive Card payload
PAYLOAD=$(cat <<EOF
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "${COLOR}",
  "summary": "Wazuh Alert: ${ALERT_DESC}",
  "sections": [{
    "activityTitle": "Wazuh SOC Alert - ${SEVERITY}",
    "facts": [
      { "name": "Rule", "value": "${ALERT_RULE_ID}: ${ALERT_DESC}" },
      { "name": "Agent", "value": "${ALERT_AGENT}" },
      { "name": "Level", "value": "${ALERT_LEVEL}" },
      { "name": "MITRE", "value": "${ALERT_MITRE}" },
      { "name": "Groups", "value": "${ALERT_GROUPS}" },
      { "name": "Time", "value": "${ALERT_TIME}" }
    ],
    "markdown": true
  }]
}
EOF
)

# Send to Teams
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d "$PAYLOAD" "$WEBHOOK_URL"

exit 0
