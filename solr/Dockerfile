FROM solr:8.11.0

USER root

# Install Wazuh agent
RUN apt-get update && \
    apt-get install -y curl apt-transport-https gnupg2 procps && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=4.7.5-1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Re-enable Log4Shell vulnerability (educational lab — remove the docker-solr mitigation)
RUN sed -i "/formatMsgNoLookups=true/d" \
    /opt/docker-solr/scripts/solr-fg \
    /opt/docker-solr/scripts/start-local-solr

# Wazuh agent config will be set at runtime via entrypoint
COPY entrypoint-wrapper.sh /opt/entrypoint-wrapper.sh
RUN chmod +x /opt/entrypoint-wrapper.sh

EXPOSE 8983

ENTRYPOINT ["/opt/entrypoint-wrapper.sh"]
