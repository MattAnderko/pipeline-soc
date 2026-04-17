FROM gitlab/gitlab-ce:13.10.2-ce.0

# Install vulnerable sudo (Baron Samedit: CVE-2021-3156)
# GitLab 13.10.2 ships on Ubuntu 20.04 (Focal)
# Ubuntu 20.04 base sudo 1.8.31 is vulnerable to CVE-2021-3156 (fix requires >= 1.8.32 / 1.9.5p2)
# Install the unpatched base focal version and pin it to prevent upgrades
RUN apt-get update && \
    apt-get install -y wget gnupg2 && \
    apt-get install -y --allow-downgrades sudo=1.8.31-1ubuntu1 && \
    apt-mark hold sudo && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Verify sudo is vulnerable: version should be < 1.8.32
RUN sudo --version | head -1

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=4.7.5-1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint-wrapper.sh /opt/entrypoint-wrapper.sh
RUN chmod +x /opt/entrypoint-wrapper.sh

# GitLab default ports
EXPOSE 80 443 22

ENTRYPOINT ["/opt/entrypoint-wrapper.sh"]
