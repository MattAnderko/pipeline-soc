FROM gitlab/gitlab-ce:13.10.2-ce.0

# Install vulnerable sudo (CVE-2023-22809: sudoedit argument bypass).
# GitLab 13.10.2 ships on Ubuntu 20.04 (Focal) with sudo 1.8.31. The
# sudoedit `--` argument bypass was introduced in sudo 1.8.0 and not fixed
# until 1.9.12p2 (Jan 2023), so 1.8.31 is squarely in the vulnerable range.
# Install the unpatched base focal version and pin it to prevent upgrades.
RUN apt-get update && \
    apt-get install -y wget gnupg2 && \
    apt-get install -y --allow-downgrades sudo=1.8.31-1ubuntu1 && \
    apt-mark hold sudo && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Confirm sudo version is vulnerable (< 1.9.12p2) during build.
RUN sudo --version | head -1

# Lab misconfiguration that the CVE-2023-22809 exploit abuses:
# the sysadmin granted the git user passwordless sudoedit access to a
# single "trusted" config file, assuming that limits edits to that file.
# CVE-2023-22809 breaks that assumption — the `--` bypass lets the
# attacker slip /etc/shadow (or any file) into the editor's argv.
RUN mkdir -p /etc/gitlab && \
    touch /etc/gitlab/trusted.conf && \
    echo 'git ALL=(root) NOPASSWD: sudoedit /etc/gitlab/trusted.conf' \
        > /etc/sudoers.d/git-trusted && \
    chmod 440 /etc/sudoers.d/git-trusted && \
    visudo -c

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
