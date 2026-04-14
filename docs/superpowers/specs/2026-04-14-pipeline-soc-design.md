# Pipeline SOC — Design Spec

## Overview

A Dockerized attack simulation and SOC monitoring environment for a university security course project. Simulates a multi-step attack chain across vulnerable services while monitoring and detecting each phase with Wazuh.

## Attack Chain

| Phase | CVE / Technique | Target | Description |
|-------|----------------|--------|-------------|
| Initial Access | CVE-2021-44228 (Log4Shell) | Apache Solr 8.11.0 | JNDI injection via Solr query → reverse shell |
| Execution | CVE-2021-22205 (ExifTool RCE) | GitLab CE 13.10.2 | Malicious image upload → ExifTool executes payload → shell as `git` |
| Privilege Escalation | CVE-2021-3156 (Baron Samedit) | GitLab (sudo 1.8.31) | Heap overflow in sudo → `git` user escalates to `root` |
| Persistence | T1053.003 | GitLab | SSH key planted + cron job reverse shell |

All vulnerabilities are userland — no kernel dependency. Safe to run in Docker with any host kernel.

## Architecture

### Containers

| Container | Base Image | Purpose | Approx Size | Approx RAM |
|-----------|-----------|---------|-------------|------------|
| `attacker` | Ubuntu minimal | Attack scripts, marshalsec (LDAP), python3, netcat | ~300MB | ~128MB |
| `solr` | Apache Solr 8.11.0 | Victim 1 — Log4Shell target, runs Wazuh agent | ~500MB | ~512MB |
| `gitlab` | GitLab CE 13.10.2 | Victim 2 — ExifTool RCE + Baron Samedit, runs Wazuh agent | ~2.5GB | ~4GB |
| `wazuh` | Wazuh all-in-one | Manager + Indexer + Dashboard | ~1.5GB | ~2GB |

### Network

Single flat Docker network:

```
soc-net (172.20.0.0/24)
├── attacker    172.20.0.10
├── solr        172.20.0.20
├── gitlab      172.20.0.30
└── wazuh       172.20.0.40
```

## Attack Flow (Semi-Automated)

Individual scripts per step, triggered manually from the attacker container:

1. **`01-log4shell.sh`** — Starts marshalsec LDAP server + HTTP server hosting malicious class. Sends JNDI payload to Solr. Solr logs the string, Log4j evaluates it, connects to attacker's LDAP, downloads and executes the payload. Result: reverse shell on Solr container.

2. **`02-exiftool-rce.sh`** — Uploads a crafted image (with embedded payload in EXIF metadata) to GitLab via API. GitLab processes the image with ExifTool, which executes the embedded payload. Result: reverse shell as `git` user on GitLab container.

3. **`03-baron-samedit.sh`** — From the `git` user shell on GitLab, runs the Baron Samedit exploit against sudo 1.8.31. Heap buffer overflow via `sudoedit -s` with trailing backslash. Result: root shell on GitLab container.

4. **`04-persistence.sh`** — As root on GitLab: adds attacker's SSH public key to `/root/.ssh/authorized_keys` and creates a cron job that establishes a reverse shell to the attacker at regular intervals.

## Wazuh Detection Layer

### Agents
- Wazuh agents installed on `solr` and `gitlab` containers
- Agents forward logs and file integrity events to the Wazuh Manager

### Custom Detection Rules (`custom_rules.xml`)

| Rule | Detects | Attack Phase |
|------|---------|-------------|
| JNDI string pattern in Solr logs | Log4Shell exploitation attempt | Initial Access |
| ExifTool spawning unexpected child processes | GitLab ExifTool RCE | Execution |
| Anomalous sudo usage / sudo crash patterns | Baron Samedit exploitation | Privilege Escalation |
| New entries in crontab files | Cron persistence | Persistence |
| Modifications to `authorized_keys` files | SSH key persistence | Persistence |

### Built-in Rules (Wazuh out-of-the-box)
- File integrity monitoring (FIM) — detects changes to critical files
- Suspicious command execution
- New network connections
- Authentication events

### Dashboards
- One dashboard per attack phase showing relevant alerts and timeline
- Overview dashboard showing the full attack chain progression

### Alerting
- Teams webhook integration on the Wazuh Manager
- Fires on high-severity alerts (level 12+)
- Configured via Wazuh's `ossec.conf` integration block

## Repo Structure

```
pipeline-soc/
├── docker-compose.yml
├── attacker/
│   ├── Dockerfile
│   └── scripts/
│       ├── 01-log4shell.sh
│       ├── 02-exiftool-rce.sh
│       ├── 03-baron-samedit.sh
│       └── 04-persistence.sh
├── solr/
│   ├── Dockerfile
│   └── config/
├── gitlab/
│   ├── Dockerfile
│   └── config/
├── wazuh/
│   ├── Dockerfile (or official image with custom config)
│   ├── config/
│   │   └── ossec.conf
│   └── rules/
│       └── custom_rules.xml
└── docs/
```

## Key Design Decisions

1. **Flat network** — simplicity over realism. All containers can reach each other directly.
2. **Wazuh single-node** — all-in-one deployment sufficient for project scope, saves resources.
3. **Semi-automated attack scripts** — one script per step for controlled demo pacing.
4. **Apache Solr over TeamCity** — same Log4Shell vulnerability but ~4x lighter on resources.
5. **Baron Samedit over PwnKit** — userland sudo exploit works in Docker regardless of host kernel.
6. **Teams webhook** — meets the kiiras.txt requirement for webhook-based alerting.
