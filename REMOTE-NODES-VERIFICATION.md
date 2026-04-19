# Remote Node Management — End-to-End Verification

Verification steps for the remote-node management feature. Run against a fresh deploy of the central T-Pot stack.

## Architecture (one-line refresher)

Remote Linux nodes run a Python agent that polls the central mgmt-ui over outbound HTTPS/443 only. Commands are queued in SQLite on the central host and delivered inline in heartbeat responses. Attack events from remote nodes are bulk-indexed into the existing T-Pot `logstash-YYYY.MM.DD` index so the attack map picks them up unchanged.

Agent API paths (bypass oauth2-proxy OIDC, authenticate via bearer token):

- `/api/v1/agent/enrol`
- `/api/v1/agent/heartbeat`
- `/api/v1/agent/events`
- `/api/v1/agent/bootstrap/{enrolment_token}`
- `/api/v1/agent/artefacts/{name}`

## Prerequisites

- Central T-Pot stack deployed via Terraform + GitLab CI with the changes on this branch.
- A separate Linux test host (Ubuntu 22.04, RHEL-family, or SUSE) with:
  - Root / sudo access
  - Outbound HTTPS/443 to the T-Pot ALB
  - No inbound ports required from the central host

## Steps

### 1. Post-deploy sanity

After `terraform apply`:

```bash
# On the central host
systemctl status honeypot-mgmt       # should be active (running)
test -d /var/lib/honeypot-mgmt        # state dir exists
test -f /opt/honeypot-mgmt/agent-bundle/agent.tar.gz  # agent bundle staged

# oauth2-proxy config syntax
oauth2-proxy --config /etc/oauth2-proxy/oauth2-proxy.cfg --validate-only

# nginx config syntax
nginx -t
```

Hit the agent endpoint with no credentials (from your workstation):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://<TPOT_FQDN>/api/v1/agent/heartbeat
# expect: 401  (not 302 — proves skip_auth_routes is effective)
```

### 2. Existing `/manage` still works

Log into `https://<TPOT_FQDN>/manage` with OIDC. Confirm the existing dashboard, Beelzebub, Ollama, and Red Team pages still work. The new **Nodes** nav link should appear.

### 3. Generate an enrollment token

In `/manage/nodes` click **Add Node**, enter a label (e.g. `edge-test-1`), submit. The page re-renders with a copy-paste one-liner:

```
curl -fsSL https://<TPOT_FQDN>/api/v1/agent/bootstrap/<token> | sudo bash
```

### 4. Onboard the remote node

SSH into the remote test host. Paste and run the one-liner as root. Expect:

- Distro detected; Python 3 + curl + Docker installed (if missing)
- Agent unpacked to `/opt/honeypot-agent`
- Config written to `/etc/honeypot-agent/config.yaml`
- `honeypot-agent.service` started; `systemctl status honeypot-agent` shows **active (running)**
- First `journalctl -u honeypot-agent` entries show successful enrol + first heartbeat

Within 60s, the node appears in `/manage/nodes` with an **online** badge and a ticking `last_seen`.

### 5. Deploy Beelzebub remotely

In the node detail page (`/manage/nodes/{id}`) click **Deploy Beelzebub**. Within two heartbeats (~60s):

- Command history shows `install_beelzebub` with `ack_status=ok`
- On the remote host: `docker ps` shows the `beelzebub` container running
- Ports `2222` (SSH) and `8888` (HTTP) are listening on the remote host

### 6. Attack-map integration

From a third host (or your workstation), trigger an attack:

```bash
ssh -p 2222 fake@<remote_node_public_ip>   # enter any password
# or:
curl http://<remote_node_public_ip>:8888/
```

Within 60s, the attack appears on the T-Pot attack map at `https://<TPOT_FQDN>/` with:

- Correct source country (GeoIP enrichment)
- `t-pot_hostname: <node_label>` field visible in Kibana's `logstash-*` index
- `type: beelzebub` and `t-pot_source: remote-agent`

### 7. Degraded / offline behaviour

On the central host:

```bash
systemctl stop honeypot-mgmt
```

Wait >5 minutes. On the remote host, confirm Beelzebub is still running (`docker ps`). Restart central:

```bash
systemctl start honeypot-mgmt
```

The node should show as **offline**, transitioning to **online** within 90s of the mgmt-ui coming back.

### 8. Token revocation

Click **Revoke** on the node in `/manage/nodes`. Within 30s:

- Agent log shows `token revoked by central; shutting down`
- Beelzebub container is stopped on the remote host
- `honeypot-agent.service` is inactive
- Node shows **revoked** in the UI

### 9. Replay protection

Try replaying a used enrollment token:

```bash
# Re-run the original one-liner on a second host
curl -fsSL https://<TPOT_FQDN>/api/v1/agent/bootstrap/<same_token> | sudo bash
```

Expect HTTP **409 Conflict** (already used). Try with an expired token (>15 min old): expect **410 Gone**. Try with a malformed token: expect **400 Bad Request**.

### 10. Idempotency

While a remote node is online, simulate duplicate command delivery by restarting the agent mid-execution:

```bash
# On the remote host, after queuing a ping:
systemctl restart honeypot-agent
```

The agent should re-read its `seen-commands.json` cache and re-ack the already-executed command with the cached result, not re-execute it. Confirm in the command history that `ack_at` is set exactly once and `ack_status=ok`.

## Troubleshooting pointers

| Symptom | Likely cause | Check |
|---|---|---|
| Bootstrap one-liner returns 302 to Entra | `skip_auth_routes` not loaded | `grep skip_auth /etc/oauth2-proxy/oauth2-proxy.cfg`, restart `oauth2-proxy` |
| Agent heartbeat 401 | Token mismatch or revoked | `sqlite3 /var/lib/honeypot-mgmt/state.db "select label,revoked_at from nodes"` |
| Events not in attack map | Wrong ES index or missing GeoIP DB | `journalctl -u honeypot-mgmt` — look for `ES bulk` lines; `ls /data/elk/logstash/GeoLite2-City.mmdb` |
| Agent fails to start docker | User not in docker group | `id honeyagent` should show `docker` group |
| `nginx -t` fails | `location /api/v1/agent` typo | `/etc/nginx/sites-available/tpot-upstream.conf` |
