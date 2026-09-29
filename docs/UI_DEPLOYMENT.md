# FAST UI and Tailscale Deployment

This guide describes the final UI deployment model on `main`.

## 1. Start FAST

```bash
./bin/fast up
./bin/fast status
```

Local endpoints:

```text
FAST UI:         http://127.0.0.1:5000
Wazuh Dashboard: https://127.0.0.1:5601
```

The Wazuh Dashboard host mapping stays on localhost. This avoids a port-443 collision with Tailscale Funnel.

## 2. Share with Tailscale

```bash
./bin/fast-share on
```

The helper checks both local backends before changing Tailscale configuration.

Result:

```text
Internet
  |
  | Tailscale Funnel HTTPS 443
  v
https://<node>.<tailnet>.ts.net
  |
  v
127.0.0.1:5000  FAST UI

Tailnet devices only
  |
  | Tailscale Serve HTTPS 8443
  v
https://<node>.<tailnet>.ts.net:8443
  |
  v
127.0.0.1:5601  Wazuh Dashboard
```

This split is intentional: the presentation/security-operations UI can be shared independently, while Wazuh administration remains tailnet-only.

## 3. Open Wazuh button behavior

FAST derives the Wazuh Dashboard URL as follows:

- local FAST UI -> `https://localhost:5601`;
- FAST UI opened through a `*.ts.net` hostname -> same hostname on port `8443`;
- explicit `FAST_WAZUH_DASHBOARD_URL` -> use the configured value.

## 4. Sharing controls

```bash
./bin/fast-share status
./bin/fast-share off
./bin/fast-share on
```

The helper changes only FAST's 443 Funnel and 8443 Serve mappings; it does not intentionally reset unrelated Tailscale routes.

## 5. Required local settings

Keep:

```env
FAST_WEB_BIND=127.0.0.1
FAST_WAZUH_DASHBOARD_LOCAL_PORT=5601
```

when using `fast-share`.

Optional metadata:

```env
FAST_PUBLIC_URL=
FAST_DEPLOYMENT_MODE=local
FAST_WAZUH_DASHBOARD_URL=
```

## 6. Authentication before public sharing

FAST authentication is disabled by default for local/demo compatibility.

Before using Funnel for anything beyond a controlled demo, enable authentication:

```env
FAST_AUTH_ENABLED=1
FAST_SESSION_SECRET=<long-random-secret>
FAST_ADMIN_USER=admin
FAST_ADMIN_PASSWORD=<strong-password>
FAST_SESSION_COOKIE_SECURE=1
```

Additional Viewer/Analyst users can be configured with `FAST_USERS_JSON`.

A public Funnel URL with `FAST_AUTH_ENABLED=0` should be treated as a demo-only exposure.

## 7. Security boundary

The FAST web container:

- does not receive the Docker socket;
- does not execute deployment commands;
- queries Wazuh through its API/Indexer interfaces;
- stores analyst metadata separately from Wazuh alerts.

Privileged lifecycle operations remain terminal-controlled through `./bin/fast`.

## 8. Old preview cleanup

Older development builds may have used `fast-ui-preview` on port 5001. It is not part of the current deployment model.

Optional one-time cleanup:

```bash
docker rm -f fast-ui-preview 2>/dev/null || true
```

## 9. Common failures

### FAST UI not healthy

```bash
curl http://127.0.0.1:5000/api/health
docker ps --filter name=fast-ioc-collector-web
```

### Wazuh local dashboard not reachable

```bash
curl -k https://127.0.0.1:5601/
```

### Funnel/Serve fails

Check:

```bash
tailscale status
tailscale funnel status
tailscale serve status
```

Tailscale Funnel requires the relevant tailnet HTTPS/Funnel permissions.

**Last reviewed:** 2026-09-29
