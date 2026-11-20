# Gateway design

The gateway is an optional, self-hosted companion to the ProxCommander app. It lets the app (iOS, Android and the hosted web build) manage a Proxmox VE cluster without exposing port 8006 to the internet. Users who already reach their cluster another way (VPN, their own reverse proxy) can keep connecting directly and skip it.

## Why it exists

- pveproxy sends no CORS headers and answers the browser's OPTIONS preflight with 501, so the web build can't call it from another origin.
- Exposing 8006 exposes the login endpoint and the whole API. pveproxy's only brute-force defence is a 3-second delay on failed logins.
- A plain CORS reverse proxy fixes the browser but still exposes everything. The gateway is an authenticated broker instead: paired devices only, an allow-list of API calls, and the Proxmox ticket never leaves the gateway.

## Where it runs

One static Go binary, shipped three ways:

| Packaging | For |
|---|---|
| LXC container on the cluster, created by a one-line installer | Most Proxmox users (recommended) |
| OCI image + `docker-compose.yml` with a `cloudflared` sidecar | Anyone already running Docker |
| Binary + systemd unit | Any Linux machine |

It runs anywhere that can reach the Proxmox nodes on 8006. It is never installed on a Proxmox host itself.

## How a request flows

```
app ──HTTPS──▶ Cloudflare Tunnel / LAN / user's proxy ──▶ gateway :8080 ──HTTPS (pinned)──▶ pveproxy :8006
```

1. **Setup.** The admin adds the cluster's nodes. The gateway fetches each node's certificate and shows the fingerprint; once confirmed, the cluster CA (or leaf) is pinned and any other certificate is a hard failure. There is no "ignore TLS errors" switch.
2. **Pairing.** The admin creates a one-time pairing code (shown as text and a QR code). The app generates an Ed25519 key on the device (native: stored in the keychain; web: a non-extractable WebCrypto key) and registers its public key with the code. Devices can be listed and revoked; revoking a device ends its sessions and closes its open console streams.
3. **Sign-in.** The app sends a Proxmox username and password once, signed with its device key. The gateway calls `POST /access/ticket`, keeps the ticket and CSRF token in memory, renews the ticket every 15 minutes (it lives 2 hours), and returns a gateway session token. Passwords are never stored. The Proxmox ticket never reaches the app.
4. **API calls.** The app calls `/api2/json/...` on the gateway with `Authorization: PCGateway <session>`. The gateway checks the session and device, checks the call against the device's profile, strips any client `Authorization`/`Cookie`, adds `Authorization: PVEAuthCookie=<ticket>` (and `CSRFPreventionToken` on writes), forwards to the first reachable node, and streams the response back with CORS headers for the allowed app origins. Reads may fail over to the next node; writes never retry on another node after a timeout.
5. **Consoles.** The app requests `vncproxy`/`termproxy` through the gateway, then opens a WebSocket to the gateway, which upgrades to the node's `vncwebsocket` with the ticket and pipes frames both ways.

## Gateway API

| Route | Auth | Purpose |
|---|---|---|
| `GET /gateway/v1/info` | none | Name, version, whether pairing is open |
| `POST /gateway/v1/pair` | pairing code | Register a device public key |
| `POST /gateway/v1/login` | device signature | Sign in to Proxmox, get a gateway session |
| `POST /gateway/v1/logout` | session | End the session and drop its ticket |
| `/api2/json/*` | session | Proxied Proxmox API, filtered by the allow-list |
| `GET /healthz` | none | Liveness for Docker/systemd |

## Policy

- Default deny. Two built-in profiles: **read-only** (GETs of cluster, node, guest, storage and task status) and **operator** (read-only plus guest power actions, consoles and task logs).
- Root-equivalent endpoints (node shell, `/access` user and ACL management, storage and network config writes, `apt`, `ceph` writes) stay blocked unless an admin adds them explicitly.
- Paths are normalised before matching; encoded dot segments and anything outside `/api2/json/` are rejected.

## Transport and certificates

- **Cloudflare Tunnel (built in).** Given a tunnel token, the gateway starts and supervises `cloudflared tunnel run`, pointed at its own `127.0.0.1:8080`. The LXC and Docker packages include `cloudflared`. Cloudflare decrypts traffic at its edge; device pairing and the allow-list still apply.
- **LAN or the user's own reverse proxy.** The gateway listens on plain HTTP for a proxy in front of it, or serves HTTPS with its own self-signed key, whose fingerprint travels in the pairing QR code so native apps can pin it. Browsers need a publicly trusted certificate, so the web build uses the tunnel or the user's proxy.
- Host and Origin headers are checked to block DNS rebinding. Upstream targets are fixed by configuration, never taken from the request.

## Safety rails

- Rate limits per IP and per device; login lockout after repeated failures.
- An append-only JSON-lines audit log: who, which device, method, path, status, duration. Never secrets, tickets or request bodies.
- Runs as a non-root user; state in one `0600` file under `/var/lib/proxcommander-gateway`; distroless image; signed releases.

## Administration

The MVP is administered by CLI subcommands (`nodes add`, `pair`, `devices`, `devices revoke`, `tunnel set`), run with `pct exec` or `docker exec`. A web setup page comes later.

## Not in scope yet

Embedded Tailscale, a vendor-run relay, SPICE consoles, fronting several clusters from one gateway, self-update.

## Open questions to settle on live PVE 8.4 and 9.x

- Can API tokens open consoles yet? The docs say no; if that changes, the gateway could hold a least-privilege token instead of user tickets for REST calls.
- Does a gateway-injected ticket work on the console WebSocket upgrade exactly as it does for REST?

## Build order

1. Scaffold: config and state file, pinned upstream pool with failover, allow-list, reverse proxy, CORS, `/healthz`, audit log, Dockerfile, CI.
2. Pairing, device keys, gateway sessions, ticket holding and renewal.
3. Console WebSocket passthrough.
4. Cloudflare Tunnel supervision and compose file.
5. LXC installer and systemd unit; signed releases.
6. App side: a "via gateway" connection type with pairing.
