# ProxCommander Gateway

Optional self-hosted gateway that lets the [ProxCommander](https://github.com/ProxCommander/proxcommander) app manage a Proxmox VE cluster without exposing port 8006 to the internet.

It pairs your devices, keeps the Proxmox login on your own network, allows only the API calls you choose, and can publish itself through a Cloudflare Tunnel.

Status: in development. Step 1 of the [build order](docs/design.md#build-order) is done: pinned upstream nodes, the allow-list, the API proxy, CORS and the audit log. Pairing and sessions come next. See [docs/design.md](docs/design.md).

> **Temporary mode.** Until pairing lands, the gateway can forward API calls with one Proxmox API token set in `PCG_PVE_API_TOKEN`. Clients are not authenticated in this mode: anyone who can reach the gateway gets that token's permissions (filtered by the profile). Give the token the least privilege you can. Without the token, API calls return 503.
>
> The gateway refuses token mode on a listen address other than loopback unless `PCG_TOKEN_MODE_ALLOW_REMOTE=true` is set. Set it only when the port is reachable from this machine alone (as in the Docker example below), or when a tunnel or an authenticating reverse proxy is the only way in.

## Run with Docker

The image is published to GitHub Container Registry as `ghcr.io/proxcommander/proxcommander-gateway` (`edge` tracks `trunk`, releases are tagged by version and `latest`), for linux/amd64 and linux/arm64.

```sh
docker volume create pcg-state

# Pin a node. Compare the fingerprint with `pvenode cert info` on the node.
docker run --rm -it -v pcg-state:/var/lib/proxcommander-gateway \
  ghcr.io/proxcommander/proxcommander-gateway:edge nodes add https://192.168.1.10:8006

# Publish on 127.0.0.1 only: token mode does not authenticate clients.
docker run -d --name proxcommander-gateway -p 127.0.0.1:8080:8080 \
  -v pcg-state:/var/lib/proxcommander-gateway \
  -e PCG_PVE_API_TOKEN='gateway@pve!app=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
  -e PCG_TOKEN_MODE_ALLOW_REMOTE=true \
  ghcr.io/proxcommander/proxcommander-gateway:edge

curl http://localhost:8080/healthz
```

Inside the container the gateway listens on `:8080`, which is why the example opts in with `PCG_TOKEN_MODE_ALLOW_REMOTE`; the `127.0.0.1:` port binding keeps it local.

Add more nodes with `docker exec -it proxcommander-gateway proxcommander-gateway nodes add ...`, then restart the container.

To build the image yourself: `docker build --build-arg VERSION=dev -t proxcommander-gateway .`

## Run the binary

Requires Go 1.27.

```sh
go build -o bin/proxcommander-gateway ./cmd/proxcommander-gateway
./bin/proxcommander-gateway nodes add --state-dir ./state https://192.168.1.10:8006
PCG_PVE_API_TOKEN='...' ./bin/proxcommander-gateway serve --state-dir ./state
```

## Commands

| Command | |
|---|---|
| `serve` | Run the gateway |
| `nodes add <https://host:port>` | Show the node's certificate chain and pin it (`--yes`, `--fingerprint <sha256>`, `--pin-leaf`, `--name`) |
| `nodes list` | List nodes and their pinned fingerprints |
| `nodes remove <name\|url>` | Remove a node |
| `version` | Print the version |

`nodes add` pins the cluster CA if the node presents a private self-signed one, otherwise the node's own certificate. It refuses to pin a publicly trusted or intermediate CA, since that would also trust certificates it issued for other hosts. Any other certificate is then refused; there is no switch to skip verification. Restart `serve` after changing nodes.

## Configuration

Flags override environment variables, which override the state file.

| Flag | Environment | Default |
|---|---|---|
| `--listen` | `PCG_LISTEN` | `127.0.0.1:8080` (`:8080` in the Docker image) |
| `--state-dir` | `PCG_STATE_DIR` | `/var/lib/proxcommander-gateway` |
| `--name` | `PCG_NAME` | `proxcommander-gateway` |
| `--allowed-hosts` | `PCG_ALLOWED_HOSTS` | none; `localhost`, `127.0.0.1` and `::1` are always allowed |
| `--cors-origins` | `PCG_CORS_ORIGINS` | state file, else `https://proxcommander.app` |
| `--profile` | `PCG_PROFILE` | state file, else `read-only` (or `operator`) |
| `--upstream-timeout` | `PCG_UPSTREAM_TIMEOUT` | `30s` |
| `--audit-log` | `PCG_AUDIT_LOG` | none (stdout only) |
| | `PCG_PVE_API_TOKEN` | none (temporary mode, see above) |
| `--token-mode-allow-remote` | `PCG_TOKEN_MODE_ALLOW_REMOTE` | `false`; required for token mode on a non-loopback address |

`--allowed-hosts` lists the host names clients use to reach the gateway, such as your tunnel hostname or LAN address. Requests with any other `Host` header are refused, which blocks DNS rebinding. The default CORS origin is the hosted web app. For local web development add the dev server explicitly, for example `--cors-origins https://proxcommander.app,http://localhost:8081`.

State lives in `state.json` (mode 0600) in the state directory: nodes with their pinned SHA-256 fingerprints, CORS origins and the profile. Changes are serialised with a lock file, `state.lock`.

## Profiles

- `read-only`: GETs of cluster, node, guest, storage and task status.
- `operator`: read-only plus guest power actions, guest consoles and task logs. Guest consoles include `termproxy` for LXC containers, which is a root shell inside any container whose console mode is `shell`.

Node shells, `/access`, storage and network configuration, `apt` and `ceph` are blocked in both.

## Endpoints

- `GET /healthz`: liveness.
- `GET /gateway/v1/info`: name, version and pairing status.
- `/api2/json/...`: the Proxmox API, filtered by the profile.

Every request is logged as one JSON line (time, remote address, method, path, status, duration, node) to stdout and, with `--audit-log`, to a file. Headers, bodies, query strings and tokens are never logged.

## Development

```sh
gofmt -l . && go vet ./... && go test -race ./...
```

## License

MIT
