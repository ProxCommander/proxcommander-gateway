# Working in this repo

## Build and test

Go is used through Docker; a local Go install is not needed.

```sh
docker run --rm -v "$PWD":/src -w /src \
  -v pcg-gomod:/go/pkg/mod -v pcg-gocache:/root/.cache/go-build \
  golang:1.27 sh -c 'test -z "$(gofmt -l .)" && go vet ./... && go test -race ./...'

docker build --build-arg VERSION=dev -t proxcommander-gateway .
```

CI runs the same checks on every pull request.

## Commits and pull requests

- Conventional Commits with a required scope: `type(scope): summary`, for example `feat(proxy): ...` or `ci(actions): ...`. PR titles use the same format.
- Branch from `trunk`; pull requests are squash-merged into `trunk`.
- Fix history forward with new commits; do not force-push shared branches.
- No AI attribution anywhere: no co-author trailers, "generated with" lines, or mentions in commits, PRs, code, comments or docs.

## Naming other products

Never name competing apps, products or companies anywhere in the repo: code, comments, docs, commits, PRs, issues and release notes. Describe other tools generically ("a mobile Proxmox client", "a hosted relay"). Keep any research that names them outside the repo.

Proxmox's own products may be named where we integrate with them. Platforms we build on (Cloudflare, Tailscale, Docker, GitHub) are fine to name.
