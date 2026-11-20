# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.4 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/ProxCommander/proxcommander-gateway/internal/version.Version=${VERSION}" \
      -o /out/proxcommander-gateway ./cmd/proxcommander-gateway \
 && mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="ProxCommander Gateway" \
      org.opencontainers.image.description="Self-hosted gateway between the ProxCommander app and a Proxmox VE cluster" \
      org.opencontainers.image.source="https://github.com/ProxCommander/proxcommander-gateway" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/proxcommander-gateway /usr/local/bin/proxcommander-gateway
COPY --from=build --chown=65532:65532 --chmod=0700 /out/state /var/lib/proxcommander-gateway
ENV PCG_LISTEN=:8080
EXPOSE 8080
VOLUME ["/var/lib/proxcommander-gateway"]
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/proxcommander-gateway"]
CMD ["serve"]
