# syntax=docker/dockerfile:1

# The build stage always runs on the builder's own architecture and
# cross-compiles, so no emulation is needed for the other platform.
FROM --platform=$BUILDPLATFORM golang:1.26.8 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /out/betterleaks-server .

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/betterleaks-server /usr/local/bin/betterleaks-server

# Inside a container the loopback default would be unreachable from outside.
# Requests are still only accepted for localhost / loopback Host headers
# unless -allowed-hosts is given.
ENV BETTERLEAKS_SERVER_ADDR=0.0.0.0:8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/betterleaks-server"]
