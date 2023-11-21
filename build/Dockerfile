FROM --platform=$BUILDPLATFORM golang:1.20-alpine as builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOPROXY=https://proxy.golang.org,direct

# Set the working directory inside the container
WORKDIR /work

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/prometheus-exporter .

FROM gcr.io/distroless/static-debian11:nonroot

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /out/prometheus-exporter /usr/bin/prometheus-exporter

# Entry Point
ENTRYPOINT [ "prometheus-exporter" ]