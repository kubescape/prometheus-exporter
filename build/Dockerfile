FROM --platform=$BUILDPLATFORM golang:1.20-alpine as builder

ENV GO111MODULE=on \
    CGO_ENABLED=0

# Set the working directory inside the container
WORKDIR /work

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/kubescape-exporter .

FROM gcr.io/distroless/static-debian11:nonroot

COPY --from=builder /out/kubescape-exporter /usr/bin/kubescape-exporter

# Entry Point
ENTRYPOINT [ "kubescape-exporter" ]