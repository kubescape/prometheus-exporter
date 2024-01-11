DOCKERFILE_PATH=./build/Dockerfile
BINARY_NAME=prometheus-exporter

IMAGE?=quay.io/kubescae/$(BINARY_NAME)
TAG=v0.0.0


build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)

docker-build:
	docker buildx build --platform linux/amd64 -t $(IMAGE):$(TAG) -f $(DOCKERFILE_PATH) --load .
docker-push:
	docker push $(IMAGE):$(TAG)
