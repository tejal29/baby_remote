all: build
.PHONY: all

REPO ?=

build:
	go build -o _output/bin/image-whitelist-server github.com/tejal29/baby_remote/imagewhitelistserver
.PHONY: build

build-image:
	GOOS=linux go build -o _output/bin/image-whitelist-server github.com/tejal29/baby_remote/imagewhitelistserver
	hack/build-image.sh
.PHONY: build-image

push-image:
	docker push gcr.io/tejaldesai-personal/image-whitelist-server:latest

clean:
	rm -rf _output
.PHONY: clean
