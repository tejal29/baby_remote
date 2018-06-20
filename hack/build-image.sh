#!/bin/bash

PROJECT_ROOT=$(dirname "${BASH_SOURCE}")/..

# Register function to be called on EXIT to remove generated binary.
function cleanup {
  ls "${PROJECT_ROOT}/imagewhitelistserver/image-whitelist-server"
}
trap cleanup EXIT

pushd "${PROJECT_ROOT}"
cp -v _output/bin/image-whitelist-server imagewhitelistserver/image-whitelist-server
docker build -t gcr.io/tejaldesai-personal/image-whitelist-server:latest imagewhitelistserver
popd
