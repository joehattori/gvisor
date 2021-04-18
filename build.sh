#!/bin/bash
set -eu

sudo rm -f /usr/local/bin/runsc
CGO_ENABLED=1 GO111MODULE=on go build -o tmp gvisor.dev/gvisor/runsc/
sudo mv tmp /usr/local/bin/runsc
