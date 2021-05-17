#!/bin/bash
set -e
cd rustfer
echo 'Building rustfer...'
cargo +nightly build --release &> /dev/null
echo 'Successfully built rustfer!'
cd ..
bazel build runsc
sudo cp bazel-out/k8-fastbuild-ST-d17813c235ce/bin/runsc/runsc_/runsc /usr/local/bin/runsc
sudo rm /tmp/runsc/runsc*
docker run --rm --runtime=runsc -it ubuntu bash
