#!/bin/bash

set -e

# Disable leak checking for now, there are some issues (or false positives)
# that we still need to fix
export ASAN_OPTIONS="detect_leaks=0"

export LSAN_OPTIONS="suppressions=${PWD}/test/lsan_suppress.txt"

TEST_CMD="python3 -m pytest --maxfail=99 test/"

build_opts='-D werror=true'

if [ -n "$SANITIZER" ]; then
    build_type=$SANITIZER
    build_opts="${build_opts} -D b_sanitize=${SANITIZER}"
else
    build_type=$CC
    export TEST_WITH_VALGRIND=true
fi

# b_lundef=false is required to work around clang
# bug, cf. https://groups.google.com/forum/#!topic/mesonbuild/tgEdAXIIdC4
if [[ "${CC}" == 'gcc-6'  || "${CC}" =~ "clang" ]]; then
    build_opts="${build_opts} -D b_lundef=false"
fi

# Standard build with Valgrind
mkdir "build-${build_type}"
cd "build-${build_type}"
#shellcheck disable=SC2086
meson ${build_opts} ..
ninja

${TEST_CMD}
sudo ninja install
