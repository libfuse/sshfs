#!/bin/bash

machine=$(uname -m)
mkdir build-$machine
cd build-$machine
meson ..
ninja
