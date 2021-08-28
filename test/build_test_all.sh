#!/bin/bash
set -e

CC=gcc test/travis-build.sh
CC=clang test/travis-build.sh
CC=clang SANITIZER=undefined test/travis-build.sh
CC=clang SANITIZER=address test/travis-build.sh
