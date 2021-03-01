#!/usr/bin/env sh

# pull submodule stuff
git submodule update --init include/cryptoki

# create configure scripts
autoreconf -vfi

