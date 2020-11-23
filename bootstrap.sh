#!/bin/sh

mkdir -p m4
autoreconf --verbose --install --force
git submodule update --init include/cryptoki

