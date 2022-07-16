#!/bin/bash

set -e

PATH="$PWD/compiler/bin:$PATH"

WORKDIR="$PWD"
SDLDIR="./SDL/src/video/"

[ -e "./SDL" ] || git clone https://github.com/libsdl-org/SDL

pushd $SDLDIR
git apply "$WORKDIR/sdl2.patch" || echo "error or already applied"
clang -m32 -Ofast -c -o stretch.o SDL_stretch.c -I ../../include
clang -m32 -Ofast -shared -v -o stretch.dll stretch.o
popd

cp $SDLDIR/stretch.dll ./