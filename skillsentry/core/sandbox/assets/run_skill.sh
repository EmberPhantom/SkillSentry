#!/bin/sh
# Minimal skill entrypoint used when the package does not declare one.
# The runner uploads this file into the container's writable /tmp tmpfs.
set -u
umask 077
export HOME="${HOME:-/home/sandbox}"
cd /skill || exit 1

if [ -x ./scripts/run.sh ]; then
    exec ./scripts/run.sh "$@"
fi
if [ -x ./run.sh ]; then
    exec ./run.sh "$@"
fi
if [ -f ./scripts/run.py ]; then
    exec python ./scripts/run.py "$@"
fi
if [ -f ./main.py ]; then
    exec python ./main.py "$@"
fi
# A package with only a SKILL.md is a valid, inert skill.
exit 0
