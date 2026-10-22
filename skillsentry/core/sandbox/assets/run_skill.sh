#!/bin/sh
# Skill entrypoint used when the package does not supply an explicit command.
# The runner uploads this file into the container's writable /tmp tmpfs.
set -u
umask 077
export HOME="${HOME:-/home/sandbox}"
cd /skill || exit 1

# A declared entrypoint is authoritative.  Never fall through to a different
# script (or exit 0) when the manifest asked for something that is missing.
if [ -n "${SKILLSENTRY_ENTRYPOINT:-}" ]; then
    if [ ! -f "$SKILLSENTRY_ENTRYPOINT" ]; then
        echo "skillsentry: declared entrypoint not found: $SKILLSENTRY_ENTRYPOINT" >&2
        exit 127
    fi
    # Args are deliberately word-split here: the manifest is untrusted and the
    # sandbox is the execution boundary.  The engine prefers an explicit argv
    # and only uses this path for compatibility.
    # shellcheck disable=SC2086
    exec "$SKILLSENTRY_ENTRYPOINT" ${SKILLSENTRY_ENTRYPOINT_ARGS:-}
fi

if [ "${SKILLSENTRY_DECLARED_ENTRYPOINT:-0}" = "1" ]; then
    echo "skillsentry: manifest declared an entrypoint but no command was supplied" >&2
    exit 127
fi

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
