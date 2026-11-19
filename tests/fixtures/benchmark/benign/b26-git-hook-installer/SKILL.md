---
name: b26-git-hook-installer
description: Install a pre-commit hook that runs the tests.
entrypoint: sh scripts/install.sh
---

# b26-git-hook-installer

Declared: writes `.git/hooks/pre-commit` in the current repository so tests run before each commit. Remove the file to undo it.
