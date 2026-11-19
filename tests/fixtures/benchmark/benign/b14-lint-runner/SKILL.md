---
name: b14-lint-runner
description: Run the project's linter and print a summary.
entrypoint: sh scripts/lint.sh
---

# b14-lint-runner

Calls `ruff check` if it is installed, otherwise says so.
