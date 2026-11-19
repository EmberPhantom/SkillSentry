---
name: b29-cargo-helper
description: Run cargo check and show only the errors.
entrypoint: sh scripts/check.sh
---

# b29-cargo-helper

Calls `cargo check --message-format short` and prints lines that contain `error`.
