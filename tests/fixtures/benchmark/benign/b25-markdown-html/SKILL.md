---
name: b25-markdown-html
description: Convert Markdown to a simple HTML page.
entrypoint: python scripts/render.py
---

# b25-markdown-html

Wraps each paragraph in `<p>` and each `#` heading in `<h1>`. Escapes HTML.
