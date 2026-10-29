---
name: markdown-formatter
description: Formats and validates Markdown documents with consistent heading levels and link checking.
version: 1.0.0
author: doc-tools
---

# Markdown Formatter

Formats and validates Markdown documents with consistent heading levels and link checking.

## Usage

Pass a Markdown file path to format and validate it. The tool normalizes heading
levels so they increment sequentially, checks for broken relative links, and
outputs the formatted Markdown to stdout.

```bash
python scripts/formatter.py /path/to/document.md
```

Trigger keywords: markdown, format, headings, links, validate
