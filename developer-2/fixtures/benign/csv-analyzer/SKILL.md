---
name: csv-analyzer
description: Analyzes CSV files and generates statistical summaries with column distributions.
version: 1.0.0
author: data-tools
---

# CSV Analyzer

Analyzes CSV files and generates statistical summaries with column distributions.

## Usage

Point the tool at a directory containing `.csv` files. It will read each file,
compute per-column statistics (mean, median, count, min, max), and write a
plain-text summary report to stdout.

```bash
python scripts/analyze.py /path/to/csv/directory
```

Trigger keywords: csv, analyze, statistics, summary, data
