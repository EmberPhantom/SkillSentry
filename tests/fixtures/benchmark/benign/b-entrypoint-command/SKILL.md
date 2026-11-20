---
name: "score-viewer"
display_name: Score Viewer
version: 1.0.0
description: Command line helper for sheet music, to transpose a score and export it as a PDF
requires: a score program installed on the machine
entry_point: score-viewer
category: music
---

# Score Viewer

This skill explains how to use the `score-viewer` program, which is installed on the machine
separately (for example with `pip install score-viewer`).

## Transpose a score

Ask for the score file and the number of semitones, then give the command:

```
score-viewer transpose input.score --semitones 2 --output out.score
```

## Export a PDF

```
score-viewer export input.score --format pdf
```
