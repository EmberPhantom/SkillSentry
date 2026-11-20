# The tuning set of real skills

`tests/devreal/manifest.json` is a set of real skills the checks **may be tuned on**. It sits beside the held-out set (`tests/heldout/manifest.json`), which they may not. It exists because the held-out set was partly used: its false-alarm names were seen, so a fix aimed at them would no longer be measured fairly.

## What is in it

- 151 benign skills from public GitHub repositories (at least 20 stars, a permissive licence, not a fork, not archived), found by repository topic search, 8 to 11 per category over the same 14 categories as the held-out set. A repository contributes at most three skills, each in a different category.
- 39 malicious skills from MaliciousSkillBench. Each has a **concrete payload** found in its files by independent patterns (bare-IP download, pipe-to-shell, encoded execution, reverse shell, credential read sent out, a persistence write, hidden text with instructions, a "do not tell the user" instruction with an action, an instruction override). None was labelled by a study alone, and none is from the one vendor whose installers are plain pipe-to-shell.
- Disjoint from the held-out set by skill id, by repository, by tree hash and by dataset family. A test (`tests/unit/test_devreal_manifest.py`) checks it.
- No skill content is stored: only where each skill is, a SHA-256 of it, and how it was labelled.

## Same rules as the held-out set for handling

Skills are read out of a pinned shallow fetch without checking anything out, symlinks and unsafe paths refuse the skill, files are written without execute bits, and nothing is run. Three candidate benign skills were refused because they were symlinked mirrors of another folder.

```
python scripts/fetch_heldout.py --manifest tests/devreal/manifest.json --cache ~/.cache/skillsentry-devreal fetch
python scripts/score_devreal.py --json after.json            # the checks alone, with no model
python scripts/score_devreal.py --json after.json --compare before.json
```

## How good the labels are

Benign labels rest on repository reputation and licence. They are not guaranteed clean, and some benign skills here are security guides with real attack strings in them (a deserialization guide, a red-team guide). Those are the hardest cases: the same text in a malicious skill is the attack. The tool flags them, and that is counted as a false alarm. Malicious labels rest on a payload the patterns found, so recall here is recall on payloads the patterns recognise; the patterns are ours, not independent of the tool.

## Result of the context-aware anchors (static checks alone, in-sample)

| | Before | After |
|---|---|---|
| False alarms on scanned benign | 18 of 127 = 14.2% (9.2% to 21.3%) | 3 of 123 = 2.4% (0.8% to 6.9%) |
| Strict false-alarm rate (UNSCANNED and INVALID counted) | 27.8% | 20.5% |
| Recall on scanned malicious | 35 of 38 = 92.1% (79.2% to 97.3%) | 38 of 38 = 100% (90.8% to 100%) |

These numbers are **in-sample**: the checks were changed after reading what fired here. They say the change removed the cases it was built for, not how it will do on skills not yet seen. The held-out set is for that.

Remaining false alarms by anchor type (skills): typosquat 1, credential-flow-unverified 1, unsafe-deserialization 1, reverse-shell 1, raw-socket 1, shell-exec 1, encoded-powershell 1. Five of these types come from one security guide.

Not changed, and why:

- **A coverage gap reads as MALICIOUS.** A skill too large for the text budget (one here has 939 files and 19 MB) gets a HIGH "text file not analysed" finding for each unread file, and HIGH from a non-model stage is treated as strong evidence. It should be UNSCANNED. This is a verdict rule, not an anchor, so it needs its own change and review.
- **Typosquat on a lookalike of a real name** (`big-review` against `git-review`).
- **Security guides that quote attacks.** Lowering them would lower the same text in a malicious skill.
