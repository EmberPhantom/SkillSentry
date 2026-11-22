# The second tuning set (devreal3)

`tests/devreal3/manifest.json` holds the skills of the third held-out set (`tests/heldout3`) after it was measured once for the final measurement. Their false alarms and misses were seen, so the checks may now be tuned on them, and they can no longer be used for a held-out claim. `tests/heldout3/manifest.json` stays as the sealed record (it records where the skills went); a claim about the tuned checks needs a fresh held-out set.

- 243 benign skills, 67 payload-confirmed malicious skills, 29 confirmed by someone else (reported apart), 31 ambiguous (not scored), and 45 reserve skills. See `docs/operations/heldout3-set.md` for how they were chosen.
- Fetch it into the same cache the third set used: `python scripts/fetch_heldout.py fetch --manifest tests/devreal3/manifest.json --cache ~/.cache/skillsentry-heldout3 --set all`.
- Score it with the checks alone: `python scripts/score_devreal.py --manifest tests/devreal3/manifest.json --cache ~/.cache/skillsentry-heldout3 --json after.json`. Recall is on the payload-confirmed skills; the confirmed-by-others group is printed apart, because an instruction with no string to find cannot be found by a static check.

## What the third set taught the checks (in-sample)

Static checks alone, scored with `scripts/score_devreal.py`:

| | Before | After |
|:---|:--|:--|
| False alarms on benign skills that finished (devreal3) | 39 of 191 = 20.4% (15.3% to 26.7%) | 29 of 203 = 14.3% (10.1% to 19.8%) |
| Strict (not finished counted as flagged) | 37.4% | 28.4% |
| Benign skills that were INVALID SKILL | 17 | 5 |
| Recall on payload-confirmed (devreal3) | 64 of 67 | 64 of 67 |
| Recall on confirmed by others, apart | 12 of 27 | 12 of 27 |
| False alarms on the first tuning set (devreal) | 11 of 141 = 7.8% | 8 of 143 = 5.6% |

The target of 5% or less on this set was **not reached**: 14.3% remains. What is left, by pattern type: HTTP POST in API client scripts whose address is a variable (10 skills), a credential read beside a send in scripts for a service the description does not name (6), a key in a header or a documented variable (5), dynamic code that is neither a regular expression nor a database call (4), installers piped into a shell from a host that is not a listed vendor, or from a vendor in an executable script, which keeps its severity by design (4), and a long tail. Those are the cases the context cannot tell from an attack without reading the skill.

The changes: nine context rules for patterns that are ordinary in the place they appear (a regular expression `.exec`, a database `exec`, `model.eval()`, an `ImportError` dependency check, a vendor key sent to that vendor in documentation, an install line in a comment, an environment copy in a file that cannot send, the word `profile` as a member, a credential-flow check that needs a real read near a send), each with a hostile variant that still flags (`tests/unit/test_devreal3_context.py`), and a parser change: a skill with frontmatter and no `name` is valid and takes its folder name.

These numbers are in-sample: the rules were written after reading these skills' flagged lines, so they do not measure the checks on new skills.
