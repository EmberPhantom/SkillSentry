# Model benchmark

`scripts/benchmark_models.py` measures how well each model, behind the harness, tells skills apart. It
is the evidence for tuning the profiles (see [Model profiles](../reference/cli.md#model-profiles)): a
change to a chunk size or a prompt is kept only if these numbers say it helps.

```bash
python scripts/benchmark_models.py                                   # the two small local models
python scripts/benchmark_models.py --model ollama=gemma3:1b --repeat 3
python scripts/benchmark_models.py --model groq=llama-3.1-8b-instant # needs GROQ_API_KEY
python scripts/benchmark_models.py --sets benign-new --limit-skills 5 # a quick check
```

Results go to `docs/operations/model-matrix/<date>/`: `matrix.md` (the report), `summary.json` (the
numbers) and `rows.jsonl` (one raw row per scan).

## The labelled set

`tests/fixtures/benchmark/labels.json` labels every skill, and says whether the deterministic checks
alone should decide it (`anchors`) or only reading the intent can (`model`).

| Set | Skills | What it holds |
|:---|--:|:---|
| `corpus` | 14 | The verification corpus of `scripts/verify_corpus.py`. Four of them are packaging problems (an oversized file, bad frontmatter, not UTF-8, a symlink): labelled `invalid`, left out of precision and recall. |
| `evasion` | 19 | The obfuscation fixtures in `tests/fixtures/evasion/`: eighteen hidden or split attacks and the plain `curl \| bash` baseline. |
| `benign-new` | 30 | Realistic harmless skills: pure Markdown, scripts that legitimately use the network, write files, run subprocesses, read the environment or a config, decode base64 data, prose in Spanish, Japanese, German and French, security-education text that talks about credentials, and long skills near and above the chunk limit. They measure false positives. |
| `malicious-new` | 20 | Exfiltration, a reverse shell, persistence, privilege escalation, install-time hooks, prompt injection in English, Spanish, Chinese and Russian, hidden instructions, social engineering, and cases with no greppable string: a "cleanup" that deletes the user's folders, a spell checker that uploads the document, a formatter that edits other skills, a "bookmarks" backup that copies cookies, a dotfile sweep. |

The skills are inert: hosts are `.invalid`, `.example` or documentation addresses, and a test checks that no
fixture names any other host (two read-only public APIs aside). Nothing in them is run unless you pass `--sandbox`.

A skill is **positive** when its verdict is SUSPICIOUS or MALICIOUS. A malicious skill that is flagged is a
true positive, a benign one that is flagged a false positive. A skill the model or sandbox could not finish
is UNSCANNED and is counted apart, never as SAFE; the **strict** columns count it as a flag, which is what a
pipeline that fails on UNSCANNED sees.

## What is measured, per model

- **Verdict against label:** the confusion matrix, precision, recall and F1 for SUSPICIOUS-or-worse, the
  false positives and false negatives by name, and the same split by set and by who should decide.
- **What the model added.** Each skill is also scanned with a model that reports nothing wrong (`baseline`: the
  deterministic checks alone, with no request made). The matrix says how many verdicts the model moved up or
  down from that, and whether each move was right (up is right for a malicious skill and wrong for a benign one).
- **Behaviour:** replies that were valid for the schema on the first attempt, invalid replies, replies cut at the
  output limit, timeouts, HTTP 429s, the share of quoted evidence that exists in the skill, tokens in and out
  from the provider's own figures, wall time (mean, median, p95), and the flip rate: skills whose status
  differed between the repeats.

The numbers come from recording every request the client makes (counts, times and token figures, never the key
or the skill text), so they cover the OpenAI-compatible, local and Gemini clients alike.

## Rules the script keeps

- **No remote call without a key.** A provider that needs a key is skipped, with the reason, when its key is not
  in the environment. Keys come only from the environment and are never written to a file.
- **A remote provider receives the skill text.** The script prints which provider is in use. Run it on this inert
  set only.
- **Local models are not loaded blindly.** A model on this machine larger than 4 GB is refused unless
  `--allow-large`.
- **It respects the limiter.** Requests go through the same client as a scan, so the provider's per-minute and
  per-day limits apply. A daily quota stops that model with one message and exit code `4`; the scan the quota cut
  short is not recorded as a result.
- **Resumable.** Rows are appended as they are produced. Run the same command again and rows already in
  `rows.jsonl` are not repeated, so a quota stop, a crash or Ctrl-C does not lose results.

## Limits

- The sandbox is off by default. A skill that only the sandbox can catch (a runtime behaviour) counts as a false
  negative here.
- At temperature 0 the same prompt can still give different replies from a server, so the flip rate is measured, not assumed to be zero.
- The labels are one person's judgement of each skill. A disagreement is a reason to change the label in
  `labels.json` with the reason, not to hide the skill.
- Small differences between models on a set this size are noise. The count, not the percentage, is the thing to
  read.

## First results: the local tier, 2026-11-19

Full report: [`model-matrix/2026-11-19/matrix.md`](model-matrix/2026-11-19/matrix.md). Two models on this machine through the native client, sandbox off, three repeats: 83 skills that carry a verdict label (46 malicious, 37 benign; four more are packaging cases left out).

| | TP | FP | FN | TN | Precision | Recall |
|:---|--:|--:|--:|--:|--:|--:|
| deterministic checks alone | 42 | 0 | 4 | 33 | 1.000 | 0.913 |
| `gemma3:1b` | 42 | 0 | 4 | 32 | 1.000 | 0.913 |
| `qwen2.5-coder:1.5b` | 42 | 0 | 4 | 32 | 1.000 | 0.913 |

What the numbers say:

- **The deterministic checks do nearly all the work.** They flag 42 of 46 malicious skills and none of the 33 benign ones.
- **The two small models add no detections.** Neither flagged any of the four skills the checks miss. `gemma3:1b` changed no verdict. `qwen2.5-coder:1.5b` moved four SUSPICIOUS verdicts to MALICIOUS, all on malicious skills. Neither added a false alarm. So on this set a 1B model is harmless, and not yet useful beyond the checks.
- **The four missed skills** are `m07-sudoers` (an anchor gap: a `sudoers` write the checks do not recognise) and three that only a model can judge: `m15-cleanup-deletes-home`, `m17-skill-tamper`, `m18-cookie-copy`.
- **Behaviour is clean:** every reply was valid for the schema on the first attempt, nothing was truncated, nothing timed out, no verdict flipped across repeats (0 of 83 for each). `gemma3:1b` quoted no evidence at all; 78% of the 27 quotes of `qwen2.5-coder:1.5b` exist in the skill.
- **One skill is UNSCANNED on both models: `b15-long-guide-near-limit`, a benign skill.** It has a single 3,016-character line, longer than the 3,000-character chunk of the `tiny` profile, so that range is a recorded gap and the skill cannot be called SAFE. Before profiles the chunk was 4,000. A long unwrapped paragraph is common in Markdown, so this is a cost of the profile geometry; splitting a long line at whitespace instead of leaving a gap would remove it. Left for the tuning step.

Not measured here: the sandbox (a runtime-only attack counts as a miss), any model above 4 GB, and any remote provider (no keys were in the environment).

## After tuning, 2026-11-19 (second run)

Full report: [`model-matrix/2026-11-19-after-tuning/matrix.md`](model-matrix/2026-11-19-after-tuning/matrix.md), same two models, same set, same settings. Three changes were made from the first run's numbers.

| | TP | FP | FN | TN | Unscanned (benign) | Precision | Recall |
|:---|--:|--:|--:|--:|--:|--:|--:|
| before: deterministic checks | 42 | 0 | 4 | 33 | 0 | 1.000 | 0.913 |
| before: `gemma3:1b` | 42 | 0 | 4 | 32 | 1 | 1.000 | 0.913 |
| before: `qwen2.5-coder:1.5b` | 42 | 0 | 4 | 32 | 1 | 1.000 | 0.913 |
| **after: deterministic checks** | 44 | 0 | 2 | 33 | 0 | 1.000 | 0.957 |
| **after: `gemma3:1b`** | 44 | 0 | 2 | 33 | 0 | 1.000 | 0.957 |
| **after: `qwen2.5-coder:1.5b`** | 44 | 0 | 2 | 33 | 0 | 1.000 | 0.957 |

Comparing the two runs skill by skill, exactly these verdicts changed and no others:

- `b15-long-guide-near-limit`: UNSCANNED to SAFE on both models. A line longer than a chunk is now split at whitespace into pieces (a hard split only when there is no whitespace), so no range is left as a gap.
- `m07-sudoers`: SAFE to SUSPICIOUS. A new `privilege-escalation` check for a passwordless sudo grant, a write to the sudoers files, a setuid bit and an admin-group change.
- `m18-cookie-copy`: SAFE to SUSPICIOUS. New `credential-store` checks for a browser's cookie store and for a browser profile folder.

No new false positive appeared among the 33 benign skills. Behaviour is unchanged: every reply valid first time, nothing truncated, no timeouts, no flips (0 of 83 on each model).

### What did not work, and why

`m15-cleanup-deletes-home` and `m17-skill-tamper` are still missed by every configuration, and the levers that were tried could not fix them. The reason is structural, not tuning.

- **A model alone cannot flag a skill the checks leave clean, by design.** Model-only evidence is "uncorroborated" and is held below the SUSPICIOUS line, and that rule is what makes a weak model unable to raise a benign skill. A test now holds it against a model that claims critical evidence, with a real quote, in every chunk of every skill: no benign skill moves, and no skill the checks leave SAFE is flagged. So for a skill with nothing the checks can see, the model stage can only add a note, whatever it is asked. Changing this would give up the safety property.
- **The two small models say these skills are fine.** On `m15`, `m17` and `m18` both returned "not deceptive" with confidence 0.90 to 0.95 and no suspicious pattern, in every chunk. A "second pass when the reply disagrees with the anchors" has no disagreement to act on, because the anchors say nothing and so does the model. A "majority vote on uncertain cases" has nothing to vote on: the replies do not flip (0 of 83 across repeats) and are never uncertain. A "trust weight by profile" lowers the weight of a signal that, for these skills, is already zero.
- **A focused second question did not help.** Each model was also asked, per skill, four yes or no questions (does it delete the user's files, send data over the network, read credentials or browser data, edit other skills) and whether the skill's own description says so, on all 69 skills with a path. Counting a yes with "the description does not say so" as a flag: `gemma3:1b` flagged 0 of 39 malicious and 0 of 30 benign, `qwen2.5-coder:1.5b` the same. The raw answers did say yes to a capability on 5 and 6 of the 39 malicious skills (and on 1 benign skill each), but both models also answered that the description admits it, so the mismatch, which is the whole point, was never seen. Only `qwen2.5-coder:1.5b` noticed the deletion in `m15`.

No lever was shipped. Shipping one that changes nothing, or one that could flag a benign skill, would only add risk. The experiment is described here and not kept in the code.

### Still missed, and what it would take

| Skill | Why | What would catch it |
|:---|:---|:---|
| `m15-cleanup-deletes-home` | A "cleanup" that deletes `Documents`, `Desktop` and `Pictures` under the home folder. The path is built from `expanduser("~")` and a list of names, so no single line is a recognisable attack, and a log rotator that deletes files is legitimate. | A check that follows the home path into a delete (data flow), or a larger model that reads the mismatch and a policy that lets a trusted model's finding count without an anchor. |
| `m17-skill-tamper` | Appends instructions to every installed skill's `SKILL.md`. Documentation about skill folders mentions the same paths, so a plain pattern would flag benign text. | A check on a write to another skill's folder, limited to code files. |

A larger model is the next measurement: the roster script lists what is available, and this benchmark reruns with `--model provider=model` once a key is set.
