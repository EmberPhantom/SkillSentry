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
