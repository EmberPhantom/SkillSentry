# The sealed fourth held-out set

`tests/heldout4/manifest.json` is the fourth held-out set of real skills. It is for **one more out-of-sample measurement of the final checks**, after the third set was measured and then used for tuning (`tests/devreal3`). It is disjoint from every earlier set, and nothing was tuned on it.

## The seal

- **Checks sealed against:** git `5f7c28162cd9` (main after the second tuning set was merged), with the git tree hash of each folder the checks live in (`skill_sentry_cli/core`, `rules`, `data`), the date, and the rule, under `seal` in the manifest.
- **Scan once.** Nothing here has been scanned with the tool. Only the fetcher's hash verify ran (420 of 420 ok), the benchmark loader's hash check, and our own pattern detector (not the tool) to screen the benign skills.
- **No more tuning on any set** until this one has been run. A fix prompted by a result here moves the affected skills to the tuning side, and the claim must be measured again on a fresh set.
- **Disjoint** from `tests/heldout`, `tests/devreal`, `tests/heldout2`, `tests/heldout3` and `tests/devreal3` by skill id, repository and tree hash; on the benign side also by dataset family. On the **malicious side** dataset family overlap is allowed (21 of the 132 malicious or ambiguous entries share a family with an earlier set; none shares an id or a tree hash), because the one benchmark that holds most malicious skills has few families. A test checks it (`tests/unit/test_heldout4_manifest.py`).

## What is in it

362 entries and 58 reserve skills.

| Group | Entries |
|:---|--:|
| Benign (reputable public repositories, at most 4 per repository, 203 repositories) | 246 |
| Malicious, payload-confirmed (a concrete payload located by independent patterns) | 60 |
| Malicious, confirmed by someone else, no payload string of our own | 24 |
| Ambiguous (not scored): 20 malicious-by-dataset without evidence, 12 benign where our detector found payload-like text | 32 |

The two malicious groups are reported apart. The benchmark script gives a recall for each.

**Benign mix, made representative on purpose.** The third set was hard-shape-heavy; this one is mostly ordinary skills so the headline false-alarm rate reflects a realistic population. Ordinary shapes are 188 of 246 (76%): prose-only 27, small script helpers 27, API integrations 18, DevOps and infrastructure 14, developer workflow 14, MCP and agent builders 13, finance 12, creative and design 12, writing and research 10, data science 8, security education 8, and non-English skills (Chinese 5, Japanese 5, Spanish 4, German 4, French 3, plus 4 picked for a language that proved to be English). Hard shapes are 58 of 246 (24%), and **the doc and the report should show them separately**: 100 or more files 19, shell installers 12, CSS, HTML or SVG 12, Office, PDF or archive 12, notebooks 3. Counted by what the skills contain: 38 with shell scripts, 23 with web files, 10 with images, 5 with archives, 4 with PDFs, 3 with notebooks and 3 with Office documents.

**Malicious, payload-confirmed by class:** exfiltration 8, download and run 8, hidden text 8, social engineering 8, reverse shell 6, persistence 6, prompt injection 6, typosquat 10, **credential theft 0**.

**Malicious, confirmed by someone else:** 13 model-only (instruction-only: no string for a pattern to find; the dataset labels them malicious with human review and a runtime check), 8 that load a remote resource, 2 in the wild per the datasets, 1 that ships an archive.

## Where the malicious skills come from

MaliciousSkillBench (several datasets in one), read from a pinned archive. Skills are only read as files and are never run. The public sample repositories we found (the Snyk ToxicSkills demonstration repository, the MaliciousAgentSkillsBench and MalSkillBench projects) are either already in the earlier sets or are the same data as the benchmark.

## Shortfalls, plainly

- **In the wild: 2.** Only 2 skills with the benchmark's provenance `wild` were left (the earlier sets used 6 of the 8 that exist and the Snyk demonstration). They are in the `confirmed` group because our patterns found no payload string in them. We did not find a public set of confirmed malicious skills from the large incident campaigns.
- **No credential-theft skills.** The benchmark has only 7 skills of that class with a concrete payload, and the earlier sets used 6 of them; the last one fell to another class. The class is not measured here.
- **Typosquat is thin.** 10 entries, all from one template.
- **No malicious notebook, Word, PowerPoint or Excel skill.** The benchmark has none. The readers are covered on the malicious side by the remote-resource skills and one archive skill only.
- **Confirmed-by-others is 24, not about 25 as planned, and model-only labels are the datasets', not ours.**
- **Hard benign shapes are thin.** Notebooks 3, Office documents 3, PDFs 4 and archives 5: permissive-licence repositories rarely ship them. Large skills are 19, fewer than planned, because 7 candidates were refused or moved to ambiguous.
- **Benign labels are a reputation and a screen.** 246 skills from repositories with stars and a permissive licence, screened by our own pattern detector. 12 were moved to ambiguous because the detector found payload-like text; nobody read all 246.
- **Recall may be flattered** for the payload group: the payload was located by patterns of the kind the checks use.

## Handling

Same fetcher, same rules: skills are read out of a pinned shallow fetch without checking anything out, symlinks and unsafe paths refuse the skill, files are written without execute bits, nothing is run. The cache is `~/.cache/skillsentry-heldout4`, outside the repository. Run the measurement with `scripts/benchmark_models.py --manifest tests/heldout4/manifest.json --cache ~/.cache/skillsentry-heldout4` and `--out` outside the repository.
