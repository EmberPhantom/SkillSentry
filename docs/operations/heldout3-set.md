# The sealed third held-out set

`tests/heldout3/manifest.json` is the third held-out set of real skills, drawn after the harness changes that came out of the second one (`tests/heldout2`): priority reading, static-cleared text and code, readers for notebooks, documents, PDFs and archives, simple-question mode and the capability check. It is for the **final measurement of the whole harness**. `tests/heldout2` stays a sealed-used set and nothing was moved.

## The seal

- **Checks sealed against:** git `0883c7c8f0bc` (main after the capability-check change), with the git tree hash of each folder the checks live in (`skill_sentry_cli/core`, `rules`, `data`), the date, and the rule, under `seal` in the manifest.
- **Scan once.** Nothing here has been scanned with the tool. Only the fetcher's hash verify ran (415 of 415 ok), the benchmark loader's hash check, and our own pattern detector (not the tool) to screen the benign skills.
- **A fix prompted by a result here** moves the affected skills to the tuning side, and the claim must be measured again on a fresh set. Nothing in the checks, profiles or prompts may be tuned on these skills.
- **Disjoint** from `tests/heldout`, `tests/devreal` and `tests/heldout2` by skill id, repository and tree hash, and on the benign side by dataset family. On the **malicious side** dataset family overlap is allowed, because the one benchmark that holds the malicious skills has few families; 15 of the 138 malicious or ambiguous entries share a dataset family with an earlier set, and none shares an id or a tree hash. A test checks all of this (`tests/unit/test_heldout3_manifest.py`).

## What is in it

370 entries and 45 reserve skills. Counts are in the manifest; the headline ones:

| Group | Entries |
|:---|--:|
| Benign (reputable public repositories, at most 4 per repository, 208 repositories) | 243 |
| Malicious, payload-confirmed (a concrete payload located by independent patterns) | 67 |
| Malicious, confirmed by someone else, no payload string of our own | 29 |
| Ambiguous (not scored): 20 malicious-by-dataset without evidence, 11 benign where our detector found payload-like text | 31 |

The two malicious groups are reported apart. The benchmark script gives a recall for each (`payload` and `confirmed`).

**Benign shapes** (a skill can have more than one): 32 with 100 or more files, 8 with notebooks, 3 with Office documents, 5 with PDFs, 5 with archives, 33 with images, 39 with CSS, HTML or SVG, 35 with shell scripts (13 shell installers), 24 prose-only, and non-English skills in Spanish (8), Chinese (8), Japanese (8), French (6) and German (5). Skills picked for a language whose text proved to be English were moved to `english_misc`.

**Malicious, payload-confirmed by class:** credential theft 6, exfiltration 9, reverse shell 6, persistence 6, download and run 8, prompt injection 6, hidden text 8, social engineering 8, typosquat 10.

**Malicious, confirmed by someone else:** 10 model-only (instruction-only: no string for a pattern to find; the dataset labels them malicious with human review and a runtime check), 10 that load a remote resource (a style sheet, page or image), 6 in-the-wild skills the datasets confirmed, 2 that ship an archive, and 1 that ships a PDF.

## Where the malicious skills come from

Malicious skills come from MaliciousSkillBench (several datasets in one) read from a pinned archive, and one published demonstration: a fake Vercel skill from the Snyk Labs ToxicSkills repository, whose payload is in the published write-up. Skills are only read as files and are never run.

## Shortfalls, plainly

- **In the wild.** 6 skills have the benchmark's provenance `wild` (5 confirmed by a study with human review and a runtime check, 1 by a static verification in the dataset), and they are in the `confirmed` group because our patterns found no payload string in them. We did not find a public repository that publishes confirmed malicious skills from the large incident campaigns. The Snyk demonstration skill is built by the publisher for a demonstration; it is not found in the wild.
- **No malicious notebook, Word, PowerPoint or Excel skill.** The benchmark has none. The new readers are covered on the malicious side only by the 10 remote-resource skills, 2 archive skills and 1 PDF skill. For the archive and PDF ones the payload location inside the file is not known to us.
- **Typosquat is thin.** 10 entries, all from one template (a runtime dependency bootstrap).
- **Model-only labels are not ours.** They rest on the dataset's human review and runtime check. We cannot show a payload string, by construction.
- **Benign document shapes are thin.** Public repositories with a permissive licence rarely ship Office documents or archives in a skill: 3 with Office documents, 5 with PDFs and 5 with archives. German is 5, and many German skills in search results turned out to be English.
- **Benign labels are a reputation and a screen.** 243 skills from repositories with stars and a permissive licence, screened by our own pattern detector. 11 were moved to ambiguous because the detector found payload-like text in them; nobody read all 243.
- **Dropped by the fetcher.** Three skills were refused because they contain symlinks; replacements were taken from the reserve where the category had one.
- **Recall may be flattered** for the payload group: the payload was located by patterns of the kind the checks also use.

## Handling

Same fetcher, same rules: skills are read out of a pinned shallow fetch without checking anything out, symlinks and unsafe paths refuse the skill, files are written without execute bits, nothing is run. The cache is `~/.cache/skillsentry-heldout3`, outside the repository. Run the final measurement with `scripts/benchmark_models.py --manifest tests/heldout3/manifest.json --cache ~/.cache/skillsentry-heldout3` and `--out` outside the repository.
