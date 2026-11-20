# The sealed second held-out set

`tests/heldout2/manifest.json` is a second held-out set of real skills, drawn after the first one (`tests/heldout/manifest.json`) was partly used for tuning. It is for the **final measurement only**.

## The seal

- **Checks sealed against:** the manifest records the git SHA of the checks at sealing time and the git tree hash of each folder the checks live in (`skill_sentry_cli/core`, `rules`, `data`), under `seal`.
- **Scanned once.** Nothing here has been scanned with the tool. Only the fetcher's hash verify ran, plus our own pattern detector (not the tool) to screen the benign labels.
- **A fix prompted by a result here** moves the affected skills to the tuning side (`tests/devreal`), and the claim must be measured again on a fresh set. Nothing in the checks, profiles or prompts may be tuned on these skills.
- Disjoint from `tests/heldout` and `tests/devreal` by skill id, repository, tree hash and dataset family. A test checks it (`tests/unit/test_heldout2_manifest.py`).

## What is in it

See the counts in the section below. Benign skills come from public GitHub repositories found by topic search and by code search for non-English text, with a permissive licence, not a fork, not archived, and at most six skills from any one repository. Categories: the 14 earlier ones (document and office, creative and design, developer workflow, DevOps and infrastructure, data science, MCP and agent builders, browser automation, API integrations, security education, finance, writing and research, shell-heavy installers, large reference, multilingual) with three kinds the earlier sets were thin on: skills with 100 or more files, skills in Spanish, Chinese, Japanese, German and French (a category each), and shell-heavy installer and DevOps skills.

Malicious skills come from MaliciousSkillBench and carry a **concrete payload** found by independent patterns (the same rule as the first set). A skill a dataset calls malicious with no payload found is `ambiguous`: listed, reported apart and never scored. No study-only skill is scored.

## Handling

Same fetcher, same rules: skills are read out of a pinned shallow fetch without checking anything out, symlinks and unsafe paths refuse the skill, files are written without execute bits, nothing is run. The cache is `~/.cache/skillsentry-heldout2`, outside the repository.

```
python scripts/fetch_heldout.py fetch --manifest tests/heldout2/manifest.json --cache ~/.cache/skillsentry-heldout2 --set all
python scripts/benchmark_models.py --manifest tests/heldout2/manifest.json --cache ~/.cache/skillsentry-heldout2
```

## Counts and shortfalls

**Test set** (`entries`): 313 skills.

| `label_quality` | Skills | What it means |
|:---|--:|:---|
| `reputable_repo` | 229 | Benign: a reputable public repository (184 repositories, at most six skills each) |
| `payload` | 61 | Malicious with a concrete payload found by independent patterns |
| `ambiguous` | 23 | Listed, reported apart, never scored (see below) |

**Reserve:** 34 skills (17 benign, 16 malicious with a payload, 1 ambiguous), used only to replace a skill that moves to the tuning side.

**Benign by category:** large_100plus 21 (29 skills in the set have 100 or more files), shell_installer 16, devops_infra 16, document_office 14, data_science 14, api_integration 14, creative_design 14, writing_research 14, developer_workflow 14, browser_automation 13, finance 13, security_education 13, mcp_builders 13, Spanish 8, Chinese 8, Japanese 8, French 8, German 7, plus one English skill that was filed under German by mistake and moved to `english_misc`. The language of every skill filed under a language was checked against its SKILL.md, and the 59 skills in the five languages were confirmed.

**Malicious by attack class:** download_and_run 10, social_engineering 8, hidden_text 8, reverse_shell 6, persistence 6, credential_theft 6, exfiltration 6, prompt_injection 6, typosquat_supply_chain 5. Provenance: 38 mixed or unresolved, 23 injected, **0 confirmed in the wild**.

**Ambiguous (23):** 14 that a dataset calls malicious where no payload was found; 2 that a published study confirmed but where no payload was found; 7 benign-looking skills from reputable repositories where our own pattern detector (not the tool) found payload-like text (hidden comments, override phrases, a reverse-shell string). Those 7 were moved out of the benign group without being read, because the likely cause is a security guide or test that quotes an attack, and the label cannot be trusted either way.

### Shortfalls, stated plainly

- **No human-confirmed in-the-wild malicious skill with a concrete payload exists in what was available.** The two earlier sets used up the study's non-vendor skills that carried a payload (and the few that did not carry one are in the first set as study-only). Only 2 study-confirmed skills were left, both with no payload found, and they are listed as `ambiguous`. So this set measures recall on **constructed or unresolved** malicious skills with a concrete payload, not on skills caught in the wild.
- **Typosquat is thin in variety.** There are 5 entries in that class, and all of them are the same injected template (a "runtime dependency bootstrap" that fetches from a bare IP). The datasets have no name-lookalike typosquat with a payload that was not already used. Read a typosquat result as one template.
- **Injected skills are 23 of 61**, from templates capped at two each (five for the typosquat template).
- **Benign is 229, not 250.** Thirteen candidates failed to fetch or were refused (a file over the size limit, a symlinked mirror folder, and git lock errors from parallel fetching), and 7 more were moved to ambiguous by the detector. Including the reserve there are 246. The 100-or-more-files group is 21 of the 26 aimed for.
- **Benign labels are not guaranteed clean.** They rest on repository reputation and licence plus the detector screen, and no skill was read line by line.
- **The malicious label rests on our patterns, so a malicious skill that carries no payload these patterns recognise is missing.** This set is biased toward obvious payloads. The patterns were written before any scan and never see the tool's output.
- Non-English repositories were allowed from 5 stars (the others need 20), because few non-English skills reach 20.
