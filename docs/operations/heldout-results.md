# Held-out measurements at a glance

Every measurement of the static checks (no model) on real skills we did not write. One row per set. Each row is one measurement, made once, on the checks as they were then. Intervals are in the section for each set.

| Set | What it was | Recall, payload-confirmed | Recall, confirmed by someone else | False alarms on finished benign | Strict false alarms | Tuned on afterwards? |
|:---|:---|:--|:--|:--|:--|:--|
| First (`tests/heldout`), before the reading-order change | 188 benign, 43 payload skills; many large skills unfinished | 26/27 = 0.963 (16 of 43 unfinished) | not a group yet | 9/78 = 0.115 | 119/188 = 0.633 | Yes: partly used for tuning, so it is not a held-out claim |
| First, after the reading-order change | the same set | 37/40 = 0.925 (3 of 43 unfinished) | not a group yet | 20/151 = 0.132 | 57/188 = 0.303 | Yes, as above |
| Second (`tests/heldout2`) | 229 benign, 61 payload; most large and document skills unfinished | 53/56 = **0.946** | not a group yet | 5/161 = **0.031** | 73/229 = 0.319 | Its unfinished lists drove the coverage work; the detection checks were not tuned on it |
| Third (`tests/heldout3`, now `tests/devreal3`) | 243 benign, hard-shape-heavy; 67 payload, 29 confirmed by others | 64/67 = **0.955** | 12/27 = **0.444** | 46/201 = **0.229** | 88/243 = 0.362 | Yes: moved to the tuning side and tuned on |
| Fourth (`tests/heldout4`) | 246 benign, 76% ordinary shapes; 60 payload, 24 confirmed by others | 57/60 = **0.950** | 6/22 = **0.273** | 33/224 = **0.147** | 55/246 = 0.224 | Not yet |

How to read it:

- **Recall on skills with a payload string is steady, 92% to 96%,** across the four sets. It is recall on payloads that patterns of the kind the checks use can find, so it may be flattered.
- **Recall on skills confirmed by someone else, with no payload string of ours, is 27% to 44%.** The ones that are an instruction and nothing else (model-only) are not found by static checks: 0 of 9 on the third set and 0 of 13 on the fourth. A model is needed for them, and no model run has finished on any set.
- **The false-alarm rate depends on the mix of skills, not only on the checks.** It was 3.1% on the second set because most large, document and installer skills did not finish, so they were not counted. It was 22.9% on the third set, which was built full of those shapes and they were read. It was 14.7% on the fourth, which is mostly ordinary skills: about 9% of ordinary skills were flagged and about 38% of the hard shapes.
- **Which numbers are out of sample.** The second and fourth rows were not tuned on before they were measured. The third was too, but it has been tuned on since, so no new claim can use it. The first set was partly tuned on.

---

# Results on the sealed fourth held-out set

One measurement of the static checks on `tests/heldout4/manifest.json` (see `docs/operations/heldout4-set.md`), run once, on 2026-12-02. This section holds ids and counts only, no skill content.

- **Checks measured:** git `1d3048e` (the commit that added the set). The set was sealed at `5f7c281`; the checks did not change in between.
- **What ran:** the deterministic checks only, with the sandbox off. **No language model finished a run** (see "What this does not measure").
- **Nothing was tuned on this set.** What happens to it next is for the owners to decide: tuning on it would make it a tuning set and end its use for a held-out claim.
- Intervals are Wilson 95%. A skill the scan could not finish (UNSCANNED, INVALID SKILL) is not a hit or a false alarm in the plain rates. The strict rates count it as a flag.

## Headline

| Measure | Result |
|:---|:--|
| Recall on payload-confirmed malicious skills | 57/60 = **0.950** (0.863 to 0.983) |
| Recall on skills confirmed by someone else, no payload string of ours | 6/22 = **0.273** (0.132 to 0.481); strict 8/24 = 0.333 (0.180 to 0.533) |
| False-alarm rate on benign skills that finished | 33/224 = **0.147** (0.107 to 0.200) |
| Strict false-alarm rate (not finished counted as flagged) | 55/246 = **0.224** (0.176 to 0.280) |

The set: 246 benign, 60 payload-confirmed malicious, 24 confirmed by someone else, 32 ambiguous (listed, never scored). 224 of the 246 benign skills finished; 22 did not (13 UNSCANNED, 9 INVALID SKILL). Of the 33 false alarms, 24 are `SUSPICIOUS` and 9 `MALICIOUS`.

## Ordinary skills and hard shapes

The set was built to be mostly ordinary skills. The two are reported apart:

| Group | Skills | Finished | Flagged | False-alarm rate on finished | Not finished | Strict |
|:---|--:|--:|--:|:--|--:|:--|
| Ordinary shapes (prose-only, small script helpers, API, DevOps, developer workflow, MCP builders, finance, creative, writing, data science, security education, languages) | 188 | 179 | 16 | **0.089** (0.056 to 0.140) | 9 | 0.133 |
| Hard shapes (100 or more files, notebooks, CSS/HTML/SVG, Office/PDF/archive, shell installers) | 58 | 45 | 17 | **0.378** (0.251 to 0.524) | 13 | 0.517 |

## What changed against the second and third sets, as measured

False alarms on finished benign skills were 3.1% on the second set, 22.9% on the third and 14.7% on the fourth.

- The second set's low rate comes from what did not finish: its large, document and installer skills were mostly unfinished, so the 161 skills it counted were the easy ones. The checks have been changed since to read those skills, and they flag at a high rate.
- The third set was full of those shapes (hard shapes were most of the set), so its rate is the hard-shape rate. The fourth is the realistic mix, and its two rows above show the two populations: about 9% for ordinary skills and 38% for the hard shapes. The fourth set's overall 14.7% sits between the two earlier numbers because its mix does.
- The ordinary-skill rate (8.9%) is the figure to compare with the second set's 3.1%. It is higher, and the intervals (0.056 to 0.140 against 0.013 to 0.071) barely overlap; we do not have a full explanation. Part is that the checks read more of each skill than they did on the second set, and part may be the sample.
- INVALID SKILL fell from 17 of 243 on the third set to 9 of 246 here, because a skill with no `name` in its frontmatter is now accepted.

## Skills that did not finish

- **Benign: 22 of 246.** 9 INVALID SKILL (malformed packages: a missing description, no frontmatter or frontmatter that does not parse) and 13 UNSCANNED. Of the 13 UNSCANNED: a file type the scan cannot read 4, images beyond the vision budget 4, a text file over 1 MiB 2, text beyond the 4 MiB text budget 1, required text not read 1, other 1.
- **Payload-confirmed malicious: 0 did not finish.** Confirmed by someone else: 2 did not finish (the two in-the-wild skills).

## Splits

False alarms on benign skills that finished, by category:

| Category | Flagged | Not finished |
|:---|:--|--:|
| prose_only | 0/26 | 1 |
| small_script_helpers | 7/25 | 2 |
| api_integration | 1/18 | 0 |
| devops_infra | 1/13 | 1 |
| developer_workflow | 0/14 | 0 |
| mcp_builders | 0/13 | 0 |
| creative_design | 3/12 | 0 |
| finance | 0/11 | 1 |
| writing_research | 1/10 | 0 |
| data_science | 1/7 | 1 |
| security_education | 1/8 | 0 |
| lang_de | 0/4 | 0 |
| lang_es | 0/4 | 0 |
| lang_fr | 0/1 | 2 |
| lang_ja | 0/4 | 1 |
| lang_zh | 0/5 | 0 |
| english_misc | 1/4 | 0 |
| large_100plus | 7/13 | 6 |
| shell_installer | 3/12 | 0 |
| web_css_html_svg | 5/11 | 1 |
| office_pdf_archive | 2/9 | 3 |
| notebook | 0/0 | 3 |

Most cells hold under 15 skills, so the intervals are wide. The hard-shape cells are the ones above 25%, and small script helpers (7 of 25) are the ordinary shape that flags most.

False alarms by pattern type (a skill can have several): secret-access 6, remote-resource 6, credential-path 5, exfil-http-post 4, shell-exec 4, credential-flow-unverified 3, raw-socket 3, dynamic-code 3, and 10 other types with 2 or fewer.

Recall by attack class (payload-confirmed): download_and_run 8/8, exfiltration 8/8, hidden_text 8/8, prompt_injection 6/6, reverse_shell 6/6, social_engineering 8/8, typosquat_supply_chain 10/10, **persistence 3/6**. Recall by provenance group: injected 28/31, mixed_unresolved 29/29.

Recall on skills confirmed by someone else, by form: remote-resource 6/8, **model-only (instruction-only) 0/13**, archive form 0/1, in the wild 0 of 2 finished (both unfinished). The model-only group is not measured by this run: those attacks have no string for the static checks to find, so only a model could catch them.

## Every miss, false alarm and unfinished skill

- **False alarms (33):** b-Forge-CallIntelligence, b-GLM-V-glmv-stock-analyst, b-GitHubClawToolkit-gemini-image-describer, b-Orryx-orryx-creation-suite, b-agent-skills-ai, b-agentic-dev-team-docker-image-audit, b-ai-agent-skills-comfyui, b-ai-agent-skills-github-auth, b-ai-brain-starter-secret-warn, b-ai-toolkit-skill-creator, b-ai-vision-mcp-performance, b-ccboard-performance, b-claude-agent-builder-agent-builder, b-claude-video-skills-motion-design-edit, b-claude-video-skills-video-edit, b-hermes-automotive-skills-automotive-commands, b-hermes-automotive-skills-automotive-knowledge, b-hq-core-import-context, b-huaweicloud-skills-huawei-cloud-clouddocs-aipage, b-humanizer-ru-humanizer-ru, b-master-skills-build, b-mcp-server-trello-skill, b-nest-turbo-starter-skill-creator, b-open-webui-plugins-inline-visualizer-v2, b-roast-my-design-system-roast-my-design-system, b-skills-for-teachers-ppt-grid-deck, b-spaceapp-skill-creator, b-standards-secrets-management, b-superPM-skills, b-tau-job-research-skills-fit-review, b-tools-create, b-total-agent-memory-memory-protocol, b-vietnam-agentic-skills-agent-observability
- **Missed payload skills (3):** `m-ASB04_000066`, `m-ASB04_001088`, `m-ASB04_003540` (all three persistence class).
- **Missed, confirmed by someone else (16):** m-ASB04_000039, m-ASB04_001823, m-ASB04_001847, m-ASB04_002147, m-ASB04_002657, m-ASB04_002900, m-ASB04_003273, m-ASB04_003494, m-ASB04_004425, m-ASB04_004806, m-ASB04_005028, m-ASB04_005082, m-ASB04_005655, m-ASB04_006362, m-ASB04_007109, m-ASB04_007414. Unfinished (2): `m-ASB04_000511`, `m-ASB04_004539`.
- **Unfinished benign skills (22):** b-3dviz-pro-max-3dviz-pro-max, b-CleanMyPosts-drawio, b-Happycapy-skills-latex-document, b-Skills-illustration-flat-with-black, b-agent-plugins-skills-improving-skills-in-lab, b-ai-marketing-market-competitors, b-ai-marketing-market-social, b-animate-animate, b-autocode-fix, b-claude-thai-skills-thai-invoice, b-context-cascade-when-managing-token-budget-use-token-budget-advisor, b-cumcm-AI-workflow--cumcm-code-reviewer, b-curation-bench-flamingo-a-visual-language-model-for-few-shot-learning-arxiv-2204-14198v2, b-cursor-1c-skills-1c-bsp-api, b-diagram-design-diagram-design, b-dotfiles-statechart, b-effekseer-vfx-skill-effekseer-vfx, b-ocx-commit, b-polyakov-claude-skills-blogger-ads-skill, b-readmedaddy-readmedaddy, b-roughcut-harness-review, b-wjx-ai-kit-wjx-survey-ppt
- **Ambiguous (32, not scored):** the checks called 10 MALICIOUS, 9 SUSPICIOUS, 12 SAFE and left 1 UNSCANNED. These say nothing about accuracy.

## Stated shortfalls of this set

The shortfalls are in `docs/operations/heldout4-set.md`; the ones that affect how to read these numbers:

- **In the wild: only 2 skills, and both did not finish.** No public set of confirmed malicious skills from the large incident campaigns was found.
- **No credential-theft skills.** That class is not measured.
- **Typosquat is 10 entries from one template.**
- **No malicious notebook, Word, PowerPoint or Excel skill.** The readers are covered on the malicious side by the remote-resource skills and one archive skill only.
- **Hard benign shapes are thin:** notebooks 3 (all unfinished), Office documents 3, PDFs 4 and archives 5.
- **Benign labels are a reputation and a detector screen.** Nobody read all 246 skills.
- **The payload group may flatter recall:** its payloads were located by patterns of the kind the checks use.

## What this does not measure

The model-assisted scan could not be run on this set: the hosted free-tier quota is too small for a set of this size, the small local models fail the built-in capability check (their output is not used), and the 6 GB local model cannot be loaded on the machine used. So every number above is for the static checks alone. Instruction-only attacks, what a model adds on large skills, and the sandbox are unmeasured.

## What this means for use

- **SkillSentry is an advisory pre-screening tool.** Do not treat it as a gate that blocks or approves installs on its own.
- **About 9% of ordinary skills are flagged and about 38% of complex ones** (100 or more files, web files, documents, installers). A reviewer should expect to look at roughly one in eleven ordinary skills and more than one in three complex skills, plus the skills that did not finish (5% of ordinary and 22% of complex).
- **Recall on skills with a payload string is high (95.0%).** On skills confirmed by someone else with no payload string of ours it is 27%, and **instruction-only attacks are not found at all by the static checks** (0 of 13 here, 0 of 9 on the third set). They need a model, and no model measurement exists.
- **Use `--require-full-coverage` and read `UNSCANNED` and `INVALID SKILL` as "not checked", never as clean.**

---

# Results on the sealed second held-out set

One measurement of the static checks on `tests/heldout2/manifest.json` (see `docs/operations/heldout2-set.md`), run once, on 2026-11-20.

- **Checks measured:** git `1198fd438a2f` (the commit that added the set). Manifest sha256 `fd2b9e8d3762`.
- **What ran:** the deterministic checks only, with the sandbox off. **No language model ran** (see "What this does not measure").
- **Nothing was tuned on this set.** No check, profile or prompt was changed because of these results. Any fix prompted by them moves the affected skills to the tuning side (`tests/devreal`), and the claim has to be measured again on a fresh set. This page holds ids and counts only; no skill content.
- Intervals are Wilson 95%. A skill the scan could not finish (UNSCANNED, INVALID SKILL) is not a hit or a false alarm in the plain rates. The strict rates count it as a flag.

## Headline

| Measure | Result |
|:---|:--|
| Recall on payload-confirmed malicious skills | 53/56 = **0.946** (0.854 to 0.982) |
| Strict recall (unscanned counted as caught) | 58/61 = 0.951 (0.865 to 0.983) |
| False-alarm rate on benign skills that finished | 5/161 = **0.031** (0.013 to 0.071) |
| Strict false-alarm rate (unscanned counted as flagged) | 73/229 = **0.319** (0.262 to 0.382) |

The set: 229 benign (reputable repositories), 61 payload-confirmed malicious, and 23 ambiguous that are listed but never scored. 56 of the 61 payload skills finished; 161 of the 229 benign skills finished.

The plain false-alarm rate is low because it only counts skills the scan finished. 68 of 229 benign skills (29.7%) did not finish, so the number a user feels is closer to the strict one.

## Skills that did not finish

- **Benign UNSCANNED: 68 of 229.** The large skills are the main cause: 19 of the 21 benign skills with 100 or more files did not finish. Without a model, text beyond the static budget cannot be read by anything, so the scan says UNSCANNED rather than SAFE.
- **Payload-confirmed UNSCANNED: 5 of 61.**

Benign UNSCANNED by category: api_integration 3, browser_automation 8, creative_design 6, data_science 2, devops_infra 2, document_office 4, finance 2, lang_de 3, lang_es 2, lang_fr 2, lang_ja 1, lang_zh 1, large_100plus 19, mcp_builders 3, security_education 2, shell_installer 4, writing_research 4, developer_workflow 0, english_misc 0.

## Splits

False alarms on benign skills that finished, by category:

| Category | Flagged | Not finished |
|:---|:--|--:|
| api_integration | 0/11 | 3 |
| browser_automation | 0/5 | 8 |
| creative_design | 0/8 | 6 |
| data_science | 0/12 | 2 |
| developer_workflow | 0/14 | 0 |
| devops_infra | 1/14 | 2 |
| document_office | 0/10 | 4 |
| english_misc | 0/1 | 0 |
| finance | 0/11 | 2 |
| lang_de | 0/4 | 3 |
| lang_es | 0/6 | 2 |
| lang_fr | 0/6 | 2 |
| lang_ja | 1/7 | 1 |
| lang_zh | 0/7 | 1 |
| large_100plus | 1/2 | 19 |
| mcp_builders | 0/10 | 3 |
| security_education | 1/11 | 2 |
| shell_installer | 0/12 | 4 |
| writing_research | 1/10 | 4 |

Most cells hold under 15 skills, so the intervals are wide (a 0/10 cell is consistent with a true rate up to about 28%). Do not read a category as "safe" or "bad" from one cell.

Recall by attack class (payload-confirmed):

| Attack class | Flagged | Not finished |
|:---|:--|--:|
| credential_theft | 6/6 | 0 |
| download_and_run | 10/10 | 0 |
| exfiltration | 6/6 | 0 |
| hidden_text | 6/8 | 0 |
| persistence | 6/6 | 0 |
| prompt_injection | 6/6 | 0 |
| reverse_shell | 6/6 | 0 |
| social_engineering | 3/4 | 4 |
| typosquat_supply_chain | 4/4 | 1 |

Recall by provenance group:

| Provenance | Flagged | Not finished |
|:---|:--|--:|
| injected (a payload added to an ordinary skill) | 17/18 = 0.944 (0.742 to 0.990) | 5 |
| mixed_unresolved (origin not resolved by the dataset) | 36/38 = 0.947 (0.827 to 0.985) | 0 |

All five unfinished payload skills are in the injected group. Recall is by source dataset 36/38 (SRC001) and 17/18 (SRC010).

## Every miss, false alarm and unfinished skill

- **False alarms (5):** `b-claude-skills-wjs-converting-text-to-video`, `b-claude_skils-jules-api`, `b-marketing-cli-mktg-x`, `b-modulestf-terraform-module-pr-review`, `b-redteam-skill-creds`
- **Missed payload skills (3):** `m-ASB04_002072`, `m-ASB04_004807`, `m-ASB04_005079`
- **Unfinished payload skills (5):** `m-ASB04_001467`, `m-ASB04_001832`, `m-ASB04_003051`, `m-ASB04_003405`, `m-ASB04_006675`
- **Unfinished benign skills (68):** `b-ComfyUI-Agent-Kit-comfyui`, `b-Light-Science-light-software-copyright`, `b-OpenDesigner-opendesigner-paint`, `b-OpenDesigner-opendesigner-paint-2`, `b-SeeCode-seecode`, `b-Textum-textum`, `b-TricorderKit-tk-boot`, `b-Vibe-Skills-docx`, `b-VibesOS-vibes`, `b-ZeroSlop-zero-slop`, `b-agent-plugins-model-deployment`, `b-agent-skills-ax-audit`, `b-agent-vision-toolkit-vision-skills`, `b-ai-employees-ads-change-list`, `b-ai-employees-csat-reply-desk`, `b-ai-employees-gtm-intake-and-dashboard`, `b-ai-employees-sales-desk-standup`, `b-ai-employees-web-dependency-run`, `b-anidoodle-anidoodle`, `b-arkhe-claude-plugins-release-please-setup`, `b-aurora-smart-home-esphome`, `b-balance-balance`, `b-bautraegervertragspruefer-skill-docs`, `b-bautraegervertragspruefer-skill-skill`, `b-brag-brag`, `b-brand-identity-skill-ko`, `b-builder-skills-write`, `b-capybara-toolbox-tidy-board`, `b-cc-blender-skill-text-to-blender`, `b-claude-code-minoan-agent-browser`, `b-claude-marketplace-worktree`, `b-claude-night-market-skills-eval`, `b-claude-seo-skills-seo`, `b-claude-skills-developing-preact`, `b-creative-director-skill-creative-director`, `b-day-trader-skill-trader-risk`, `b-document-SKILLs-pptx`, `b-forge-skills-forge-app-builder`, `b-forja-landing-skill`, `b-forward-deployed-selling-forward-deployed-selling`, `b-geo-doctor-ai-crawler-audit`, `b-geo-sleuth-geo-sleuth`, `b-hedgehog-bmad-brainstorming`, `b-hook-everything-market-intelligence`, `b-logo-design-skill-logo-design`, `b-manim-skill-manim-skill`, `b-manim_skill-manimgl-best-practices`, `b-mcode-stack-magic-move-deck`, `b-music-skill-music-production`, `b-native-subtitle-quote-image-native-subtitle-quote-image`, `b-neuromapa-sobre`, `b-ok-skills-ai-elements`, `b-openmeld-verify-service-connection`, `b-reanimate-reanimate`, `b-recomby-geo-seo-geo-optimizer`, `b-rsc-harness-connect-tool`, `b-skills-choose-your-orchestrator`, `b-skills-isometric-motion`, `b-skills-jeecg-codegen-new`, `b-skills-scenario-godot-performance-export`, `b-skills-scenario-godot-rendering-lighting`, `b-stitch-kit-stitch-design-system`, `b-super-board-super-collect`, `b-unikit-ai-unikit-memory`, `b-vexjoy-agent-frontend`, `b-vexjoy-agent-workflow`, `b-vocaloid-style-mv-pipeline-vocaloid-style-mv`, `b-yoink-setup`
- **Ambiguous (23, not scored):** the checks flagged 9 (MALICIOUS or SUSPICIOUS), called 10 SAFE, left 2 INVALID SKILL and 2 UNSCANNED. These say nothing about accuracy, because the labels are unresolved.

## Stated shortfalls of this set

- **No in-the-wild malicious skill.** None of the 61 payload skills was a human-confirmed real-world attack. They are dataset skills with a payload located by our own pattern detectors. Recall here measures detection of constructed or unresolved skills.
- **Recall may be flattered.** The same kind of pattern that decided "this skill has a payload" is what the checks look for. A skill whose payload the detectors could not find was not scored at all, so the set leans toward payloads the checks can see.
- **Typosquat is thin.** 5 skills, all from one template. Hidden text (8) and social engineering (8) are also small.
- **Benign labels are a reputation, not a proof.** A benign skill is one from a public repository with stars and a permissive licence, screened by a pattern detector. Nobody read all 229. A real attack in a popular repository would be labelled benign and counted as a false alarm.
- **Small cells.** Most splits hold under 15 skills. Treat per-category numbers as hints.
- **Repository clustering.** Up to six benign skills may come from one repository, so the 229 are less independent than the count suggests.

## What this does not measure

The model-assisted scan (the analysis stage that reads the text and judges intent) **could not be run on this set**. The free-tier quota of the hosted model services available for the run was too small: one service finished 5 of 313 skills in 30 passes, and a larger one finished 1 skill in 7 minutes. So every number above is for the static checks alone. What a model adds (reading late reference text, instruction-only attacks, reducing UNSCANNED on large skills) is unmeasured here. The sandbox was also off, so dynamic behaviour is unmeasured.

## What this means for use

- **SkillSentry is an advisory pre-screening tool, not a gate.** A SAFE result means the checks found nothing in what they could read. It is not a guarantee, and the sandbox and model stages are not a substitute for reading a skill you do not trust.
- **Without a model, most large skills are not scanned.** 19 of 21 benign skills with 100 or more files came back UNSCANNED. Plan for a model, or treat UNSCANNED as "not checked".
- **The strict false-alarm rate is 31.9%.** Counting every skill the tool would not call SAFE, about one in three ordinary skills needs a human look. Scanning only the skills that finish, about one in thirty-two is a false alarm.
- **Recall is high on skills with a visible payload (94.6%)**, with a wide interval (85.4% to 98.2%), and the set cannot show how the tool does against a careful real attacker.
- UNSCANNED is never reported as SAFE, and that stays true.


---

# Results on the sealed third held-out set

One measurement of the static checks on `tests/heldout3/manifest.json` (see `docs/operations/heldout3-set.md`), run once, on 2026-11-27, for the final measurement of the whole harness. This section holds ids and counts only, no skill content.

- **Checks measured:** git `2499fa4b6f92` (the commit that added the set). Manifest sha256 `32097dca363d`.
- **What ran:** the deterministic checks only, with the sandbox off. **No language model finished a run** (see "What this does not measure").
- **Nothing was tuned on this set before the run.** What happens to it now is described at the end: it moves to the tuning side, so it cannot be used for a held-out claim again.
- Intervals are Wilson 95%. A skill the scan could not finish (UNSCANNED, INVALID SKILL) is not a hit or a false alarm in the plain rates. The strict rates count it as a flag.

## Headline

| Measure | Result |
|:---|:--|
| Recall on payload-confirmed malicious skills | 64/67 = **0.955** (0.876 to 0.985) |
| Recall on skills confirmed by someone else (a dataset's human review and runtime check, or a published write-up), no payload string of ours | 12/27 = **0.444** (0.276 to 0.627); strict 14/29 = 0.483 (0.314 to 0.656) |
| False-alarm rate on benign skills that finished | 46/201 = **0.229** (0.176 to 0.292) |
| Strict false-alarm rate (not finished counted as flagged) | 88/243 = **0.362** (0.304 to 0.424) |

The set: 243 benign, 67 payload-confirmed malicious, 29 confirmed by someone else, 31 ambiguous (listed, never scored). 201 of the 243 benign skills finished; 42 did not (25 UNSCANNED and 17 INVALID SKILL).

## The rise in false alarms, as measured

The false-alarm rate on finished benign skills is 22.9%, against 3.1% on the second held-out set. The intervals (0.176 to 0.292 and 0.013 to 0.071) do not overlap, so this is a real difference and not noise.

- **Where it is.** The set was built to include the shapes the second set left out or left unscanned. The rise is concentrated there: skills with 100 or more files 12 of 17 finished were flagged (0.706), CSS, HTML and SVG skills 9 of 15 (0.600), shell installers 5 of 8 (0.625), notebooks 3 of 8 (0.375). These skills were mostly `UNSCANNED` on the second set, so they were not in its false-alarm rate; the checks read them now, and they flag. Outside those four shapes, 17 of 153 finished skills were flagged (0.111).
- **It is not only the new shapes.** 11.1% outside the hard shapes is still above the 3.1% measured on the second set. We do not have a full explanation. Part of it is that the checks changed between the two sets (the readers, priority reading, static-cleared code and new pattern checks expose more text to the pattern checks), and part may be the sample.
- **What fires.** By pattern type, among the 46 false alarms (a skill can have several): dynamic-code 20, credential-flow-unverified 15, exfil-http-post 11, secret-access 6, shell-exec 5, persistence 5, and a long tail of 14 other types. 39 are `SUSPICIOUS` and 7 `MALICIOUS`.
- **What it means.** About one in four ordinary skills that finish is flagged by the static checks alone, and more than one in three counting skills that did not finish. This is a measured number and we do not excuse it: a reviewer would have to look at a large share of ordinary skills.

## Skills that did not finish

- **Benign: 42 of 243** (17.3%): 17 INVALID SKILL (malformed packages: a missing field or an unreadable manifest) and 25 UNSCANNED. Of the 25 UNSCANNED: images beyond the vision budget 7, text beyond the 4 MiB text budget 6, required text not read 4, a file type the scan cannot read 3, other 3, a text file over 1 MiB 1, a compiled or oversized file 1.
- **Skills with 100 or more files: 15 of 32 did not finish.**
- **Payload-confirmed malicious: 0 did not finish.** Confirmed by someone else: 2 did not finish.

## Splits

False alarms on benign skills that finished, by category:

| Category | Flagged | Not finished |
|:---|:--|--:|
| api_integration | 1/9 | 0 |
| archive | 1/3 | 2 |
| creative_design | 0/8 | 0 |
| data_science | 0/6 | 3 |
| developer_workflow | 2/11 | 1 |
| devops_infra | 3/10 | 2 |
| english_misc | 3/11 | 1 |
| images | 2/16 | 4 |
| lang_de | 0/4 | 1 |
| lang_es | 1/8 | 0 |
| lang_fr | 1/6 | 0 |
| lang_ja | 0/8 | 0 |
| lang_zh | 0/6 | 2 |
| large_100plus | 12/17 | 15 |
| notebook | 3/8 | 0 |
| office_document | 1/3 | 0 |
| pdf | 0/1 | 3 |
| prose_only | 1/23 | 1 |
| security_education | 1/11 | 0 |
| shell_installer | 5/8 | 5 |
| web_css_html_svg | 9/15 | 1 |
| writing_research | 0/9 | 1 |

Most cells hold under 15 skills, so the intervals are wide. The cells above 0.5 (large, web and shell) are the ones that matter.

Recall by attack class (payload-confirmed):

| Attack class | Flagged | Not finished |
|:---|:--|--:|
| credential_theft | 6/6 | 0 |
| download_and_run | 8/8 | 0 |
| exfiltration | 8/9 | 0 |
| hidden_text | 6/8 | 0 |
| persistence | 6/6 | 0 |
| prompt_injection | 6/6 | 0 |
| reverse_shell | 6/6 | 0 |
| social_engineering | 8/8 | 0 |
| typosquat_supply_chain | 10/10 | 0 |

Recall by provenance group (payload-confirmed): injected 28/30 (0.933), mixed_unresolved 36/36 (1.000), demonstration 0/1. Recall by source dataset: 36/36 and 28/30 for the two benchmark datasets, 0/1 for the published demonstration.

Recall on skills confirmed by someone else, by form: remote-resource 8/10, wild (dataset-confirmed) 3/5 (1 not finished), document form 1/1, model-only (instruction-only) 0/9 (1 not finished), archive form 0/2. **The model-only group is not measured by this run**: those attacks have no string for the static checks to find, so only a model could catch them, and no model run finished.

## Every miss, false alarm and unfinished skill

- **False alarms (46):** b-LangGraph-Partner-langgraph-development, b-MemoryBench-vercel-deploy-claimable, b-SkillMD-gsd-browser, b-SkillMD-hermes-dojo, b-YouTube-AI-Motion-Graphics-board-sync, b-agent-skills-hermes-onboarding, b-agent-sprite-forge-codeart2d, b-ai-agent-skills-classification-agentgram, b-ai-agent-skills-classification-asana, b-animate-roblox-characters-animate-roblox-characters, b-api-gateway-skill-api-gateway, b-arch-diagram-skill-arch-diagram, b-awesome-copilot-agents-az-cli, b-basdonax-ai-agentkit-actualizar-agente-whatsapp, b-bitrix-agent-skill-bitrix, b-charles-video-maker-charles-video-maker, b-container-container, b-data2story-skill-data2story-pro, b-divalto-ia-devkit-documenting-erp, b-docx-cli-weak-agent-test, b-eodhd-claude-skills-eodhd-api, b-galyarder-framework-brainstorming, b-getspecstory-workthreads, b-hardened-skills-canvas-hardened, b-investigators-copilot-osint, b-kilo-kit-mcp-render-deploy, b-manifest-dev-poll-slack, b-market-research-skills-analyst-research, b-motion-video-skill-motion-video-production, b-oh-story-claudecode-story-setup, b-open-agent-hub-claude-api, b-open-agent-hub-docx, b-paper2code-paper2code, b-product-launch-motion-skill-product-launch-motion, b-qa-skills-bug-reproduction, b-recruiting-copilot-recruit-board, b-sd0x-harness-deploy-flow, b-skill-up-full-report-pipeline, b-skillnote-complete-skill, b-skills-k8s-catch-up, b-skills-threads-post, b-threads-skills-threads-skills, b-tui-design-tui-design, b-ultraship-writing-skills, b-website-rebuild-skill-website-rebuild, b-youtube-skills-youtube-skills
- **Missed payload skills (3):** `m-ASB04_002079`, `m-ASB04_004729`, `m-toxicskills-goof-vercel`. Two are hidden-text class and one is the published demonstration (exfiltration class).
- **Missed, confirmed by someone else (15):** m-ASB04_000268, m-ASB04_000759, m-ASB04_001189, m-ASB04_001280, m-ASB04_001411, m-ASB04_001660, m-ASB04_002202, m-ASB04_002685, m-ASB04_004034, m-ASB04_004190, m-ASB04_004937, m-ASB04_005464, m-ASB04_005521, m-ASB04_006253, m-ASB04_007158. Unfinished (2): `m-ASB04_000369`, `m-ASB04_002772`.
- **Unfinished benign skills (42):** b-BB-Video-bb-video, b-Dev-Labs-ian-xiaohei-illustrations, b-My-MathModeling-skills-math-figure, b-OpenCodeBuch-bausteine, b-PyWry-modals, b-TDX-finance-mcp-plugin-v2-tdx-wxd-bk, b-TDX-finance-mcp-plugin-v2-tdx-wxd-etf, b-agentic-brownfield-coding-bashless, b-agentic-brownfield-coding-headless, b-agentic-brownfield-coding-monorepo, b-agentic-brownfield-coding-standalone, b-agentmako-mako-guide, b-agentmako-mako-workflow, b-chinese-fortune-chinese-fortune, b-claude-skill-social-post-social-post, b-clawd-emotes-skill-clawd-emotes, b-clawd-emotes-skill-clawd-photo-compositor, b-cleantv-android-tv-setup, b-devpace-pace-dev, b-diagram-design-zh-diagram-design-zh, b-digital-human-koubo-comfyui-digital-human-koubo, b-drawio-skill-drawio-skill, b-dynare-copilot-dynare-copilot, b-everything-claude-finance-wertschoepfungsketten, b-fast-agent-fast-agent-system, b-job-application-agent-job-application-agent, b-keeran.ai-hormozi-vsl, b-maptiler-skills-skills, b-msp-claude-plugins-api-patterns, b-nature-skills-nature-figure, b-open-agent-hub-remotion-best-practices, b-open-bridge-mail-draft, b-presentation-skill-presentation-skill, b-product-film-product-film, b-proof-how-it-works, b-quant-buddy-view-quant-buddy-view, b-recall-loom-recallloom, b-skills-pstack-skill, b-stalemap-upgrade, b-taste-skill-taste-skill, b-tyran-fidelity-gate, b-vibe-knowledge-vibe-knowledge
- **Ambiguous (31, not scored):** the checks called 6 MALICIOUS, 12 SUSPICIOUS and 13 SAFE. These say nothing about accuracy.

## Stated shortfalls of this set

The shortfalls are in `docs/operations/heldout3-set.md`; the ones that affect how to read these numbers:

- **No confirmed in-the-wild payload set.** The in-the-wild skills are 6 dataset-confirmed ones in the "confirmed by someone else" group, plus one demonstration built by its publisher.
- **No malicious notebook, Word, PowerPoint or Excel skill.** The readers are covered on the malicious side by only a few remote-resource, archive and PDF skills.
- **Typosquat is 10 entries from one template.**
- **Benign labels are a reputation and a detector screen.** Nobody read all 243 skills. A real attack in a popular repository would be counted as a false alarm.
- **The payload group may flatter recall:** its payloads were located by patterns of the kind the checks use.

## What this does not measure

The model-assisted scan could not be run on this set. A hosted free-tier model finished 2 of the 29 confirmed skills in 25 minutes (one scan took 243 seconds), and the 6 GB local model cannot be loaded on the machine used (about 3.4 GB of memory was free). So every number above is for the static checks alone. The model-only attacks, what a model adds on large skills, and the sandbox are unmeasured.

## What this means for use

- **SkillSentry is an advisory pre-screening tool.** Do not treat it as a gate that blocks or approves installs on its own.
- **The static checks alone flag too many ordinary skills.** 22.9% of finished benign skills (36.2% counting the ones that did not finish) is not usable as an automatic block. It can order a review queue.
- **Recall on skills with a payload string is high (95.5%)** and drops to 44.4% on skills confirmed by someone else with no payload string of ours. Attacks that are only instructions need a model and are unmeasured.
- **Large and web-heavy skills are where it is weakest:** most are flagged or not finished.
- **This set can no longer be a held-out set.** Its false alarms and misses are tuning material; any change they prompt moves these skills to the tuning side and the claim must be measured again on a fresh set.
