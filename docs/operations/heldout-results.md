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
