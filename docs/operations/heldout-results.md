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
