# Choosing and running a model

SkillSentry's checks come in two layers. The **deterministic checks** (patterns, syntax-tree checks, credential flow, hidden text, the sandbox) are the ground truth and run without any model. The **model stage** reads the skill the way a reviewer would, compares what it says with what it does, and adds findings the patterns cannot see. This page says how to pick a model for that stage, how to configure each provider, what a model can and cannot add, and how to measure it yourself.

## What a model can and cannot do

Read this before choosing, because it sets expectations.

- **A model cannot make a clean skill look unsafe on its own.** A finding that only the model reported, with nothing from the deterministic checks behind it, does not raise the verdict into SUSPICIOUS, and a verdict that rests on model output alone never reaches MALICIOUS. Every quote the model gives is checked against the skill's own text, and a quote that is not there is dropped. A skill the model could not finish reading is `UNSCANNED`, never `SAFE`.
- **The other side of that rule: a model cannot catch a skill the checks leave clean.** If a skill does something harmful with no line the checks recognise, the model stage can add a note, not a verdict. This is deliberate. It is what keeps a weak model from raising false alarms, and it is tested against a model that claims critical evidence in every chunk of every benchmark skill.
- **A bigger model helps the model stage, not the checks.** Moving from a small local model to a hosted one changes how well the intent is read and how often a reply is malformed. It does not change what the deterministic checks find.

## Choosing a provider

| If you want | Use | Notes |
|:---|:---|:---|
| Nothing to leave your machine | `ollama` (or any server on `localhost`) | No key, no limits, no cost. The default. Quality depends on the model you can run. |
| A free hosted model for the inert test corpus | `openrouter`, `nim` or `groq` | Free tiers are rate limited; the client paces itself. Skill content goes to the provider. |
| One of your own servers (LM Studio, llama.cpp, vLLM, a gateway) | `openai` with a `base_url` | Any server that speaks the OpenAI chat API. |
| A hosted model from Google | `cloud` (the Gemini API) | Needs `GEMINI_API_KEY`. Skill content goes to Google. |

`auto` (the default) tries the local model first and never chooses a hosted provider on its own. A hosted provider is always something you select.

### The privacy rule

**A hosted provider receives the skill's content.** The banner of every scan names the provider, but the decision is yours:

- Use a hosted provider on skills you are willing to send to a third party: the benchmark corpus, public skills, your own open-source skills.
- For a skill you do not want to share, use a model on this machine. Free tiers often allow the provider to use prompts to improve its products; read the terms before sending anything you care about.
- Keys come only from environment variables. They are never read from the configuration file (a value that looks like a key there is refused), and they are not written to logs, reports, JSON output or the verdict cache.

## Choosing a model class

SkillSentry sorts a model into a **class** by its id and shapes its requests to the class: how much text goes in a call, how many calls a skill may use, how short the reply schema is, whether worked examples are shown. An unknown model gets the conservative `small` class.

| Class | Chosen for | Context | Reply limit | Characters per call | Calls per skill | Retries | Examples in the prompt |
|:---|:---|--:|--:|--:|--:|--:|:---|
| `tiny` | under 5B parameters | 4,096 | 1,024 | 3,000 | 4 | 1 | yes |
| `small` | 5B to 13B, and the default for an unknown model | 8,192 | 1,536 | 4,000 | 3 | 1 | yes |
| `mid` | 14B to 40B | 32,768 | 2,048 | 4,000 | 4 | 1 | no |
| `large` | 41B and up, and hosted frontier models | 128,000 | 4,096 | 8,000 | 6 | 1 | no |
| `reasoning` | models that think before answering | 128,000 | 8,192 | 8,000 | 6 | 0 | no |

`skill-sentry-cli doctor` prints the class it chose. To override one value, or the whole class, use `[model.profile]` (see the [CLI reference](../reference/cli.md#model-profiles)):

```toml
[model.profile]
name = "mid"            # or leave "auto"
context_tokens = 16384  # a value you know your server runs with
```

A long line is read in pieces, so a skill with one very long paragraph is read in full on every class. A skill that needs more calls than the class allows is reported `UNSCANNED` with the range that was not read; it is never quietly marked `SAFE`.

## Configuration for each provider

Put these in `skillsentry.toml` (or the file named by `SKILLSENTRY_CONFIG`). Set the key in your shell, not in the file.

### A model on this machine (ollama)

```toml
[model]
backend = "local"
ollama_url = "http://localhost:11434"
ollama_model = "<the tag you pulled>"   # `ollama list` shows it
ollama_num_ctx = 4096                   # the window the server runs the model with
```

No key. The context and reply limit you set here are the ones the profile uses.

### Any OpenAI-compatible server (`openai`)

```toml
[model]
backend = "openai"

[model.provider]
base_url = "http://localhost:1234/v1"   # must end in /v1
model = "<the model id the server uses>"
api_key_env = "MY_SERVER_KEY"           # the NAME of the variable, never the key
```

A server on `localhost`, `127.0.0.1` or `::1` is reported as local and needs no key. For a remote one, set the variable: `export MY_SERVER_KEY=...`.

### OpenRouter

```toml
[model]
backend = "openrouter"

[model.provider]
model = "<a model id; ids ending :free are free>"
```

```bash
export OPENROUTER_API_KEY=...
```

### NVIDIA NIM

```toml
[model]
backend = "nim"

[model.provider]
model = "<a hosted model id>"
```

```bash
export NVIDIA_API_KEY=...
```

### Groq

```toml
[model]
backend = "groq"

[model.provider]
model = "<a hosted model id>"
```

```bash
export GROQ_API_KEY=...
```

### Gemini

```toml
[model]
backend = "cloud"
gemini_model = "<a Gemini API model id>"
```

```bash
export GEMINI_API_KEY=...
```

You can also pick the provider for one run with `--backend` (`local`, `cloud`, `openai`, `openrouter`, `nim`, `groq`). Run `skill-sentry-cli doctor` after changing a provider: it names the provider, whether the key variable is set (never its value), whether the model is listed, the profile and the limits in use.

## Free-tier limits

Free tiers cap requests a minute, tokens a minute and requests a day, per model. SkillSentry paces its requests to the limits it knows, waits out a `Retry-After`, and when a **daily** quota is used up it stops using the model for the run: it finishes the static checks for the remaining skills, reports them `UNSCANNED`, prints one message with how many skills the model read and how many it did not, and exits `4`. Run it again after the limit resets, or switch model or provider.

**These figures were collected from third-party summaries on 2026-11-19. The providers did not confirm them, and they change often. Verify them on your own account, and see below for how to list what a provider offers today.**

| Provider | Reported free limits | Starting value in SkillSentry | Notes |
|:---|:---|:---|:---|
| OpenRouter | 20 requests/min; 50 requests/day, or 1,000/day after buying credits; models whose id ends `:free` | 20 requests/min; 50/day for a `:free` id | Failed calls count towards the daily cap. Use a fixed model id for repeatable runs. |
| NVIDIA NIM | about 40 requests/min | 40 requests/min | Trial terms say testing and evaluation. Reports of models that are listed but do not answer chat. |
| Groq | per model, for example 30 requests/min, 8,000 tokens/min, 1,000 to 14,400 requests/day | 30 requests/min, 6,000 tokens/min | The tokens-a-minute cap is the real limit for a long skill: the client paces by tokens, not only requests. |
| Gemini API | varies by model and project; Google publishes no fixed free figures per model | none | Check your own project's limits in AI Studio. Free-tier prompts may be used to improve products. |
| A server on this machine | none | none | The only tier with no limits and no data leaving the machine. |

Set the limits for your account under `[model.provider]`; `0` turns one off:

```toml
[model.provider]
requests_per_minute = 20
tokens_per_minute = 0        # off
requests_per_day = 1000
```

The count of requests in a day is kept for one run, so a new run starts at zero and learns a quota from the provider's first refusal. A scan also never sleeps past `--max-time`: if pacing needs longer than the time left, that request is not sent and the stage says so.

## See what a provider offers today

`scripts/list_free_models.py` asks each provider's own `/models` endpoint, so the list is generated, not remembered:

```bash
python scripts/list_free_models.py --no-probe          # list only; no chat request is sent
python scripts/list_free_models.py --providers groq --probe-limit 10
```

It reads keys from the environment, skips a provider whose key is not set (nothing is sent to it), and writes a dated file with each model's class and, if probed, the rate-limit headers the provider returned, which are the best source of the real limits. See [Model roster](../operations/model-roster.md).

## Measure a model yourself

`scripts/benchmark_models.py` scans a labelled set of 83 skills (the verification corpus, the evasion fixtures, 30 benign skills and 20 malicious ones) with each model and reports precision, recall, the false positives and negatives by name, what the model changed against the deterministic checks alone, and how it behaved (valid replies, truncation, timeouts, tokens, time, and whether verdicts flip between repeats):

```bash
python scripts/benchmark_models.py                              # the models on this machine
python scripts/benchmark_models.py --model groq=<model id>      # needs GROQ_API_KEY
python scripts/benchmark_models.py --model openai=<model id> --base-url http://localhost:1234/v1
```

A provider without its key in the environment is skipped and nothing is sent to it. The set is inert text and code with addresses that cannot be real, and the script prints which provider receives it. A local model larger than 4 GB is refused unless you pass `--allow-large`. The run is resumable and respects the provider's limits. Results go to `docs/operations/model-matrix/<date>/`. See [Model benchmark](../operations/model-benchmark.md) for the method and the set.

## What the measurements say

Two small models (about 1B parameters each) on this machine, on that set, with the sandbox off. Reports: [first run](../operations/model-matrix/2026-11-19/matrix.md) and [after tuning](../operations/model-matrix/2026-11-19-after-tuning/matrix.md).

| | Malicious flagged | Benign flagged | Precision | Recall |
|:---|--:|--:|--:|--:|
| Deterministic checks alone, before tuning | 42 of 46 | 0 of 33 | 1.000 | 0.913 |
| Deterministic checks alone, after tuning | 44 of 46 | 0 of 33 | 1.000 | 0.957 |
| Either small model, after tuning | 44 of 46 | 0 of 33 | 1.000 | 0.957 |

What this says, plainly:

- **The deterministic checks do nearly all the work.** The gains from the first run to the second came from fixing the checks (a sudoers write, a browser cookie store) and from reading very long lines in pieces. They did not come from a model.
- **A model of this size adds almost nothing.** Neither small model found a skill the checks missed. One moved four SUSPICIOUS verdicts to MALICIOUS, all on malicious skills, and neither added a false alarm. Replies were valid for the schema on the first attempt every time, nothing was cut off or timed out, and no verdict changed between three repeats.
- **A model alone cannot raise a skill the checks leave clean.** This is by design, not a tuning gap. A second question, a second pass, a vote across replies and a lower trust weight were considered; with nothing for the checks to corroborate, none of them can change a verdict, and the small models answered "not deceptive" on the missed skills anyway. A model that claimed critical evidence in every chunk moved no benign skill and flagged no clean one.
- **Two skills in the set are still missed by every configuration.** One is a "cleanup" skill that deletes the user's own folders, building the path from the home folder in pieces; a pattern cannot tell it from a legitimate log cleaner without following the path into the delete. The other quietly appends instructions to every installed skill; skill documentation mentions the same paths, so a plain pattern would flag harmless text. Both need either a deeper check on how the path is built and used, or a larger model together with a rule that lets a trusted model's finding count without a corroborating check. Neither has been measured yet.
- **A larger model is the next measurement.** The numbers above are for the local tier only. No hosted provider has been measured, because that needs your key; run the benchmark with `--model` to add one.

## If something goes wrong

| You see | Likely cause | What to do |
|:---|:---|:---|
| `UNSCANNED`, "partial coverage" | `SKILL.md`, a script, a config file or instruction text needs more calls than the class allows, or the window is too small | Use a larger class or model, or raise `context_tokens` if the server really runs a larger window. |
| `SAFE` with "Static-only: ..." and "Coverage: partial" | Plain text with no risk signal, beyond the call budget, was read by the static checks only | Nothing is wrong. Use `--require-full-coverage` in CI if partial results must fail. The model read `SKILL.md`, the scripts and the instruction text first. See "Long reference text beyond the model's budget" in `docs/security/evasion-limits.md`. |
| `UNSCANNED`, "quota is used up", exit `4` | A daily limit is exhausted | Run again after the reset, or switch provider or model. |
| `UNSCANNED`, "the request was not sent" | `--max-time` is shorter than the pacing a free tier needs | Raise `--max-time`, or lower the number of skills per run. |
| `... is not set` | The key variable is empty | `export` it in the shell that runs the scan. |
| "refused the credentials" | A wrong or expired key | Check the variable named in the message. |
