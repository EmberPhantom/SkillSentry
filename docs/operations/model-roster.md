# Model roster

Provider model lists and free-tier limits change often, so a list written by hand goes stale.
`scripts/list_free_models.py` asks each provider's own `/models` endpoint what it offers today and
writes the answer as a dated JSON file.

```bash
python scripts/list_free_models.py                         # every provider that has a key set, plus the local server
python scripts/list_free_models.py --providers groq --probe-limit 10
python scripts/list_free_models.py --no-probe              # list only; send no chat request
python scripts/list_free_models.py --stdout                # print the JSON instead of writing a file
```

The default output is `docs/operations/model-roster/roster-<date>.json`.

## What each row holds

For each provider: `status` (`ok`, `skipped`, `error`), the address, and the models. For each model: its id, whether the provider
says it is free, its context window when the provider reports one, the **profile** class it
resolves to (`tiny`, `small`, `mid`, `large`, `reasoning`), and, when probed, `probe`: whether a
one-token request was answered, the HTTP status, the time in milliseconds, and the rate-limit
headers the provider returned (`retry-after`, `x-ratelimit-*`), which are the best source of the
real limits.

## Rules

- **Keys come only from the environment**: `OPENROUTER_API_KEY`, `NVIDIA_API_KEY`, `GROQ_API_KEY`.
  The script never asks for one, never reads one from a file, never prints one, and scrubs it from
  every message it records.
- **No request goes to a remote provider without its key.** A provider whose variable is unset is
  written as `skipped` ("... is not set; nothing was sent"), and nothing is sent to it.
- **A probe sends only the text "Reply with the word ok."** Nothing from any skill leaves the machine.
- **Probes are few by default** (`--probe-limit`, 3 per provider; `--probe-all` for every model). A free
  tier has a daily request cap, and failed calls count against it.
- **Free means what the provider says.** OpenRouter marks free models (an id ending in `:free`, or a
  price of zero); `--all-models` keeps the others. NVIDIA NIM and Groq list what the key may use, and
  the free tier's terms (testing only, rate limits, whether prompts are used to improve products) are the provider's,
  not something the list can show.
- **The local server needs no key** and is listed without a probe: a probe loads the model, and a large
  one needs more memory than a small machine has free. Use `--probe-local` to probe it.

The roster is the input to the model benchmark; a model that is listed but does not answer a probe is
left out of it.
