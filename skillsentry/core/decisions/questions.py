"""Fixed semantic question taxonomy for local decision backends.

The taxonomy is deliberately small.  Large choice sets degrade Laya accuracy
and make calibration harder.  Add a capability only when there is a
deterministic evidence source or a clear evaluation case for it.
"""

from __future__ import annotations

from collections.abc import Iterable

from skillsentry.core.decisions.base import DecisionQuestion, EvidenceCandidate

INTENT_CHOICES: dict[str, str] = {
    "text_processing": "Summarising, translating, transforming, or generating text.",
    "file_management": "Reading, writing, moving, or organising files and directories.",
    "network_access": "Calling APIs, downloading resources, or otherwise using the network.",
    "credential_access": "Reading, requesting, or transmitting credentials or secrets.",
    "code_execution": "Running commands, scripts, or arbitrary code.",
    "ui_automation": "Interacting with a browser, desktop UI, or other graphical surface.",
    "data_export": "Uploading, exporting, or transferring user or system data.",
    "other": "None of the categories above is a good fit.",
}

DECEPTION_CHOICES: dict[str, str] = {
    "consistent": "The implementation is consistent with the declared purpose.",
    "unclear": "The available evidence is insufficient to decide.",
    "deceptive": "The implementation hides or contradicts its declared purpose.",
}

# Question IDs are stable: they appear in telemetry, calibration files, and
# report metadata.  Do not rename one without a migration.
CAPABILITY_QUESTIONS: dict[str, str] = {
    "cap_credentials": (
        "Does the skill read, request, or transmit credential material such as "
        "passwords, API keys, tokens, private keys, or cloud credentials?"
    ),
    "cap_env_secrets": (
        "Does the skill inspect environment variables or shell profiles to discover "
        "secrets or credentials?"
    ),
    "cap_process": "Does the skill spawn processes or execute shell commands?",
    "cap_network": "Does the skill make outbound network requests?",
    "cap_upload": "Does the skill send data to a remote endpoint?",
    "cap_dns": "Does the skill perform DNS lookups or encode data in DNS queries?",
    "cap_filesystem": (
        "Does the skill write, modify, or delete files outside its own package directory?"
    ),
    "cap_persistence": (
        "Does the skill modify startup, shell profile, scheduled task, or other "
        "persistence mechanisms?"
    ),
    "cap_obfuscation": (
        "Does the skill decode, encrypt, or otherwise obfuscate content to hide its behavior?"
    ),
    "cap_hidden_behavior": "Does the skill hide behavior from the user or operator?",
    "cap_prompt_injection": (
        "Does the skill contain instructions aimed at an auditing agent or language "
        "model rather than at its own runtime?"
    ),
    "cap_deception": "Does the implementation contradict its declared intent?",
}


def adjudication_questions(candidates: Iterable[EvidenceCandidate]) -> dict[str, DecisionQuestion]:
    """One yes/no question per candidate, keyed ``adj_<candidate_id>``.

    The question names only the candidate's code-owned anchor type.  The code
    itself travels in the state, never in the instructions.
    """

    return {
        f"adj_{candidate.candidate_id}": DecisionQuestion(
            type="noul",
            instructions=(
                f"Is the code candidate {candidate.candidate_id} (anchor type "
                f"{candidate.anchor_type}) used for a harmful purpose rather than the "
                "skill's declared function?"
            ),
        )
        for candidate in candidates
    }


def semantic_questions() -> dict[str, DecisionQuestion]:
    """Return a fresh copy of the V1 semantic question set.

    A fresh mapping is returned so callers cannot mutate the module-level
    taxonomy while building a request.
    """

    questions: dict[str, DecisionQuestion] = {
        "intent": DecisionQuestion(
            type="choice",
            instructions="Which category best describes the skill's declared purpose?",
            criteria=dict(INTENT_CHOICES),
        ),
        "deception": DecisionQuestion(
            type="choice",
            instructions=(
                "Does the implementation behave consistently with the declared purpose, "
                "or does it hide or contradict that purpose?"
            ),
            criteria=dict(DECEPTION_CHOICES),
        ),
    }
    for question_id, instructions in CAPABILITY_QUESTIONS.items():
        questions[question_id] = DecisionQuestion(type="noul", instructions=instructions)
    return questions


__all__ = [
    "CAPABILITY_QUESTIONS",
    "DECEPTION_CHOICES",
    "INTENT_CHOICES",
    "adjudication_questions",
    "semantic_questions",
]
