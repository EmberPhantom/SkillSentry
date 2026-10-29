"""JSON Schemas for Gemma semantic map and reduce steps."""

from __future__ import annotations

SCHEMA_VERSION = "1"

MAP_SCHEMA = {
    "type": "object",
    "properties": {
        "claims": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "enum": [
                            "credential_access",
                            "env_secrets",
                            "process_exec",
                            "network_request",
                            "data_upload",
                            "dns_activity",
                            "fs_write_outside_package",
                            "persistence",
                            "obfuscation",
                            "hidden_behavior",
                            "prompt_injection_to_auditor",
                            "contradicts_declared_intent",
                        ],
                    },
                    "quote": {"type": "string", "maxLength": 300},
                    "why": {"type": "string", "maxLength": 200},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
                "required": ["capability", "quote", "why", "confidence"],
            },
        }
    },
    "required": ["claims"],
}

REDUCE_SCHEMA = {
    "type": "object",
    "properties": {
        "intent": {
            "type": "string",
            "enum": [
                "text_processing",
                "file_management",
                "network_access",
                "credential_access",
                "code_execution",
                "ui_automation",
                "data_export",
                "other",
            ],
        },
        "consistency": {
            "type": "string",
            "enum": ["consistent", "unclear", "deceptive"],
        },
        "consistency_reason": {"type": "string", "maxLength": 300},
        "needs_human_review": {"type": "boolean"},
    },
    "required": ["intent", "consistency", "consistency_reason", "needs_human_review"],
}

