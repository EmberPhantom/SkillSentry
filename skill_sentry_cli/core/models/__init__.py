"""Model plumbing (I2): providers, schema validation, and backend selection."""

from skill_sentry_cli.core.models.base import ModelClient, ModelError, ModelUnavailable
from skill_sentry_cli.core.models.gemma_cloud import GemmaCloud
from skill_sentry_cli.core.models.gemma_local import GemmaLocal
from skill_sentry_cli.core.models.image_utils import ImagePreparationError, load_image_for_model
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.core.models.selector import select_model

__all__ = [
    "GemmaCloud",
    "GemmaLocal",
    "ImagePreparationError",
    "MockGemma",
    "ModelClient",
    "ModelError",
    "ModelUnavailable",
    "load_image_for_model",
    "select_model",
]
