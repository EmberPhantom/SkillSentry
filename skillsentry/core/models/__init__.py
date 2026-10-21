"""Model plumbing (I2): providers, schema validation, and backend selection."""

from skillsentry.core.models.base import ModelClient, ModelError, ModelUnavailable
from skillsentry.core.models.gemma_cloud import GemmaCloud
from skillsentry.core.models.gemma_local import GemmaLocal
from skillsentry.core.models.image_utils import ImagePreparationError, load_image_for_model
from skillsentry.core.models.mock import MockGemma
from skillsentry.core.models.selector import select_model

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
