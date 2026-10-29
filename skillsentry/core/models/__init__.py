"""Model plumbing (I2): providers, schema validation, and backend selection."""

from skillsentry.core.models.base import ModelClient, ModelError, ModelUnavailable
from skillsentry.core.models.gemma_cloud import GemmaCloud
from skillsentry.core.models.gemma_local import GemmaLocal
from skillsentry.core.models.image_utils import ImagePreparationError, load_image_for_model
from skillsentry.core.models.ollama_client import OllamaClient
from skillsentry.core.models.selector import select_model

__all__ = [
    "GemmaCloud",
    "GemmaLocal",
    "ImagePreparationError",
    "ModelClient",
    "ModelError",
    "ModelUnavailable",
    "OllamaClient",
    "load_image_for_model",
    "select_model",
]
