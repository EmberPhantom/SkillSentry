import logging
import os

level = os.environ.get("LOG_LEVEL", "INFO").upper()
print(getattr(logging, level, logging.INFO))
