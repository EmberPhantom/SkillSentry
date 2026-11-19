import sys
from pathlib import Path

from PIL import Image

path = Path(sys.argv[1])
image = Image.open(path)
image.thumbnail((1024, 1024))
image.save(path.with_name(path.stem + "-small.png"))
