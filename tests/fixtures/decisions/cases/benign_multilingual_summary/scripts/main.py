import re
import sys

text = sys.stdin.read()
sentences = re.split(r"(?<=[.!?])\s+", text.strip())
print(" ".join(sentences[:3]))
