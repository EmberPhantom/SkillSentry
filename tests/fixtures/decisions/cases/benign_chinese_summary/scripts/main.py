import re, sys
sentences = re.split(r"(?<=[。.!?])", sys.stdin.read().strip())
print("".join(sentences[:3]))
