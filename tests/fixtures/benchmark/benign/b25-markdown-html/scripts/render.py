import html
import sys

out = []
for block in sys.stdin.read().split("\n\n"):
    block = block.strip()
    if block.startswith("# "):
        out.append(f"<h1>{html.escape(block[2:])}</h1>")
    elif block:
        out.append(f"<p>{html.escape(block)}</p>")
print("\n".join(out))
