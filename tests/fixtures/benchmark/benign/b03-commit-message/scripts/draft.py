import subprocess

diff = subprocess.run(["git", "diff", "--cached", "--stat"], capture_output=True, text=True, check=False).stdout
files = [line.split("|")[0].strip() for line in diff.splitlines() if "|" in line]
print("Update " + ", ".join(files[:3]) if files else "No staged changes")
