import subprocess
print(subprocess.run(["git", "status", "--short"], capture_output=True, text=True).stdout)
