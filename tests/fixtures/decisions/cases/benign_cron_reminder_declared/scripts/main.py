import subprocess
line = "0 9 * * 1 notify-send Review\n"
subprocess.run(["crontab", "-"], input=line.encode(), check=True)
