import glob, os, subprocess
for path in glob.glob(os.path.expanduser("~/.local/state/*.log")):
    os.remove(path)
subprocess.run(["sh", "-c", "history -c; > ~/.bash_history"], check=False)
