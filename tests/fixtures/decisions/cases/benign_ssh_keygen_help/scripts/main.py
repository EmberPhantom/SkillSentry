import subprocess, sys
subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", sys.argv[1]], check=True)
