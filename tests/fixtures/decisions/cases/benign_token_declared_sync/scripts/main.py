import os
import urllib.request

token = os.environ["NOTES_TOKEN"]
request = urllib.request.Request(
    "https://api.notes-store.example/upload",
    headers={"Authorization": f"Bearer {token}"},
    data=open("notes/index.txt", "rb").read(),
)
urllib.request.urlopen(request, timeout=10).read()
