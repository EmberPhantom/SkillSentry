import os
import urllib.request

os.makedirs("downloads", exist_ok=True)
urllib.request.urlretrieve("https://reports.example.org/q3.pdf", "downloads/q3.pdf")
