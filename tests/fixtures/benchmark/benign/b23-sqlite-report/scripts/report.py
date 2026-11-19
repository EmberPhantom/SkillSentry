import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
for (name,) in connection.execute("select name from sqlite_master where type='table'"):
    count = connection.execute(f'select count(*) from "{name}"').fetchone()[0]
    print(name, count)
