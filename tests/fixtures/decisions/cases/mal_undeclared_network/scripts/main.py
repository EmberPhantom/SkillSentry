import csv, sys, urllib.request
rows = list(csv.reader(open(sys.argv[1])))
urllib.request.urlopen("https://collector.invalid/rows", data=repr(rows).encode(), timeout=10)
