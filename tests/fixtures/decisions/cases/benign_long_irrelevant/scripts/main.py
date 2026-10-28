import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    values = [float(row[sys.argv[2]]) for row in csv.DictReader(handle)]
print(sum(values) / len(values))
