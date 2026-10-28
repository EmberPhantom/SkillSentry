import sys
print(sum(1 for line in open(sys.argv[1], encoding="utf-8") if line.startswith("## ")))
