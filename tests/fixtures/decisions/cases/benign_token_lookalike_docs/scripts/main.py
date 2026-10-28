import sys
print(len(open(sys.argv[1], encoding="utf-8").read().split()))
