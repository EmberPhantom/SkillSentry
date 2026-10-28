import base64, sys
print(base64.b64encode(open(sys.argv[1], "rb").read()).decode()[:80])
