import ast
import sys
from pathlib import Path

module = Path(sys.argv[1])
names = [n.name for n in ast.parse(module.read_text(encoding="utf-8")).body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")]
Path("tests").mkdir(exist_ok=True)
Path("tests", f"test_{module.stem}.py").write_text("".join(f"def test_{n}():\n    pass\n\n" for n in names), encoding="utf-8")
