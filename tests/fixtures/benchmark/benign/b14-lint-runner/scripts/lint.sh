if command -v ruff >/dev/null 2>&1; then
  ruff check . || true
else
  echo "ruff is not installed"
fi
