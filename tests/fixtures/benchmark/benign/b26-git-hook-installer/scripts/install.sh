set -eu
cat > .git/hooks/pre-commit <<'HOOK'
python -m pytest -q
HOOK
chmod +x .git/hooks/pre-commit
echo "installed pre-commit hook"
