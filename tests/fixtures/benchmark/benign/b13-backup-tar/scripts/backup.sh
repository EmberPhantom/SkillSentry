set -eu
folder="$1"
mkdir -p backups
tar -czf "backups/$(basename "$folder")-$(date +%Y%m%d).tar.gz" "$folder"
echo "backup written to backups/"
