#!/bin/bash
# Install an uploaded Capstone starter without erasing existing learner work.

set -euo pipefail

usage() {
  echo "Usage: $0 <archive.tgz> <destination> <create|backup-replace>" >&2
}

if [ "$#" -ne 3 ]; then
  usage
  exit 2
fi

archive="$1"
destination="$2"
mode="$3"

case "$mode" in
  create|backup-replace) ;;
  *)
    echo "ERROR: install mode must be create or backup-replace" >&2
    exit 2
    ;;
esac

if [[ ! "$destination" =~ ^/home/ubuntu/work/[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: destination must be one direct child of /home/ubuntu/work" >&2
  exit 2
fi
if [ ! -f "$archive" ]; then
  echo "ERROR: uploaded Capstone archive is missing: $archive" >&2
  exit 3
fi

if [ "$mode" = create ] && [ -e "$destination" ]; then
  echo "ERROR: destination already exists; existing learner edits were preserved" >&2
  echo "To retain a timestamped backup and install a new starter, rerun with:" >&2
  echo "  CAPSTONE_UPLOAD_MODE=backup-replace" >&2
  exit 4
fi

install -d -m 0755 /home/ubuntu/work
staging=$(mktemp -d /home/ubuntu/work/.capstone-upload.XXXXXX)
backup_path=""

rollback() {
  status=$?
  if [ "$status" -ne 0 ] && \
     [ -n "$backup_path" ] && \
     [ ! -e "$destination" ] && \
     [ -e "$backup_path" ]; then
    mv "$backup_path" "$destination"
  fi
  rm -rf "$staging"
  trap - EXIT
  exit "$status"
}
trap rollback EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

tar -xzf "$archive" -C "$staging"
if [ ! -f "$staging/capstone/app/main.py" ] || \
   [ ! -x "$staging/capstone/attacks/run-all.sh" ]; then
  echo "ERROR: uploaded archive is not a valid Capstone starter" >&2
  exit 3
fi

if [ -e "$destination" ]; then
  backup_root=/home/ubuntu/work/capstone-backups
  install -d -m 0755 "$backup_root"
  backup_path="$backup_root/$(basename "$destination").$(date -u +%Y%m%dT%H%M%SZ).$$"
  mv "$destination" "$backup_path"
  printf 'CAPSTONE_BACKUP=%s\n' "$backup_path"
fi

mv "$staging/capstone" "$destination"
printf 'CAPSTONE_INSTALLED=%s\n' "$destination"
printf 'CAPSTONE_UPLOAD_MODE=%s\n' "$mode"

trap - EXIT HUP INT TERM
rm -rf "$staging"
