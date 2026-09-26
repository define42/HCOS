#!/usr/bin/env bash
set -euo pipefail

command -v shellcheck >/dev/null 2>&1 || { echo 'shellcheck is required.' >&2; exit 1; }
find scripts overlay -type f -print0 | while IFS= read -r -d '' file; do
    first_line=$(head -n 1 "$file")
    case "$first_line" in
        '#!/bin/sh'|'#!/sbin/openrc-run')
            sh -n "$file"
            shellcheck --shell=sh "$file"
            ;;
    esac
done
