#!/bin/bash
# Native executable POST_SCRIPT; never logs destination identifiers.
if [ "${4:-}" != "phpmyadmin" ]; then exit 0; fi
exec /usr/local/libexec/recovery-bundle.py s3 "$@"
