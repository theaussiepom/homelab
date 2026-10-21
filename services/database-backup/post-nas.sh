#!/bin/bash
# Native executable POST_SCRIPT; framework propagates this process's status.
# Only the last component of the ordered mysql,phpmyadmin job creates a bundle.
if [ "${4:-}" != "phpmyadmin" ]; then exit 0; fi
exec /usr/local/libexec/recovery-bundle.py nas "$@"
