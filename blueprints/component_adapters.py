"""Expose the same stdlib-only logical app ownership contract to source validators."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'proxmox/applications'))
from application_contract import (ADAPTERS, RUNTIME_FILES, CUSTODY_ROOTS, adapter,
                                  runtime_files, custody_directory)
from application_contract import ordered_services,SIDECAR_FILES
