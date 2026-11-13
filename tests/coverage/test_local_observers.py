"""Inspection helpers use synthetic metadata and never open native devices."""

import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("valid", [True, False])
def test_vendor_metadata_receipt_accepts_only_startup_difference(tmp_path, valid):
    spec = importlib.util.spec_from_file_location(
        "metadata_verifier", ROOT / "proxmox/iso/scripts/verify_metadata.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "build/single-usb-production").mkdir(parents=True)
    (tmp_path / "evidence").mkdir()
    (tmp_path / "build/single-usb-production/pve-installer.squashfs").write_bytes(
        b"fixture filesystem"
    )
    common = b"# ignored comment\n\nregular R 1 600 0 0 4 10 0\n"
    (tmp_path / "build/vendor-files.pseudo").write_bytes(
        common
        + b"usr/sbin/unconfigured.sh R 1 755 0 0 5 10 0\n# START OF DATA - DO NOT MODIFY\n"
    )

    def execute(argv, **kwargs):
        output = Path(argv[argv.index("-pf") + 1])
        output.write_bytes(
            common
            + (
                b"usr/sbin/unconfigured.sh R 2 755 0 0 6 99 0\n"
                if valid
                else b"other F 1 755 0 0 cat other\n"
            )
            + b"# START OF DATA - DO NOT MODIFY\n"
        )

    with patch.object(module.subprocess, "run", side_effect=execute):
        if valid:
            module.verify(tmp_path)
        else:
            with pytest.raises(ValueError):
                module.verify(tmp_path)
    receipt = json.loads(
        (tmp_path / "evidence/final-metadata-verification.json").read_text()
    )
    assert receipt["all_other_vendor_metadata_preserved"] is valid


def test_metadata_parser_accepts_an_eof_terminated_metadata_listing(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "metadata_rows", ROOT / "proxmox/iso/scripts/verify_metadata.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "metadata"
    source.write_bytes(b"root D 1 755 0 0\n")
    assert module.records(source) == {b"root D 1 755 0 0"}
