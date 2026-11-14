"""Authoritative image selection policy for declared component software."""
from pathlib import Path
import re


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def image(value):
    _require(isinstance(value,dict),'Use a declared image policy record')
    if value in ({
        "repository": repository,
        "tag": "latest",
        "digest": None,
    } for repository in ("ghcr.io/bitwarden/lite", "ghcr.io/music-assistant/server", "ghcr.io/koush/scrypted")):
        return {"image": value["repository"] + ":latest"}
    # A local image ID is a retained private archive selection, never an update.
    if set(value) == {"local_id", "archive", "archive_sha256"}:
        _require(
            all(isinstance(value[key],str)for key in value)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value["local_id"])
            and Path(value["archive"]).is_absolute()
            and re.fullmatch("[0-9a-f]{64}", value["archive_sha256"]),
            "Supply the preserved custom image and archive identity",
        )
        return {
            "image": value["local_id"],
            "archive": value["archive"],
            "archive_sha256": value["archive_sha256"],
        }
    _require(
        set(value) == {"repository", "tag", "digest"}
        and isinstance(value['repository'],str)
        and re.fullmatch(r"[a-z0-9][a-z0-9./_-]*", value["repository"])
        and (value["tag"] is None or isinstance(value['tag'],str)and re.fullmatch(r"[A-Za-z0-9_.-]+", value["tag"]))
        and isinstance(value["digest"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]),
        "Keep a repository, optional recorded tag and immutable digest",
    )
    return {
        "image": value["repository"]
        + (":" + value["tag"] if value["tag"] else "")
        + "@"
        + value["digest"]
    }
