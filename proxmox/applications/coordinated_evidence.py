"""Read the exact retained completed-group provenance; never execute or repair it."""

from pathlib import Path
from private_io import require, private_directory, digest, encoded
from coordinated_contract import selection, shape, fingerprint, ROLES
from custody_records import Snapshot, decode, recovery, no_markers
from coordinated_generation import initial_copy

ORIGINAL_FILES = {
    "site", "plan.json", "applied.json", "started.json", "rollout-complete.json",
    "guest.tfplan", "terraform.tfstate", "ssh-trust.json", "guest.tfplan.json",
    "foundation-complete.json", "tfvars",
}


def request_shape(value, group):
    shape(value, {"schema", "operation", "catalogue_sha256", "members"})
    require(value["schema"] == group["schema"] and value["operation"] == group["operation"]
            and value["catalogue_sha256"] == group["catalogue"]["sha256"],
            "Preserve the exact commissioned request")
    roles = ROLES[group["schema"]]
    shape(value["members"], roles)
    for role, row in value["members"].items():
        shape(row, {"vmid", "installer_revision", "adapter_revision", "plan_directory", "network_packet", "runtime_packet", "startup"})
        require(type(row["vmid"]) is int and row["vmid"] == group["members"][role]["vmid"],
                "Preserve the full commissioned member set")
        for name in ("installer_revision", "adapter_revision"):
            fingerprint(row[name], 40)
        import re
        require(isinstance(row["plan_directory"], str) and re.fullmatch(r"database-network-plan-[A-Za-z0-9-]{1,100}", row["plan_directory"]),
                "Preserve the original plan directory")
        packet = row["network_packet"]
        shape(packet, {"schema", "vmid", "request_sha256", "review_packet_sha256", "apply_helper_sha256", "allow_guest_restart"})
        require(packet["schema"] == "homelab-database-network-apply-v1" and packet["vmid"] == row["vmid"]
                and packet["allow_guest_restart"] is True and isinstance(row["runtime_packet"], dict),
                "Preserve the original member network/runtime packet")
        for name in ("request_sha256", "review_packet_sha256", "apply_helper_sha256"):
            fingerprint(packet[name])
        shape(row["startup"], {"gate_sha256", "dependency_sha256"})
        for value_hash in row["startup"].values():
            fingerprint(value_hash)
    return value


def source_proofs(snapshot, cfg, group, request):
    directory = Path(cfg["paths"]["coordinated_custody_inputs"])
    private_directory(directory)
    values = {}
    for key in ("catalogue", "acceptance"):
        row = group[key]
        raw = snapshot.read(directory / row["file"])
        require(digest(raw) == row["sha256"], "Preserve exact custody source evidence")
        values[key] = decode(raw)
    catalogue = values["catalogue"]
    require(isinstance(catalogue, dict) and catalogue.get("schema") == "homelab-database-networks-v1"
            and isinstance(catalogue.get("networks"), dict)
            and set(catalogue["networks"]) == {"postgresql", "mariadb", "influxdb"},
            "Preserve the accepted original network catalogue")
    acceptance = values["acceptance"]
    if group["schema"] == "homelab-postgresql-cutover-v1":
        shape(acceptance, {"observed_utc", "scope", "automatic_cd", "qualified_request_sha256", "qualified_completion_sha256",
                           "NAS_parity", "password_restore_receipt_sha256", "browser", "status", "remaining_scope"})
        require(acceptance["status"] == "network31_group_and_saved_credential_SQL_accepted"
                and acceptance["qualified_request_sha256"] == group["records"]["request.json"]
                and acceptance["qualified_completion_sha256"] == group["records"]["complete.json"],
                "Bind the exact retained PostgreSQL acceptance")
    else:
        shape(acceptance, {"schema", "mode", "helper_revision", "installer_revision", "catalogue_sha256", "packet"})
        member = request["members"]["mariadb"]
        require(acceptance["schema"] == "homelab-database-server-cutover-selection-v1"
                and acceptance["mode"] == "apply" and acceptance["packet"] == request
                and acceptance["catalogue_sha256"] == request["catalogue_sha256"]
                and acceptance["helper_revision"] == member["adapter_revision"]
                and acceptance["installer_revision"] == member["installer_revision"],
                "Bind the exact retained MariaDB selection")


def member_proof(snapshot, cfg, group, role, request):
    selected = group["members"][role]
    work = Path(cfg["paths"]["state_root"]) / str(selected["vmid"])
    private_directory(work)
    overlay_path = work / selected["overlay"]["directory"] / "overlay.json"
    private_directory(overlay_path.parent)
    no_markers(overlay_path.parent)
    raw = snapshot.read(overlay_path)
    require(digest(raw) == selected["overlay"]["sha256"], "Preserve the selected network overlay")
    remote = Path(group["recovery"]["directory"]) / str(selected["vmid"]) / selected["overlay"]["directory"] / "overlay.json"
    private_directory(remote.parent)
    no_markers(remote.parent)
    require(snapshot.read(remote) == raw, "Preserve local/NAS member overlay parity")
    overlay = decode(raw)
    member = request["members"][role]
    packet = member["network_packet"]
    require(isinstance(overlay, dict) and overlay.get("schema") == "homelab-database-network-overlay-v1"
            and overlay.get("status") == "network_overlay_verified"
            and overlay.get("packet_sha256") == digest(encoded(packet))
            and selected["overlay"]["directory"] == "database-network-apply-" + packet["review_packet_sha256"],
            "Preserve the exact completed member operation")
    plan = work / member["plan_directory"]
    private_directory(plan)
    no_markers(plan)
    request_raw = snapshot.read(plan / "request.json")
    review_raw = snapshot.read(plan / "review-packet.json")
    require(digest(request_raw) == packet["request_sha256"] == overlay.get("request_sha256")
            and digest(review_raw) == packet["review_packet_sha256"] == overlay.get("review_packet_sha256"),
            "Preserve accepted saved network plan inputs")
    network, review = decode(request_raw), decode(review_raw)
    original = overlay.get("original")
    require(isinstance(original, dict) and network.get("original") == original
            and overlay.get("candidate_guest_sha256") == review.get("candidate_guest_sha256"),
            "Preserve original and candidate plan bindings")
    shape(original, {"files", "source_sha256", "input_hashes", "state_lineage", "state_serial"})
    fingerprint(original["source_sha256"])
    files = original["files"]
    require(isinstance(files, dict) and {"site", "plan.json", "terraform.tfstate", "ssh-trust.json"} <= set(files)
            and set(files) <= ORIGINAL_FILES and isinstance(original["input_hashes"], dict),
            "Keep the complete original installation proof")
    loaded = {}
    for name, expected in files.items():
        fingerprint(expected)
        if name == "terraform.tfstate":
            continue
        path = Path(selected["installed_site"]) if name == "site" else (
            work / "tofu/site.auto.tfvars.json" if name == "tfvars" else work / name)
        loaded[name] = snapshot.read(path)
        require(digest(loaded[name]) == expected, "Preserve original installation record bytes")
    installed = decode(loaded["site"])
    previous = decode(loaded["plan.json"])
    require(installed["guest"]["vmid"] == selected["vmid"] and installed["app"]["kind"] == role
            and installed["site"]["node"] == selected["node"]
            and previous.get("source_sha256") == original["source_sha256"]
            and previous.get("input_hashes") == original["input_hashes"],
            "Preserve original source, input and installed profile identity")
    paths = installed["paths"]
    require(paths["state_root"] == cfg["paths"]["state_root"]
            and all(paths[key] == cfg["paths"][key] for key in ("backup_mount", "backup_directory", "backup_source")),
            "Preserve original local and recovery custody paths")
    ca_hash = original["input_hashes"].get(paths["ca_file"])
    require(ca_hash is not None and digest(snapshot.read(Path(cfg["paths"]["ca_file"]), private=False)) == ca_hash,
            "Preserve the commissioned public CA trust")
    trust = decode(loaded["ssh-trust.json"])
    shape(trust, {"address", "keys"})
    require(trust["address"] == installed["app"]["address"] and isinstance(trust["keys"], list) and trust["keys"],
            "Preserve the commissioned guest host trust")
    fingerprint(overlay.get("state_sha256"))
    require(isinstance(overlay.get("state_lineage"), str) and overlay["state_lineage"], "Keep the original state lineage")
    require(overlay["state_lineage"] == original["state_lineage"]
            and type(original["state_serial"]) is int and type(overlay.get("state_serial")) is int
            and overlay["state_serial"] > original["state_serial"] and overlay.get("vmid") == selected["vmid"],
            "Preserve the completed network generation identity")
    initial_record = selected["initial_ordinary"]
    initial_raw = None if initial_record is None else snapshot.read(work / initial_record["operation"] / "complete.json")
    initial = initial_copy(work, selected, raw=initial_raw)
    if initial is None:
        require(selected["initial_state_sha256"] == overlay["state_sha256"], "An unproved later backend is not an initial anchor")
    else:
        copy = work / selected["initial_ordinary"]["operation"] / "complete.json"
        require(snapshot.read(copy) == initial, "Preserve the initial ordinary immutable copy")
    return overlay["state_lineage"], initial


def inspect(cfg):
    """Validate complete immutable evidence; return only hashes and own anchors."""
    group = selection(cfg)
    if group is None:
        return {}, None, None
    state = Path(cfg["paths"]["state_root"])
    private_directory(state)
    recovery(cfg)
    directory = state / group["directory"]
    remote = Path(group["recovery"]["directory"]) / group["directory"]
    private_directory(directory)
    private_directory(remote)
    no_markers(directory)
    no_markers(remote)
    snapshot = Snapshot()
    records = {}
    for name, expected in group["records"].items():
        raw = snapshot.read(directory / name)
        require(digest(raw) == expected and snapshot.read(remote / name) == raw,
                "Preserve exact local/NAS completed group custody")
        records[name] = raw
    require(records["request.json"] == records["claim.json"], "Preserve matching request and claim custody")
    request = request_shape(decode(records["request.json"]), group)
    complete = decode(records["complete.json"])
    require(complete == {"status": "passed", "operation": group["operation"],
                         "packet_sha256": group["records"]["request.json"], "roles": list(ROLES[group["schema"]])},
            "Require the exact full successful group completion")
    source_proofs(snapshot, cfg, group, request)
    own = None
    for role in group["members"]:
        anchors = member_proof(snapshot, cfg, group, role, request)
        if role == cfg["app"]["kind"]:
            own = anchors
    return snapshot.finish(), *own
