"""VM driver control paths run with a fake process and bounded temporary disk files."""

import importlib.util
import io
import json
from pathlib import Path
import sys
import subprocess
from unittest.mock import MagicMock, Mock, patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "proxmox/iso"


def load():
    spec = importlib.util.spec_from_file_location(
        "vm_boot_driver", ROOT / "scripts/boot_test.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "case",
    [
        "matching-check",
        "wrong-machine",
        "missing-member",
        "ambiguous-member",
        "cancel-install",
        "profile-wrong-machine",
        "timeout",
        "streaming",
        "natural-exit",
        "terminate",
    ],
)
def test_boot_driver_journals_native_verdict_without_starting_a_vm(tmp_path, case):
    module = load()
    selected = (
        "matching-check"
        if case in ("timeout", "streaming", "natural-exit", "terminate")
        else case
    )
    for name in ("fixture", "production"):
        folder = tmp_path / "build" / ("single-usb-" + name)
        folder.mkdir(parents=True)
        (folder / ("Proxmox-9.2-1-" + name + ".iso")).write_bytes(b"synthetic media")
    config = tmp_path / "build/single-usb-production/readback/homelab/config.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps({"machine_uuid": "11111111-1111-4111-8111-111111111111"})
    )
    reasons = {
        "wrong-machine": "wrong machine UUID",
        "missing-member": "missing, ambiguous or conflicting disk identity: LAB-NEW-B",
        "ambiguous-member": "missing, ambiguous or conflicting disk identity: LAB-NEW-A",
        "cancel-install": "installation was not explicitly confirmed",
        "profile-wrong-machine": "wrong machine UUID",
    }
    menu = b"Proxmox: CHECK ONLY - serial console\nProxmox: INSTALL - serial console; confirmation required\nThe highlighted entry will be executed automatically\n"
    menu += b"*Proxmox: CHECK ONLY - no installation\n"
    frames = [menu, b"*Proxmox: INSTALL - two NEW SSDs; confirmation required\n",
              b"*Proxmox: CHECK ONLY - serial console\n"]
    if case == "cancel-install":
        frames.append(b"*Proxmox: INSTALL - serial console; confirmation required\n")
    data = b"HOMELAB_CHECK_PASS:\n"
    if selected == "matching-check":
        data += b"CHECK ONLY selected; installation cannot continue\n"
    else:
        data += (
            (b"Type exactly:\n" if case == "cancel-install" else b"")
            + b"HOMELAB_REFUSED:"
            + reasons[case].encode()
            + b"\n"
        )
    proc = MagicMock(returncode=None)
    qmp_socket = MagicMock()
    qmp_socket.__enter__.return_value = qmp_socket
    qmp_socket.makefile.side_effect = lambda *args: io.BytesIO(b'{"QMP":{}}\n')
    proc.stdout.fileno.return_value = 99999

    def poll():
        if case == "natural-exit":
            proc.returncode = 0
        return proc.returncode

    proc.poll.side_effect = poll
    waits = [0]

    def wait(**kwargs):
        waits[0] += 1
        if case == "terminate" and waits[0] == 1:
            raise subprocess.TimeoutExpired("fixture qemu", 10)
        proc.returncode = 0
        return 0

    proc.wait.side_effect = wait
    original_copy = module.shutil.copyfile
    original_open = Path.open

    class SmallDisk:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def write(self, data):
            return self.stream.write(data)

        def truncate(self, size):
            assert size in (16 * 1024**3, 24 * 1024**3)
            return self.stream.truncate(65536)

    def bounded_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        return (
            SmallDisk(stream)
            if path.suffix == ".raw" and path.is_relative_to(tmp_path)
            else stream
        )

    def copy(source, target):
        if str(source).startswith("/usr/share/OVMF/"):
            Path(target).write_bytes(b"fixture firmware")
        else:
            original_copy(source, target)

    def path(value):
        return tmp_path if str(value) == "/work" else Path(value)

    def start(argv, **kwargs):
        assert not any("file=/dev/" in str(arg) for arg in argv)
        qmp = (
            next(arg for arg in argv if str(arg).startswith("unix:"))
            .split(",")[0]
            .removeprefix("unix:")
        )
        Path(qmp).touch()
        return proc

    size = 4 if case == "ambiguous-member" else 3

    def command(sock, name, arguments=None):
        if name == 'input-send-event':
            events = arguments['events']
            assert [event['data']['down'] for event in events] == [True, False]
            assert all(event['data']['key']['data'] in {'down','ret'} for event in events)
        return (
            [{"device": "disk" + str(i), "stats": {"wr_bytes": 0}} for i in range(size)]
            if name == "query-blockstats"
            else {}
        )

    ticks = iter(range(1000))
    with (
        patch.object(module, "Path", side_effect=path),
        patch.object(Path, "open", bounded_open),
        patch.object(module.shutil, "copyfile", side_effect=copy),
        patch.object(module.subprocess, "Popen", side_effect=start),
        patch.object(
            module.select,
            "select",
            side_effect=(
                [([], [], []), *[([proc.stdout], [], [])] * 10]
                if case == "streaming"
                else lambda *args: ([proc.stdout], [], [])
            ),
        ),
        patch.object(
            module.os,
            "read",
            side_effect=(
                [
                    b"booting\n",
                    *frames,
                    b"HOMELAB_CHECK_PASS:\n",
                    b"CHECK ONLY selected; installation cannot continue\n",
                ]
                if case == "streaming"
                else [b""] if case == "timeout" else [*frames, data]
            ),
        ),
        patch.object(module.time, "sleep"),
        patch.object(module.time, "monotonic", side_effect=lambda: next(ticks)),
        patch.object(module.socket, "socket", return_value=qmp_socket),
        patch.object(module, "command", side_effect=command),
        patch.object(sys, "argv", ["boot", selected, "--seconds", "10"]),
    ):
        if case in ("timeout", "natural-exit"):
            with pytest.raises(SystemExit):
                module.main()
        else:
            module.main()
    receipt = json.loads(
        next((tmp_path / "build/vm-tests").glob("*/receipt.json")).read_text()
    )
    assert (
        receipt["no_target_disk_writes"] == (case != "natural-exit")
        and receipt["production_host_accessed"] is False
    )
    assert receipt["result"] == (
        "checked-and-stopped"
        if selected == "matching-check" and case not in ("timeout", "natural-exit")
        else None if case in ("timeout", "natural-exit") else "refused"
    )
    if case == "cancel-install":
        assert any(
            call.args[0] == b"CANCEL\n" for call in proc.stdin.write.call_args_list
        )


def test_qmp_command_ignores_events_and_refuses_error_messages():
    module = load()
    sock = Mock()
    sock.makefile.return_value = io.BytesIO(
        b'{"event":"ready"}\n{"return":{"ok":true}}\n'
    )
    assert module.command(sock, "query-status") == {"ok": True}
    assert json.loads(sock.sendall.call_args.args[0]) == {"execute": "query-status"}
    sock.makefile.return_value = io.BytesIO(b'{"error":"fixture failure"}\n')
    with pytest.raises(RuntimeError):
        module.command(sock, "query-status")


def test_menu_selection_waits_for_each_highlight_before_entering_serial_mode():
    module = load()
    ready = b'\n'.join(module.MenuSelection.entries) + b'\nThe highlighted entry will be executed automatically\n'
    for cancel in (False, True):
        selector = module.MenuSelection(cancel)
        send = Mock()
        assert not selector.choose(send, b'booting')
        assert not selector.choose(send, ready)
        send.assert_not_called()
        data = ready
        for index in range(selector.target + 1):
            data += b'*Proxmox: ' + selector.entries[index] + b'\n'
            done = selector.choose(send, data)
            assert done == (index == selector.target)
            if not done:
                count = send.call_count
                assert not selector.choose(send, data)  # stale echo cannot trigger another arrow or Enter
                assert send.call_count == count
                assert all(call.args[0] != 'ret' for call in send.call_args_list)
        assert [call.args[0] for call in send.call_args_list] == ['down'] * selector.target + ['ret']
        assert selector.choose(send, data)
        assert send.call_count == selector.target + 1
    selector = module.MenuSelection(False)
    send = Mock()
    assert not selector.choose(send, ready + b'*Proxmox: INSTALL - serial console; confirmation required')
    send.assert_not_called()


def test_shell_wrapper_forwards_all_arguments_to_the_case_validator(tmp_path):
    import os
    import shutil

    root = tmp_path / 'fixture'
    scripts = root / 'scripts'; scripts.mkdir(parents=True)
    for name in ('run.sh', 'workflow.py'):
        shutil.copyfile(ROOT / 'scripts' / name, scripts / name)
    commands = tmp_path / 'commands'; commands.mkdir()
    marker = tmp_path / 'vm-call.json'
    docker = commands / 'docker'
    docker.write_text(
        '#!' + sys.executable + '\n'
        'import importlib.util,json,os,pathlib,sys\n'
        'if sys.argv[1] == "info": raise SystemExit(0)\n'
        'args=sys.argv[sys.argv.index("python3")+1:]\n'
        'spec=importlib.util.spec_from_file_location("fixture_workflow",pathlib.Path(os.environ["FIXTURE_ROOT"])/args[0])\n'
        'module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n'
        'def run(*args): pathlib.Path(os.environ["FIXTURE_MARKER"]).write_text(json.dumps([str(v) for v in args]))\n'
        'module.run=run;sys.argv=args\n'
        'try: module.main()\n'
        'except ValueError: raise SystemExit(2)\n'
    )
    docker.chmod(0o700)
    env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
               FIXTURE_ROOT=str(root), FIXTURE_MARKER=str(marker))
    for arguments, accepted in [(['test-case','wrong-machine'],True),
                                (['test-case','wrong-machine','extra'],False),
                                (['test-case'],False),(['test-case','unknown'],False)]:
        marker.unlink(missing_ok=True)
        result = subprocess.run(['bash',str(scripts / 'run.sh'),*arguments],env=env,capture_output=True,timeout=10)
        assert (result.returncode == 0) == accepted, (arguments,result.stderr)
        assert marker.exists() == accepted
        if accepted:
            assert json.loads(marker.read_text()) == ['/work/scripts/boot_test.py','wrong-machine']


def test_menu_keys_use_bounded_local_qmp_events_without_terminal_escape_bytes():
    import socket
    import tempfile
    from concurrent.futures import ThreadPoolExecutor

    module = load()
    for key in ('down', 'ret'):
        with tempfile.TemporaryDirectory(prefix='menu-qmp-') as temp:
            path = str(Path(temp) / 'qmp.sock')
            received = []
            with socket.socket(socket.AF_UNIX) as server:
                server.settimeout(5)
                server.bind(path); server.listen(1)
                def respond():
                    peer, _ = server.accept()
                    with peer:
                        peer.settimeout(5)
                        peer.sendall(b'{"QMP":{}}\n')
                        stream = peer.makefile('rb')
                        for _ in range(2):
                            received.append(json.loads(stream.readline()))
                            peer.sendall(b'{"return":{}}\n')
                with ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(respond)
                    module.menu_key(path, key)
                    result.result(timeout=5)
            assert received == [{'execute':'qmp_capabilities'}, {'execute':'input-send-event','arguments':{'events':[
                {'type':'key','data':{'down':True,'key':{'type':'qcode','data':key}}},
                {'type':'key','data':{'down':False,'key':{'type':'qcode','data':key}}}
            ]}}]
    with patch.object(module.socket, 'socket') as connect, pytest.raises(ValueError):
        module.menu_key('/unused', 'unsupported')
    connect.assert_not_called()
    for greeting in (b'[]\n', b'{}\n'):
        sock = MagicMock(); sock.__enter__.return_value = sock
        sock.makefile.return_value = io.BytesIO(greeting)
        with patch.object(module.socket, 'socket', return_value=sock), patch.object(module, 'command') as command, pytest.raises(ValueError):
            module.menu_key('/synthetic', 'down')
        command.assert_not_called()
