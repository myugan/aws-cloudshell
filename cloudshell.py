#!/usr/bin/env python3
"""Use AWS CloudShell from your terminal, with no Console and no `aws configure add-model`.

CloudShell has no public SDK. This script carries its own minimal botocore
service model — the eight operations it uses — writes it to the botocore data
path, then drives `session-manager-plugin` to give you a real interactive shell
or one-shot command execution.

    ./cloudshell.py shell                     # interactive shell (creates env if needed)
    ./cloudshell.py exec -- 'whoami; uname -a'
    ./cloudshell.py put ./dump.sql /home/cloudshell-user/dump.sql
    ./cloudshell.py get /home/cloudshell-user/report.json ./report.json
    ./cloudshell.py list
    ./cloudshell.py create --name bastion --vpc-id vpc-123 \
        --subnet-id subnet-abc --security-group-id sg-xyz
    ./cloudshell.py delete

Requirements: Python 3.9+, boto3, session-manager-plugin in PATH, AWS credentials.

Caveats, all real:
  * Undocumented API: AWS can change or break it without notice.
  * programmatic sessions get NO console credentials, so `aws` inside the
    environment fails until this script injects yours (it does by default,
    with shell echo disabled so secrets are not printed).
  * the session is a PTY, not a TCP stream: no local port forwarding, so you
    run mysql/psql/curl *inside* CloudShell rather than through it.
  * environments suspend after ~20 min idle; an open session keeps it awake.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import pty
import re
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
import uuid
from pathlib import Path

SERVICE_MODEL = {
    "version": "2.0",
    "metadata": {
        "apiVersion": "2019-03-01",
        "auth": ["aws.auth#sigv4"],
        "endpointPrefix": "cloudshell",
        "protocol": "rest-json",
        "protocols": ["rest-json"],
        "serviceFullName": "AWS CloudShell",
        "serviceId": "CloudShell",
        "signatureVersion": "v4",
        "signingName": "cloudshell",
        "uid": "cloudshell-2019-03-01",
    },
    "operations": {
        "DescribeEnvironments": {
            "name": "DescribeEnvironments",
            "http": {"method": "POST", "requestUri": "/describeEnvironments"},
            "input": {"shape": "EmptyInput"},
            "output": {"shape": "DescribeEnvironmentsOutput"},
        },
        "CreateEnvironment": {
            "name": "CreateEnvironment",
            "http": {"method": "POST", "requestUri": "/createEnvironment"},
            "input": {"shape": "CreateEnvironmentInput"},
            "output": {"shape": "EnvironmentOutput"},
        },
        "GetEnvironmentStatus": {
            "name": "GetEnvironmentStatus",
            "http": {"method": "POST", "requestUri": "/getEnvironmentStatus"},
            "input": {"shape": "EnvironmentIdInput"},
            "output": {"shape": "GetEnvironmentStatusOutput"},
        },
        "StartEnvironment": {
            "name": "StartEnvironment",
            "http": {"method": "POST", "requestUri": "/startEnvironment"},
            "input": {"shape": "EnvironmentIdInput"},
        },
        "StopEnvironment": {
            "name": "StopEnvironment",
            "http": {"method": "POST", "requestUri": "/stopEnvironment"},
            "input": {"shape": "EnvironmentIdInput"},
            "output": {"shape": "EnvironmentIdOutput"},
        },
        "DeleteEnvironment": {
            "name": "DeleteEnvironment",
            "http": {"method": "POST", "requestUri": "/deleteEnvironment"},
            "input": {"shape": "EnvironmentIdInput"},
        },
        "CreateSession": {
            "name": "CreateSession",
            "http": {"method": "POST", "requestUri": "/createSession"},
            "input": {"shape": "CreateSessionInput"},
            "output": {"shape": "CreateSessionOutput"},
        },
        "DeleteSession": {
            "name": "DeleteSession",
            "http": {"method": "POST", "requestUri": "/deleteSession"},
            "input": {"shape": "DeleteSessionInput"},
        },
        "SendHeartBeat": {
            "name": "SendHeartBeat",
            "http": {"method": "POST", "requestUri": "/sendHeartBeat"},
            "input": {"shape": "EnvironmentIdInput"},
        },
    },
    "shapes": {
        "String": {"type": "string"},
        "Boolean": {"type": "boolean"},
        "StringList": {"type": "list", "member": {"shape": "String"}},
        "EmptyInput": {"type": "structure", "members": {}},
        "EnvironmentIdInput": {
            "type": "structure",
            "required": ["EnvironmentId"],
            "members": {"EnvironmentId": {"shape": "String"}},
        },
        "EnvironmentIdOutput": {"type": "structure", "members": {"EnvironmentId": {"shape": "String"}}},
        "EnvironmentOutput": {
            "type": "structure",
            "members": {"EnvironmentId": {"shape": "String"}, "Status": {"shape": "String"}},
        },
        "EnvironmentList": {"type": "list", "member": {"shape": "EnvironmentOutput"}},
        "DescribeEnvironmentsOutput": {
            "type": "structure",
            "members": {"Environments": {"shape": "EnvironmentList"}},
        },
        "GetEnvironmentStatusOutput": {
            "type": "structure",
            "members": {
                "Status": {"shape": "String"},
                "EnvironmentId": {"shape": "String"},
                "StatusReason": {"shape": "String"},
            },
        },
        "CreateEnvironmentInput": {
            "type": "structure",
            "members": {"EnvironmentName": {"shape": "String"}, "VpcConfig": {"shape": "VpcConfig"}},
        },
        "VpcConfig": {
            "type": "structure",
            "required": ["VpcId", "SubnetIds", "SecurityGroupIds"],
            "members": {
                "VpcId": {"shape": "String"},
                "SubnetIds": {"shape": "StringList"},
                "SecurityGroupIds": {"shape": "StringList"},
            },
        },
        "CreateSessionInput": {
            "type": "structure",
            "required": ["EnvironmentId", "SessionType"],
            "members": {
                "EnvironmentId": {"shape": "String"},
                "SessionType": {"shape": "String"},
                "TabId": {"shape": "String"},
                "QCliDisabled": {"shape": "Boolean"},
            },
        },
        "CreateSessionOutput": {
            "type": "structure",
            "members": {
                "SessionId": {"shape": "String"},
                "TokenValue": {"shape": "String"},
                "StreamUrl": {"shape": "String"},
            },
        },
        "DeleteSessionInput": {
            "type": "structure",
            "required": ["EnvironmentId", "SessionId"],
            "members": {"EnvironmentId": {"shape": "String"}, "SessionId": {"shape": "String"}},
        },
    },
}

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]")
CHUNK = 64 * 1024


def die(msg: str, code: int = 1) -> None:
    print(f"cloudshell: {msg}", file=sys.stderr)
    raise SystemExit(code)


def log(msg: str) -> None:
    print(f"cloudshell: {msg}", file=sys.stderr)


# ---------------------------------------------------------------- model cache


def model_file() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return root / "cloudshell" / "models" / "cloudshell" / "2019-03-01" / "service-2.json"


def ensure_model() -> Path:
    """Write the built-in service model where botocore looks; return its path."""
    dst = model_file()
    payload = json.dumps(SERVICE_MODEL).encode()
    try:
        if dst.read_bytes() == payload:
            return dst
    except OSError:
        pass
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(".tmp")
    tmp.write_bytes(payload)
    tmp.replace(dst)
    return dst


# -------------------------------------------------------------------- client


def make_client(args):
    try:
        import boto3
        import botocore.session
    except ImportError:
        die("boto3 is not installed: python3 -m pip install boto3")

    path = ensure_model()
    # botocore looks for <search_path>/cloudshell/2019-03-01/service-2.json
    model_root = str(path.parents[2])

    bc_session = botocore.session.get_session()
    loader = bc_session.get_component("data_loader")
    loader.search_paths.insert(0, model_root)

    session = boto3.Session(
        botocore_session=bc_session, profile_name=getattr(args, "profile", None)
    )
    region = getattr(args, "region", None) or session.region_name
    if not region:
        die("no region configured: pass --region or set AWS_REGION")
    try:
        client = session.client("cloudshell", region_name=region)
    except Exception as exc:  # UnknownServiceError if the model was not picked up
        die(f"cannot load the cloudshell model: {exc}")
    return client, session, region


def guard(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as exc:
        name = type(exc).__name__
        if name == "ClientError":
            err = exc.response.get("Error", {})
            die(f"{err.get('Code', '?')}: {err.get('Message', exc)}")
        die(f"{name}: {exc}")


def describe(client):
    return guard(client.describe_environments).get("Environments", [])


def resolve_env(client, env_id, create: bool) -> str:
    if env_id:
        return env_id
    envs = describe(client)
    if envs:
        return envs[0]["EnvironmentId"]
    if not create:
        die("no CloudShell environment in this account/region; run `create` first")
    env_id = guard(client.create_environment)["EnvironmentId"]
    log(f"created environment {env_id}")
    return env_id


def wait_running(client, env_id: str, timeout: int = 180) -> str:
    status = guard(client.get_environment_status, EnvironmentId=env_id).get("Status")
    if status == "SUSPENDED":
        guard(client.start_environment, EnvironmentId=env_id)
        status = "RESUMING"
    deadline = time.time() + timeout
    while status != "RUNNING":
        if status in {"DELETING", "DELETED", "ERROR", "FAILED"}:
            die(f"environment {env_id} is {status}")
        if time.time() > deadline:
            die(f"environment stuck in {status} after {timeout}s")
        time.sleep(3)
        status = guard(client.get_environment_status, EnvironmentId=env_id).get("Status")
    return status


def credentials_export(session, region: str | None = None) -> list[str]:
    creds = session.get_credentials()
    if creds is None:
        die("no AWS credentials available locally to inject into CloudShell")
    frozen = creds.get_frozen_credentials()
    lines = [f"export AWS_ACCESS_KEY_ID={shlex.quote(frozen.access_key)}"]
    lines.append(f"export AWS_SECRET_ACCESS_KEY={shlex.quote(frozen.secret_key)}")
    if frozen.token:
        lines.append(f"export AWS_SESSION_TOKEN={shlex.quote(frozen.token)}")
    region = region or session.region_name
    if region:
        lines.append(f"export AWS_DEFAULT_REGION={shlex.quote(region)}")
        lines.append(f"export AWS_REGION={shlex.quote(region)}")
    return lines


# ------------------------------------------------------------------- session


def write_all(fd: int, data: bytes) -> None:
    """Write every byte; a tty write can be short or interrupted by SIGWINCH."""
    view = memoryview(data)
    while view:
        try:
            view = view[os.write(fd, view) :]
        except InterruptedError:
            continue


def terminal_size() -> tuple[int, int]:
    try:
        rows, cols = struct.unpack(
            "HHHH",
            fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0)),
        )[:2]
        return (cols or 132, rows or 43)
    except OSError:
        return (132, 43)


def reset_terminal(fd: int) -> None:
    """Undo modes a crashed remote program can leave on the local terminal."""
    try:
        if os.isatty(fd):
            write_all(fd, b"\x1b[0m\x1b[?25h\x1b[?1l\x1b[?2004l")
    except OSError:
        pass


class Session:
    """One CloudShell SSM session, addressed through a local PTY."""

    def __init__(
        self,
        payload: dict,
        region: str,
        plugin: str,
        cols: int = 132,
        rows: int = 43,
    ) -> None:
        self.session_id = payload["SessionId"]
        self._cols, self._rows = cols, rows
        self._buf = b""
        self._eof = False
        self.master, slave = pty.openpty()
        self._slave_path = os.ttyname(slave)
        # The plugin never puts its own stdin in raw mode, so a canonical pty
        # turns ^C/^Z/^\ into signals to the plugin instead of bytes for the
        # remote shell. Raw mode is what makes Ctrl-C reach CloudShell.
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            tty.setraw(slave)
        except (OSError, termios.error):
            pass
        self.proc = subprocess.Popen(
            [plugin, json.dumps(payload), region, "StartSession"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
        )
        os.close(slave)

    def _set_size(self, cols: int, rows: int) -> None:
        # Only emit a real change; a no-op resize still raises SIGWINCH.
        if (cols, rows) == (self._cols, self._rows):
            return
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            self._cols, self._rows = cols, rows
        except OSError:
            pass

    def write(self, data: bytes | str) -> None:
        payload = data.encode() if isinstance(data, str) else data
        view = memoryview(payload)
        while view:
            view = view[os.write(self.master, view) :]

    def harden_tty(self) -> None:
        """Re-apply raw mode after the plugin starts.

        session-manager-plugin turns ISIG back on a few seconds in, which makes
        the local pty swallow ^C/^Z as signals instead of forwarding them.
        """
        try:
            fd = os.open(self._slave_path, os.O_RDWR | os.O_NOCTTY)
        except OSError:
            return
        try:
            tty.setraw(fd, termios.TCSANOW)
        except (OSError, termios.error):
            pass
        finally:
            os.close(fd)

    def _fill(self, timeout: float) -> None:
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return
        try:
            data = os.read(self.master, 65536)
        except OSError:
            data = b""
        if not data:
            self._eof = True
            return
        self._buf += data

    def wait_for(self, token: bytes, timeout: float) -> bytes:
        """Consume and return everything before `token`, then the token itself removed."""
        deadline = time.time() + timeout
        while True:
            idx = self._buf.find(token)
            if idx >= 0:
                before, self._buf = self._buf[:idx], self._buf[idx + len(token) :]
                return before
            if self._eof:
                tail = clean_output(self._buf.decode("utf-8", "replace"))[-300:].strip()
                raise RuntimeError(f"session closed before marker: {tail}" if tail else "session closed before marker")
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError(token.decode(errors="replace"))
            self._fill(min(0.2, left))

    def wait_line(self, timeout: float) -> bytes:
        deadline = time.time() + timeout
        while b"\n" not in self._buf:
            if self._eof:
                return b""
            left = deadline - time.time()
            if left <= 0:
                return b""
            self._fill(min(0.2, left))
        line, self._buf = self._buf.split(b"\n", 1)
        return line

    def wait_ready(self, timeout: float = 45) -> None:
        """Wait until the remote bash executes commands.

        The echo of our input contains the seed but not its base64 form, so a
        match proves the shell ran the command rather than the pty echoing it.
        Send exactly once: retries produce duplicate echoes that arrive after
        the token and would surface as visible junk at handoff.
        """
        seed = "csready" + uuid.uuid4().hex[:8]
        token = base64.b64encode((seed + "\n").encode())
        self.write(f"echo {seed} | base64\n")
        try:
            self.wait_for(token, timeout)
        except TimeoutError:
            die("CloudShell session did not become ready")
        except RuntimeError as exc:
            msg = str(exc)
            if "Concurrent command limit exceeded" in msg:
                msg += " (close stale CloudShell tabs, or stop/start the environment)"
            die(msg)
        self._buf = b""

    def _apply_stty(self, opts: str) -> None:
        seed = "csstty" + uuid.uuid4().hex[:8]
        token = base64.b64encode((seed + "\n").encode())
        self.write(f"stty {opts}; echo {seed} | base64\n")
        try:
            self.wait_for(token, 15)
        except TimeoutError:
            die(f"remote `stty {opts}` did not complete")

    def start_noninteractive(self) -> None:
        self.wait_ready()
        self.harden_tty()
        # -icanon lifts the 4096-byte canonical line limit; -echo keeps
        # injected secrets and long payloads out of the visible transcript.
        self._apply_stty("-icanon -echo min 1 time 0")

    def start_interactive(self, inject: list[str]) -> None:
        self.wait_ready()
        self.harden_tty()
        self._apply_stty("-icanon -echo min 1 time 0")
        if inject:
            # History off while the exports execute, and a leading space too:
            # credentials must never land in ~/.bash_history.
            payload = "set +o history\n" + "".join(f" {line}\n" for line in inject) + "set -o history\n"
            self.write(payload)
        # Last setup command doubles as the sentinel: it is sent with echo off,
        # so nothing is displayed, and everything the setup printed is provably
        # before this token. That makes the handoff deterministic instead of
        # racing a timer.
        self._apply_stty("sane")
        # The plugin re-enables ISIG a few seconds after connecting; do this
        # last so Ctrl-C is a byte for the remote shell, not a local signal.
        self.harden_tty()

    def run(self, script: str, timeout: float = 300) -> tuple[str, int]:
        nonce = uuid.uuid4().hex[:10]
        begin = f"__CS_BEGIN_{nonce}__".encode()
        end = f"__CS_END_{nonce}__".encode()
        remote = f"/tmp/.cloudshell-{nonce}.sh"
        b64 = base64.b64encode(script.encode()).decode()
        line = (
            f"printf %s '{b64}' | base64 -d > {remote}; echo {begin.decode()}; "
            f"bash {remote}; rc=$?; echo {end.decode()}:$rc; rm -f {remote}\n"
        )
        try:
            self.write(line)
            self.wait_for(begin, 20)
            body = self.wait_for(end, timeout)
            rc_line = self.wait_line(5)
        except TimeoutError as exc:
            die(f"command timed out waiting for {exc}")
        except RuntimeError as exc:
            die(str(exc))
        match = re.match(rb":\s*(\d+)", rc_line)
        rc = int(match.group(1)) if match else 1
        return body.decode("utf-8", "replace"), rc

    def interactive(self) -> int:
        stdin = sys.stdin.fileno()
        stdout = sys.stdout.fileno()
        attrs = None
        old_winch = None
        old_signals = {}

        def forward_size(*_):
            try:
                rows, cols = struct.unpack(
                    "HHHH", fcntl.ioctl(stdin, termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0))
                )[:2]
                self._set_size(cols or 132, rows or 43)
            except OSError:
                pass

        def bail(signum, frame):
            raise SystemExit(128 + signum)

        if sys.stdin.isatty():
            attrs = termios.tcgetattr(stdin)
            tty.setraw(stdin)
            old_winch = signal.signal(signal.SIGWINCH, forward_size)
            for sig in (signal.SIGHUP, signal.SIGTERM):
                old_signals[sig] = signal.signal(sig, bail)
            forward_size()
        # The pane was cleared during setup; ask for one fresh prompt and let
        # the relay print it, rather than replaying the setup transcript.
        self._buf = b""
        self.write("\r")
        stdin_open = True
        piped = not sys.stdin.isatty()
        deadline = None
        try:
            while self.proc.poll() is None:
                fds = [self.master] + ([stdin] if stdin_open else [])
                ready, _, _ = select.select(fds, [], [], 0.5 if deadline else None)
                if stdin in ready:
                    chunk = os.read(stdin, 65536)
                    if chunk:
                        self.write(chunk)
                    else:
                        stdin_open = False
                        if piped:
                            # Piped input finished: close the remote shell, then
                            # drain its remaining output before giving up.
                            deadline = time.time() + 15
                            try:
                                os.write(self.master, b"exit\n")
                            except OSError:
                                pass
                if self.master in ready:
                    try:
                        chunk = os.read(self.master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    write_all(stdout, chunk)
                if deadline is not None and time.time() > deadline:
                    break
        finally:
            if attrs is not None:
                termios.tcsetattr(stdin, termios.TCSAFLUSH, attrs)
                reset_terminal(stdout)
            if old_winch is not None:
                signal.signal(signal.SIGWINCH, old_winch)
            for sig, old in old_signals.items():
                signal.signal(sig, old)
        try:
            return self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return 0

    def quit_shell(self, timeout: float = 5) -> None:
        """Exit the remote shell so the container-side session ends with it."""
        if self.proc.poll() is not None:
            return
        try:
            self.write("exit\n")
        except OSError:
            return
        deadline = time.time() + timeout
        while time.time() < deadline and self.proc.poll() is None:
            self._fill(0.2)

    def close(self) -> None:
        try:
            os.close(self.master)
        except OSError:
            pass
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def find_plugin() -> str:
    plugin = os.environ.get("SESSION_MANAGER_PLUGIN") or shutil.which("session-manager-plugin")
    if not plugin:
        die(
            "session-manager-plugin not found in PATH; install it from "
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
        )
    return plugin


def open_session(client, region: str, env_id: str, cols: int = 132, rows: int = 43) -> Session:
    # BASH needs no TabId and creates no tmux session, so there is nothing to
    # clean up or repaint. (TMUX would need a TabId and leaks a tab per session.)
    payload = guard(
        client.create_session,
        EnvironmentId=env_id,
        SessionType="BASH",
        QCliDisabled=True,
    )
    slim = {k: payload[k] for k in ("SessionId", "TokenValue", "StreamUrl")}
    return Session(slim, region, find_plugin(), cols, rows)


def end_session(client, env_id: str, shell: Session) -> None:
    """Exit the remote shell, close the plugin, then free the SSM session."""
    shell.quit_shell()
    shell.close()
    try:
        client.delete_session(EnvironmentId=env_id, SessionId=shell.session_id)
    except Exception as exc:
        if os.environ.get("CLOUDSHELL_DEBUG"):
            log(f"delete_session failed: {exc}")


# ------------------------------------------------------------------ commands


def clean_output(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "")
    return ANSI_RE.sub("", text).replace("\x0f", "")


def cmd_list(args) -> int:
    client, _, _ = make_client(args)
    envs = describe(client)
    if not envs:
        print("no CloudShell environments in this account/region", file=sys.stderr)
        return 0
    width = max(len(e.get("EnvironmentId", "")) for e in envs)
    for env in envs:
        env_id = env.get("EnvironmentId", "")
        status = env.get("Status")
        if not status:
            try:
                status = client.get_environment_status(EnvironmentId=env_id).get("Status", "?")
            except Exception:
                status = "?"
        print(f"{env_id:<{width}}  {status}")
    return 0


def cmd_create(args) -> int:
    client, _, _ = make_client(args)
    kwargs = {}
    if args.vpc_id:
        if not args.subnet_id or not args.security_group_id:
            die("--vpc-id needs at least one --subnet-id and --security-group-id")
        kwargs["VpcConfig"] = {
            "VpcId": args.vpc_id,
            "SubnetIds": args.subnet_id,
            "SecurityGroupIds": args.security_group_id,
        }
        if not args.name:
            die("a VPC environment needs --name")
    if args.name:
        kwargs["EnvironmentName"] = args.name
    env = guard(client.create_environment, **kwargs)
    print(env["EnvironmentId"])
    return 0


def cmd_status(args) -> int:
    client, _, _ = make_client(args)
    env_id = resolve_env(client, args.env_id, create=False)
    print(json.dumps(guard(client.get_environment_status, EnvironmentId=env_id), indent=2, default=str))
    return 0


def _lifecycle(name: str):
    def run(args) -> int:
        client, _, _ = make_client(args)
        env_id = resolve_env(client, args.env_id, create=False)
        if name == "delete":
            guard(client.delete_environment, EnvironmentId=env_id)
        elif name == "stop":
            guard(client.stop_environment, EnvironmentId=env_id)
        elif name == "start":
            guard(client.start_environment, EnvironmentId=env_id)
        print(env_id)
        return 0

    return run


def keep_alive(client, env_id: str) -> threading.Event:
    """SendHeartBeat is what defers an idle suspend; an open session does not."""
    stop = threading.Event()

    def beat() -> None:
        while not stop.wait(300):
            try:
                client.send_heart_beat(EnvironmentId=env_id)
            except Exception:
                return

    threading.Thread(target=beat, daemon=True).start()
    return stop


def cmd_shell(args) -> int:
    client, session, region = make_client(args)
    env_id = resolve_env(client, args.env_id, create=not args.no_create)
    wait_running(client, env_id)
    shell = open_session(client, region, env_id, *terminal_size())
    stop = keep_alive(client, env_id)
    try:
        inject = [] if args.no_creds else credentials_export(session, region)
        shell.start_interactive(inject)
        log(f"connected to {env_id} ({region}); exit to disconnect")
        return shell.interactive()
    finally:
        stop.set()
        end_session(client, env_id, shell)


def cmd_exec(args) -> int:
    command = " ".join(args.command).strip()
    if not command:
        if sys.stdin.isatty():
            die("nothing to run: pass a command after `--` or pipe a script on stdin")
        command = sys.stdin.read()
    if not command.strip():
        die("empty command")

    client, session, region = make_client(args)
    env_id = resolve_env(client, args.env_id, create=not args.no_create)
    wait_running(client, env_id)
    shell = open_session(client, region, env_id)
    try:
        preamble = [] if args.no_creds else credentials_export(session, region)
        script = "\n".join([*preamble, command]) + "\n"
        shell.start_noninteractive()
        out, rc = shell.run(script, timeout=args.timeout)
        out = clean_output(out).lstrip("\n")
        sys.stdout.write(out if out.endswith("\n") or not out else out + "\n")
        return rc
    finally:
        end_session(client, env_id, shell)


def _remote_stat(shell: Session, path: str) -> int:
    out, rc = shell.run(f"stat -c %s -- {shlex.quote(path)}\n", timeout=30)
    if rc != 0:
        die(f"cannot stat remote file {path}: {out.strip()}")
    try:
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        die(f"unexpected stat output for {path}: {out!r}")


def cmd_put(args) -> int:
    local = Path(args.local).expanduser()
    if not local.is_file():
        die(f"no such local file: {local}")
    data = local.read_bytes()
    client, session, region = make_client(args)
    env_id = resolve_env(client, args.env_id, create=not args.no_create)
    wait_running(client, env_id)
    shell = open_session(client, region, env_id)
    remote = shlex.quote(args.remote)
    try:
        shell.start_noninteractive()
        total = max(1, (len(data) + CHUNK - 1) // CHUNK)
        for index in range(total):
            chunk = base64.b64encode(data[index * CHUNK : (index + 1) * CHUNK]).decode()
            op = ">" if index == 0 else ">>"
            out, rc = shell.run(f"printf %s '{chunk}' | base64 -d {op} {remote}\n", timeout=120)
            if rc != 0:
                die(f"upload failed at chunk {index + 1}/{total}: {out.strip()}")
            log(f"uploaded chunk {index + 1}/{total} ({(index + 1) * CHUNK if index + 1 < total else len(data)} bytes)")
        print(args.remote)
        return 0
    finally:
        end_session(client, env_id, shell)


def cmd_get(args) -> int:
    client, session, region = make_client(args)
    env_id = resolve_env(client, args.env_id, create=not args.no_create)
    wait_running(client, env_id)
    shell = open_session(client, region, env_id)
    remote = shlex.quote(args.remote)
    try:
        shell.start_noninteractive()
        size = _remote_stat(shell, args.remote)
        total = max(1, (size + CHUNK - 1) // CHUNK)
        blob = bytearray()
        for index in range(total):
            cmd = f"dd if={remote} bs={CHUNK} skip={index} count=1 2>/dev/null | base64\n"
            out, rc = shell.run(cmd, timeout=120)
            if rc != 0:
                die(f"download failed at chunk {index + 1}/{total}: {out.strip()}")
            try:
                blob += base64.b64decode(re.sub(r"\s+", "", clean_output(out)), validate=True)
            except ValueError as exc:
                die(f"bad base64 from chunk {index + 1}: {exc}")
            log(f"downloaded chunk {index + 1}/{total}")
        if len(blob) != size:
            die(f"size mismatch: got {len(blob)} bytes, remote file is {size}")
        Path(args.local).expanduser().write_bytes(bytes(blob))
        print(args.local)
        return 0
    finally:
        end_session(client, env_id, shell)


def cmd_creds(args) -> int:
    _, session, region = make_client(args)
    creds = session.get_credentials()
    if creds is None:
        die("no AWS credentials available")
    frozen = creds.get_frozen_credentials()
    if args.format == "json":
        print(
            json.dumps(
                {
                    "AccessKeyId": frozen.access_key,
                    "SecretAccessKey": frozen.secret_key,
                    "SessionToken": frozen.token,
                },
                indent=2,
            )
        )
    else:
        print("\n".join(credentials_export(session, region)))
    return 0


def cmd_model(args) -> int:
    path = ensure_model()
    print(path)
    if args.install_cli:
        dst = Path.home() / ".aws" / "models" / "cloudshell" / "2019-03-01" / "service-2.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dst)
        print(f"installed for the AWS CLI: {dst}")
        print("now try: aws cloudshell describe-environments --region us-east-1")
    return 0


# ---------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", default=argparse.SUPPRESS, help="AWS profile")
    common.add_argument("--region", default=argparse.SUPPRESS, help="AWS region")
    common.add_argument("-e", "--env-id", default=argparse.SUPPRESS, help="environment id")

    parser = argparse.ArgumentParser(
        description="AWS CloudShell from the terminal (undocumented API)",
        parents=[common],
        epilog="run `%(prog)s <command> --help` for command-specific options",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name, func, help_text, create_flags=False):
        p = sub.add_parser(name, parents=[common], help=help_text)
        p.set_defaults(func=func)
        if create_flags:
            p.add_argument("--no-create", action="store_true", help="fail instead of creating an environment")
        return p

    add("list", cmd_list, "list environments")
    p = add("create", cmd_create, "create an environment")
    p.add_argument("--name", help="environment name (required for VPC environments)")
    p.add_argument("--vpc-id")
    p.add_argument("--subnet-id", action="append", default=[])
    p.add_argument("--security-group-id", action="append", default=[])
    add("status", cmd_status, "environment status")
    for name, text in (("start", "start a suspended environment"), ("stop", "stop an environment"), ("delete", "delete an environment")):
        add(name, _lifecycle(name), text)
    add("shell", cmd_shell, "interactive shell", create_flags=True).add_argument(
        "--no-creds", action="store_true", help="do not inject local AWS credentials"
    )
    p = add("exec", cmd_exec, "run a command and print its output", create_flags=True)
    p.add_argument("--no-creds", action="store_true", help="do not inject local AWS credentials")
    p.add_argument("--timeout", type=int, default=300, help="seconds to wait for the command (default 300)")
    p.add_argument("command", nargs=argparse.REMAINDER, help="command to run (use -- before it)")
    p = add("put", cmd_put, "upload a file over the session", create_flags=True)
    p.add_argument("local")
    p.add_argument("remote")
    p = add("get", cmd_get, "download a file over the session", create_flags=True)
    p.add_argument("remote")
    p.add_argument("local")
    p = add("creds", cmd_creds, "print local credentials for manual injection")
    p.add_argument("--format", choices=("export", "json"), default="export")
    p = add("model", cmd_model, "show or install the service model")
    p.add_argument("--install-cli", action="store_true", help="also install into ~/.aws/models for `aws cloudshell`")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    # Global options use SUPPRESS so a subparser cannot overwrite a value given
    # before the subcommand; that also means the attribute is absent unless set.
    for name, default in (
        ("profile", None),
        ("region", None),
        ("env_id", None),
    ):
        if not hasattr(args, name):
            setattr(args, name, default)
    if getattr(args, "command", None):
        args.command = [c for c in args.command if c != "--"]
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
