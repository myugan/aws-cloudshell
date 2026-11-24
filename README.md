# aws-cloudshell

Access AWS CloudShell from your terminal: an interactive shell, one-shot
commands, and file transfer — without the AWS Console and without
`aws configure add-model`.

CloudShell has no public SDK. This script carries its own minimal botocore
service model (nine operations), writes it to the botocore data path at
runtime, and drives `session-manager-plugin` over the resulting SSM session.
Sessions use the `BASH` session type, so no tmux tab is created and there is
nothing to leak.

Reference: [Abusing AWS CloudShell for Data Exfiltration](https://myugan.com/posts/abusing-aws-cloudshell-for-data-exfiltration)

## Requirements

- Python 3.9+
- `pip install -r requirements.txt`
- [`session-manager-plugin`](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) in `PATH`
- AWS credentials (profile, environment, or instance role)

## Usage

```bash
python3 cloudshell.py                                # interactive prompt (one session)
python3 cloudshell.py shell                          # interactive shell
python3 cloudshell.py serve                          # hold one session; share it over a socket
python3 cloudshell.py exec -- 'whoami; uname -a'     # run and print output
python3 cloudshell.py put ./dump.sql /home/cloudshell-user/dump.sql
python3 cloudshell.py get /home/cloudshell-user/report.json ./report.json
python3 cloudshell.py list
```

Global options: `--profile`, `--region`, `-e/--env-id`. Commands that need a
session create the environment if none exists; `--no-create` fails instead.

| Command | What it does |
|---|---|
| `repl` (or no command) | Interactive prompt over one session; see below |
| `shell` | Interactive PTY shell; injects your credentials by default |
| `serve` | Holds one session and runs jobs for other invocations over a unix socket |
| `exec` | Runs a script, prints output, exits with the remote status |
| `put` / `get` | Chunked base64 transfer over the session |
| `setup` | Installs `cloudflared` into `~/.local/bin` (idempotent; `--force` reinstalls) |
| `list` / `create` / `status` / `start` / `stop` / `delete` | Environment lifecycle, including VPC environments |
| `creds` | Prints frozen credentials for manual injection |
| `model` | Shows the cached model; `--install-cli` installs it for `aws cloudshell` |

## Interactive prompt

No command (or `repl`) keeps one session open and runs commands from a prompt:

```bash
python3 cloudshell.py                     # prompt; injects credentials like `exec`
python3 cloudshell.py repl --no-creds     # prompt without exporting credentials
```

```text
cloudshell> exec uname -m
cloudshell> put ./dump.sql /home/cloudshell-user/dump.sql
cloudshell> get /home/cloudshell-user/report.json ./report.json
cloudshell> setup
```

`list`, `exec`, `put`, `get`, `setup`, `shell`, `help` and `exit` are
available. The session opens on the first command that needs it. `shell`
closes the prompt's session and hands over to an interactive one; the next
command opens a fresh session. A failed command prints its error and leaves
the prompt running.

Each `exec` runs in a fresh bash, so `cd` and exported variables do not carry
over between commands; use `shell` when you need shell state.

## cloudflared

`setup` downloads the latest static `cloudflared` binary for the environment's
architecture into `~/.local/bin`, which is already on `PATH` and inside the
1 GB persistent home directory. Re-running it is cheap; `--force` re-downloads.
The install needs no credentials, and `setup` never exports any.

```bash
python3 cloudshell.py setup
```

Run a token-based tunnel, with the token created in the Cloudflare dashboard:

```bash
cloudflared tunnel --no-autoupdate run --token "$TUNNEL_TOKEN"
```

`cloudflared tunnel login` cannot complete inside CloudShell: it waits for a
callback on the container's `localhost`, which the browser approving the
request cannot reach. `cloudflared service install` also fails, because there
is no systemd. A tunnel lives only as long as the shell session — CloudShell
suspends after 20–30 minutes of inactivity and ends sessions after 12 hours.

## Sharing one session

A session ticket is single-use: `SessionId`, `TokenValue` and `StreamUrl` come
back once from `CreateSession`, and a second websocket on the same token
displaces the first — the existing shell dies with
`Cannot perform start session: websocket: close sent`. There is no attach call
in the API, so the only way to reuse a session is to share the PTY that owns it.

`serve` does exactly that. It holds the session and listens on
`~/.aws-cloudshell/<env-id>.sock`:

```bash
python3 cloudshell.py serve                      # in one terminal (interactive, or headless)
python3 cloudshell.py exec --via ~/.aws-cloudshell/<env-id>.sock -- 'ls /tmp'
python3 cloudshell.py get --via ~/.aws-cloudshell/<env-id>.sock /home/cloudshell-user/x.json ./x.json
```

`--via` is optional: `exec`, `put` and `get` reuse any socket they find and
fall back to opening a session of their own. Jobs from concurrent clients share
one remote shell and are serialized; the remote status is preserved. Stop the
server with `^C` (interactive) or `SIGTERM`; the socket is removed either way.

## Notes

- **Undocumented API.** AWS can change it without notice.
- **Credentials.** Programmatic sessions get none. `shell`, `serve` and `exec`
  export your local frozen credentials into the session; use `--no-creds` to
  skip.
- **Not a tunnel.** The session is a PTY, so there is no local port
  forwarding — run `mysql`/`psql`/`curl` inside CloudShell.
- **Short-lived.** Each command opens a session, exits the shell, and deletes
  the SSM session. `shell` and `serve` also send `sendHeartBeat` every five
  minutes, so an idle environment is not suspended underneath you; a `serve`
  socket keeps working until you stop it.
