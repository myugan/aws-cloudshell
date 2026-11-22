# aws-cloudshell

Access AWS CloudShell from your terminal: an interactive shell, one-shot
commands, and file transfer — without the AWS Console and without
`aws configure add-model`.

CloudShell has no public SDK. This script carries its own minimal botocore
service model (nine operations), writes it to the botocore data path at
runtime, and drives `session-manager-plugin` over the resulting SSM session.
Sessions use the `BASH` session type, so no tmux tab is created and there is
nothing to leak.

## Requirements

- Python 3.9+
- `pip install -r requirements.txt`
- [`session-manager-plugin`](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) in `PATH`
- AWS credentials (profile, environment, or instance role)

## Usage

```bash
python3 cloudshell.py shell                          # interactive shell
python3 cloudshell.py exec -- 'whoami; uname -a'     # run and print output
python3 cloudshell.py put ./dump.sql /home/cloudshell-user/dump.sql
python3 cloudshell.py get /home/cloudshell-user/report.json ./report.json
python3 cloudshell.py list
```

Global options: `--profile`, `--region`, `-e/--env-id`. `shell` and `exec`
create the environment if none exists.

| Command | What it does |
|---|---|
| `shell` | Interactive PTY shell; injects your credentials by default |
| `exec` | Runs a script, prints output, exits with the remote status |
| `put` / `get` | Chunked base64 transfer over the session |
| `list` / `create` / `status` / `start` / `stop` / `delete` | Environment lifecycle, including VPC environments |
| `creds` | Prints frozen credentials for manual injection |
| `model` | Shows the cached model; `--install-cli` installs it for `aws cloudshell` |

## Notes

- **Undocumented API.** AWS can change it without notice.
- **Credentials.** Programmatic sessions get none. `shell` and `exec` export
  your local frozen credentials into the session; use `--no-creds` to skip.
- **Not a tunnel.** The session is a PTY, so there is no local port
  forwarding — run `mysql`/`psql`/`curl` inside CloudShell.
- **Short-lived.** Each command opens a session, exits the shell, and deletes
  the SSM session. `shell` also sends `sendHeartBeat` every five minutes, so
  an idle environment is not suspended underneath you.
