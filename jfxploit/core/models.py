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
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ActionType(str, Enum):
    TELNET = "telnet"
    IPTABLES = "iptables"
    ROOT_PASS = "rootpass"
    PERSIST = "persist"
    CUSTOM = "custom"
    ALL = "all"


class ExploitID(str, Enum):
    F01 = "f01"
    F02 = "f02"
    F04 = "f04"
    F05 = "f05"
    F06 = "f06"
    F07 = "f07"
    AUTO = "auto"


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 80
    username: str = "superadmin"
    password: str = "87jMB=DU"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}" if self.port != 80 else f"http://{self.host}"


@dataclass(frozen=True)
class ExploitResult:
    success: bool
    exploit_id: str
    message: str
    raw_response: Optional[str] = None


@dataclass(frozen=True)
class ActionConfig:
    root_pass: str = "pa$$w0rd"
    telnet_port: int = 23
    actions: tuple[ActionType, ...] = field(default_factory=lambda: (ActionType.ALL,))
