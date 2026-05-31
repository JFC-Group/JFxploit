from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ActionType(str, Enum):
    TELNET = "telnet"
    IPTABLES = "iptables"
    ROOT_PASS = "rootpass"
    PERSIST = "persist"
    ALL = "all"


class ExploitID(str, Enum):
    F01 = "f01"
    F02 = "f02"
    F04 = "f04"
    F05 = "f05"
    F06 = "f06"
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
