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
import socket
import time


def check_telnet(host: str, port: int = 23, timeout: int = 5, retries: int = 3) -> bool:
    """Check if telnet port is open on host."""
    for attempt in range(retries):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            if attempt < retries - 1:
                time.sleep(2)
    return False
