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
