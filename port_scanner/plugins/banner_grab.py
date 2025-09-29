# port_scanner/plugins/banner_grab.py
import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def tcp_banner_grab(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """간단한 TCP connect + recv 방식의 banner grab (http이면 헤더를 받아오거나 tcp banner)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # HTTP은 간단한 GET으로 확인
            if port in (80, 8080, 8000, 443):
                try:
                    s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                except Exception:
                    pass
            else:
                # 비HTTP 서비스엔 빈 바이트 전송 없이 recv()만 시도
                pass
            try:
                data = s.recv(4096)
                return data.decode(errors="ignore").strip()
            except Exception:
                return None
    except Exception as e:
        logger.debug("banner grab failed %s:%d -> %s", ip, port, e)
        return None
