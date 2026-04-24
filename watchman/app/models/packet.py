from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any


@dataclass
class PacketRecord:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    summary: str = ""
    suspicious: bool = False
    reason: str = ""

    @classmethod
    def create(cls, **kwargs: Any) -> "PacketRecord":
        kwargs.setdefault("timestamp", datetime.utcnow().isoformat())
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
