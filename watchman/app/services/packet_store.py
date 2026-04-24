import sqlite3
from collections import deque
from pathlib import Path
from threading import Lock

from app.models.packet import PacketRecord


class PacketStore:
    """Stores packet history in memory (fast dashboard) + SQLite (persistence)."""

    def __init__(self, db_path: Path, cache_size: int = 5000) -> None:
        self.db_path = str(db_path)
        self.cache = deque(maxlen=cache_size)
        self.lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    length INTEGER NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    summary TEXT,
                    suspicious INTEGER NOT NULL DEFAULT 0,
                    reason TEXT
                )
                """
            )
            conn.commit()

    def add(self, packet: PacketRecord) -> None:
        packet_dict = packet.to_dict()
        with self.lock:
            self.cache.appendleft(packet_dict)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO packets (
                    timestamp, src_ip, dst_ip, protocol, length,
                    src_port, dst_port, summary, suspicious, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet.timestamp,
                    packet.src_ip,
                    packet.dst_ip,
                    packet.protocol,
                    packet.length,
                    packet.src_port,
                    packet.dst_port,
                    packet.summary,
                    int(packet.suspicious),
                    packet.reason,
                ),
            )
            conn.commit()

    def recent(self, limit: int = 50) -> list[dict]:
        with self.lock:
            return list(self.cache)[:limit]

    def search(self, protocol: str | None = None, suspicious_only: bool = False, limit: int = 100) -> list[dict]:
        query = """
            SELECT timestamp, src_ip, dst_ip, protocol, length,
                   src_port, dst_port, summary, suspicious, reason
            FROM packets WHERE 1=1
        """
        params: list = []
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol.upper())
        if suspicious_only:
            query += " AND suspicious = 1"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "timestamp": row[0],
                "src_ip": row[1],
                "dst_ip": row[2],
                "protocol": row[3],
                "length": row[4],
                "src_port": row[5],
                "dst_port": row[6],
                "summary": row[7],
                "suspicious": bool(row[8]),
                "reason": row[9] or "",
            }
            for row in rows
        ]
