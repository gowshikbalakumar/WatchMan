from pathlib import Path


class Config:
    BASE_DIR = Path(__file__).resolve().parents[2]
    DATA_DIR = BASE_DIR / "data"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DATABASE_PATH = DATA_DIR / "packets.db"
    MAX_CACHE_PACKETS = 5000
    DEFAULT_INTERFACE = None
