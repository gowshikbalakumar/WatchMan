import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from utils.filter_engine import PacketFilter


def test_basic_filter_match():
    pkt = {"protocol": "TCP", "dst_port": 80, "length": 120}
    assert PacketFilter().matches(pkt, "protocol==TCP and dst_port==80")


def test_basic_filter_no_match():
    pkt = {"protocol": "UDP", "dst_port": 53, "length": 80}
    assert not PacketFilter().matches(pkt, "protocol==TCP")
