from threading import Event, Thread

from app.models.packet import PacketRecord
from app.services.detection import SuspiciousDetector

try:
    from scapy.all import sniff  # type: ignore
    from scapy.layers.dns import DNS  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
except Exception:  # pragma: no cover
    sniff = None
    IP = TCP = UDP = DNS = object


class SnifferService:
    def __init__(self, packet_store):
        self.packet_store = packet_store
        self.detector = SuspiciousDetector()
        self.stop_event = Event()
        self.worker: Thread | None = None
        self.running = False

    def start(self, interface: str | None = None) -> bool:
        if self.running or sniff is None:
            return False
        self.stop_event.clear()
        self.worker = Thread(target=self._sniff_loop, args=(interface,), daemon=True)
        self.worker.start()
        self.running = True
        return True

    def stop(self) -> None:
        self.stop_event.set()
        self.running = False

    def _sniff_loop(self, interface: str | None) -> None:
        def process(pkt):
            record = self.decode_packet(pkt)
            suspicious, reason = self.detector.evaluate(record.to_dict())
            record.suspicious = suspicious
            record.reason = reason
            self.packet_store.add(record)

        sniff(
            iface=interface,
            prn=process,
            store=False,
            stop_filter=lambda _: self.stop_event.is_set(),
        )

    @staticmethod
    def decode_packet(pkt) -> PacketRecord:
        src_ip = pkt[IP].src if IP in pkt else "unknown"
        dst_ip = pkt[IP].dst if IP in pkt else "unknown"
        protocol = "OTHER"
        src_port = None
        dst_port = None

        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            if DNS in pkt:
                protocol = "DNS"
            else:
                protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

        if protocol == "TCP" and (src_port == 80 or dst_port == 80):
            protocol = "HTTP"

        return PacketRecord.create(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            length=len(pkt),
            src_port=src_port,
            dst_port=dst_port,
            summary=pkt.summary(),
        )
