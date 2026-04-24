from flask import Blueprint, current_app, jsonify, request

from app.utils.filter_engine import PacketFilter

api_bp = Blueprint("api", __name__)
packet_filter = PacketFilter()


@api_bp.get("/health")
def health_check():
    return jsonify({"status": "ok"})


@api_bp.post("/sniffer/start")
def start_sniffer():
    interface = request.json.get("interface") if request.is_json else None
    sniffer = current_app.extensions["sniffer"]
    started = sniffer.start(interface=interface)
    return jsonify({"running": sniffer.running, "started": started})


@api_bp.post("/sniffer/stop")
def stop_sniffer():
    sniffer = current_app.extensions["sniffer"]
    sniffer.stop()
    return jsonify({"running": sniffer.running})


@api_bp.get("/packets")
def get_packets():
    store = current_app.extensions["packet_store"]
    expression = request.args.get("filter")
    protocol = request.args.get("protocol")
    suspicious_only = request.args.get("suspicious") == "1"

    packets = store.search(protocol=protocol, suspicious_only=suspicious_only)
    packets = [pkt for pkt in packets if packet_filter.matches(pkt, expression)]
    return jsonify({"count": len(packets), "packets": packets})


@api_bp.get("/stats")
def stats():
    store = current_app.extensions["packet_store"]
    recent = store.recent(limit=500)
    by_protocol: dict[str, int] = {}
    suspicious = 0

    for pkt in recent:
        by_protocol[pkt["protocol"]] = by_protocol.get(pkt["protocol"], 0) + 1
        if pkt.get("suspicious"):
            suspicious += 1

    return jsonify(
        {
            "captured_packets": len(recent),
            "protocol_counts": by_protocol,
            "suspicious_packets": suspicious,
        }
    )
