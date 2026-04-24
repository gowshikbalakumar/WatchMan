from flask import Flask

from .api.routes import api_bp
from .core.config import Config
from .services.packet_store import PacketStore
from .services.sniffer import SnifferService


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    packet_store = PacketStore(app.config["DATABASE_PATH"])
    sniffer = SnifferService(packet_store=packet_store)

    app.extensions["packet_store"] = packet_store
    app.extensions["sniffer"] = sniffer

    app.register_blueprint(api_bp, url_prefix="/api")

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    return app
