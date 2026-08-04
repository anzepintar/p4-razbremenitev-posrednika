import logging

logger = logging.getLogger(__name__)


class SniPassthrough:
    def server_connect(self, data) -> None:
        client_sni = getattr(data.client, "sni", None)
        if not client_sni:
            return
        data.server.sni = client_sni
        logger.debug("sni_passthrough: %s -> %s", data.server.address, client_sni)


addons = [SniPassthrough()]
