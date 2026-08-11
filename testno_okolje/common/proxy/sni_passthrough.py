class SniPassthrough:
    def server_connect(self, data) -> None:
        client_sni = getattr(data.client, "sni", None)
        if client_sni:
            data.server.sni = client_sni


addons = [SniPassthrough()]
