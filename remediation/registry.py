from remediation.handlers.as_b23 import ASB23JSONPRemediationHandler


class RemediationRegistry:
    def __init__(self, connection_registry):
        self.connection_registry = connection_registry
        self.handlers = {
            "AS-B23": ASB23JSONPRemediationHandler(
                connection_registry.client, self._token,
            )
        }

    def _token(self, target):
        record = self.connection_registry.tokens.server_tokens.get(target.service_url)
        if record and record.valid():
            return record.token
        raise RuntimeError("Server token tidak tersedia atau kedaluwarsa. Jalankan discovery kembali.")

    def get(self, control_id):
        return self.handlers.get(control_id)

    def server_targets(self):
        return [
            target for target in self.connection_registry.get_connected_targets()
            if target.component_type == "server"
        ]
