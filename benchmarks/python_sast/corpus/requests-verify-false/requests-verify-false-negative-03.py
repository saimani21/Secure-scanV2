class HttpClient:
    def get(self, url: str, *, verify: bool):
        return url, verify


def fetch(client: HttpClient, url: str):
    return client.get(url, verify=False)

