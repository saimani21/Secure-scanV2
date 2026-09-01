class TextCodec:
    def loads(self, payload: str) -> str:
        return payload


def decode(codec: TextCodec, payload: str) -> str:
    return codec.loads(payload)

