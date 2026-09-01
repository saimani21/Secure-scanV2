import json


def deserialize(payload: str):
    return json.loads(payload)
