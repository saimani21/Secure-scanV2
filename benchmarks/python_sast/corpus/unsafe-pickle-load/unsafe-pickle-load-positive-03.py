import pickle


def decode_argument(payload: bytes):
    serialized = payload
    return pickle.loads(serialized)

