import pickle


def decode(payload: bytes):
    return pickle.loads(payload)

