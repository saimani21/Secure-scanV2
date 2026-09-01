import pickle


def deserialize(payload: bytes):
    return pickle.loads(payload)
