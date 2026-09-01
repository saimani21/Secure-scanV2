import pickle


def encode(value: object) -> bytes:
    return pickle.dumps(value)

