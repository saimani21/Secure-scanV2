import pickle


def serialize(value: object) -> bytes:
    return pickle.dumps(value)
