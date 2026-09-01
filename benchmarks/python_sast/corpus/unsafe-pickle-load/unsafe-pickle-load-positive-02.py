import pickle
from typing import BinaryIO


def read(stream: BinaryIO):
    return pickle.load(stream)

