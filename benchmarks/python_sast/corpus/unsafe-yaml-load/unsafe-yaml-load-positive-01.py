import yaml


def decode(document: str):
    return yaml.unsafe_load(document)

