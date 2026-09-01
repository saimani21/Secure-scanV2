import yaml


def decode(document: str):
    return yaml.safe_load(document)

