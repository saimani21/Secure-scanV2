import yaml


def decode(document: str):
    return yaml.load(document, Loader=yaml.UnsafeLoader)

