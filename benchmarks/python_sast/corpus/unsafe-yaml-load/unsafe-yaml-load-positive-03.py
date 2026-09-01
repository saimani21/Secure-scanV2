import yaml
from yaml import CLoader


def decode(document: str):
    return yaml.load(document, CLoader)

