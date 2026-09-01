import yaml
from yaml import FullLoader


def deserialize_with_unclassified_loader(document: str) -> tuple[object, ...]:
    return (
        yaml.load(document, Loader=yaml.FullLoader),
        yaml.load(document, Loader=FullLoader),
        yaml.load(document, yaml.FullLoader),
        yaml.load(document, FullLoader),
    )
