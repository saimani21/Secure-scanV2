import yaml
from yaml import CLoader, Loader, UnsafeLoader


def deserialize_unsafe(document: str):
    return yaml.unsafe_load(document)


def deserialize_with_keyword_loaders(document: str) -> tuple[object, ...]:
    return (
        yaml.load(document, Loader=yaml.Loader),
        yaml.load(document, Loader=Loader),
        yaml.load(document, Loader=yaml.UnsafeLoader),
        yaml.load(document, Loader=UnsafeLoader),
        yaml.load(document, Loader=yaml.CLoader),
        yaml.load(document, Loader=CLoader),
    )


def deserialize_with_positional_loaders(document: str) -> tuple[object, ...]:
    return (
        yaml.load(document, yaml.Loader),
        yaml.load(document, Loader),
        yaml.load(document, yaml.UnsafeLoader),
        yaml.load(document, UnsafeLoader),
        yaml.load(document, yaml.CLoader),
        yaml.load(document, CLoader),
    )
