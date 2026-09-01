import yaml
from yaml import CSafeLoader, SafeLoader


def deserialize_safely(document: str) -> tuple[object, ...]:
    return (
        yaml.safe_load(document),
        yaml.load(document, Loader=yaml.SafeLoader),
        yaml.load(document, Loader=SafeLoader),
        yaml.load(document, Loader=yaml.CSafeLoader),
        yaml.load(document, Loader=CSafeLoader),
        yaml.load(document, yaml.SafeLoader),
        yaml.load(document, SafeLoader),
        yaml.load(document, yaml.CSafeLoader),
        yaml.load(document, CSafeLoader),
    )
