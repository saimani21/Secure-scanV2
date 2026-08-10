# Curated clean fixture: safe_load avoids unsafe object construction.

import yaml


def parse_document(document: str) -> object:
    return yaml.safe_load(document)
