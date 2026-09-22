# Curated benchmark fixture: one intentional unsafe-yaml-load rule match.

import yaml


def parse_document(document: str) -> object:
    return yaml.load(document, Loader=yaml.Loader)
