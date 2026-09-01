import lxml.etree


def parser() -> lxml.etree.XMLParser:
    return lxml.etree.XMLParser(no_network=True, resolve_entities=True)

