import lxml.etree


def parser() -> lxml.etree.XMLParser:
    return lxml.etree.XMLParser(resolve_entities=True)
