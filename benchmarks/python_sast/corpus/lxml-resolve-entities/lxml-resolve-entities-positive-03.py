import lxml.etree


def parse(document: bytes):
    parser = lxml.etree.XMLParser(resolve_entities=True, recover=False)
    return lxml.etree.fromstring(document, parser)

