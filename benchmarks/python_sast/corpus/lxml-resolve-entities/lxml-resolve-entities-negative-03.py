import xml.etree.ElementTree


def parse(document: str):
    return xml.etree.ElementTree.fromstring(document)

