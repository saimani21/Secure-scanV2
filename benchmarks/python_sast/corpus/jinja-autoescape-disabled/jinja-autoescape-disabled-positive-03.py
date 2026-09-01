import jinja2


def templates(loader: jinja2.BaseLoader) -> jinja2.Environment:
    return jinja2.Environment(loader=loader, autoescape=False)

