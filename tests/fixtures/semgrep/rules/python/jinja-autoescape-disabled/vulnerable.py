import jinja2


def environment() -> jinja2.Environment:
    return jinja2.Environment(autoescape=False)
