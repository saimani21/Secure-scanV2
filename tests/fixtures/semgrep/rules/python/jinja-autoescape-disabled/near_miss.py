import jinja2


def html_environment() -> jinja2.Environment:
    return jinja2.Environment(autoescape=jinja2.select_autoescape())
