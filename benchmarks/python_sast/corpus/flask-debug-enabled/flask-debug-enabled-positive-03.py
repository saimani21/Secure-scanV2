import flask


def serve() -> None:
    service = flask.Flask("service")
    service.config["ENV"] = "development"
    service.run(port=5001, debug=True)

