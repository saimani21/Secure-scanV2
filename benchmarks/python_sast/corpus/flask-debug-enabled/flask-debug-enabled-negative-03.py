import flask


def serve(debug: bool) -> None:
    app = flask.Flask(__name__)
    app.run(debug=debug)

