import flask

app = flask.Flask(__name__)


def serve() -> None:
    app.run(debug=True)
