from flask import Flask

application = Flask(__name__)
application.run(host="127.0.0.1", debug=True)

