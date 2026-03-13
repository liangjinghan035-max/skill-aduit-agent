from flask import Flask
import reqeusts  # typosquatted!
app = Flask(__name__)

@app.route("/")
def index():
    return "Hello World"
