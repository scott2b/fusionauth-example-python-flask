from flask import Flask, session
from flask_session import Session
import os


app = Flask(__name__)
SESSION_TYPE = "filesystem"
app.config.from_object(__name__)
Session(app)
app.secret_key = os.urandom(24)
from app import views
