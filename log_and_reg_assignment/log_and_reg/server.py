from flask import Flask, render_template, request, redirect
from flask_app import app
from flask_app.controllers import logs


if __name__=="__main__":
    app.run(debug=True)