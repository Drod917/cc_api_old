from flask import Flask
from .models import db
from .routes import bp
from flasgger import Swagger 

def create_app(config=None):
    app = Flask(__name__)
    swagger = Swagger(app)

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            #print("\n\nUpdating app config")
            app.config.update(config)

    setup_app(app)
    return app

def setup_app(app):
    @app.before_first_request
    def create_tables():
        db.create_all()

    db.init_app(app)
    app.register_blueprint(bp, url_prefix='')