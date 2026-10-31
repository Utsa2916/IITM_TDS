"""ASGI entry point for running the Flask app under Uvicorn."""
from asgiref.wsgi import WsgiToAsgi
from app import app

# Flask is a WSGI application. WsgiToAsgi adapts it for Uvicorn.
application = WsgiToAsgi(app)
