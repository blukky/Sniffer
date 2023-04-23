"""
ASGI config for SnifferDjango project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os

from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from snf.routing import ws_urlpatterns


application = ProtocolTypeRouter({
    "websocket": AuthMiddlewareStack(URLRouter(ws_urlpatterns)),
    "http": get_asgi_application()
})

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SnifferDjango.settings")


