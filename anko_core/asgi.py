"""
ASGI config for anko_core project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os

from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

from api.middleware import TokenAuthMiddlewareStack
import api.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'anko_core.settings')

django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": TokenAuthMiddlewareStack(
            URLRouter(api.routing.websocket_urlpatterns)
        ),
    }
)
